package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// The run loop is the binary. Everything under it has its own tests; what only
// these can prove is that the wiring holds: the sockets a config names are the
// sockets served, the process stops when told and gives its ports back, and a
// public socket that dies takes the process down with it rather than leaving
// it running and looking healthy.

// runLoopConfig writes a config that binds two sockets the test already holds
// and reaches nothing else. The secret is a hostless dd one on purpose: the
// startup SNI check runs only for a fronting hostname, and with none there is
// no DNS lookup and no public-IP probe to reach the internet from a test.
func runLoopConfig(t *testing.T, public, extra uint) (*config.Config, string) {
	t.Helper()

	secret, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	raw := fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"

# Port 1 is never listening: a FakeTLS connection that fails its handshake is
# fronted here, refused at once, and closed -- which is how a test tells a
# served socket from one merely bound.
[domain-fronting]
host = "127.0.0.1"
port = 1

# What ends a connection that sends garbage is this timeout: the proxy waits
# for the rest of a handshake -- 64 bytes on the dd door, a whole TLS record
# on the FakeTLS one -- and only then gives up and closes. Short, so the
# served-or-not check is quick whichever door it knocks on.
[network.timeout]
handshake = "300ms"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]
`, secret.Hex(), public, extra)

	conf, err := utils.ParseConfig([]byte(raw))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	return conf, path
}

// brokenListener is a socket whose accept fails for good, the way a descriptor
// closed underneath the process would.
type brokenListener struct{ net.Listener }

var errAcceptBroken = errors.New("accept: bad file descriptor")

func (brokenListener) Accept() (net.Conn, error) { return nil, errAcceptBroken }

// runInBackground starts the run loop and hands back the channel its return
// value arrives on. Closing stop is what production's SIGTERM does.
func runInBackground(
	stop <-chan struct{}, conf *config.Config, path string, listen listenFunc,
) <-chan error {
	done := make(chan error, 1)

	go func() { done <- runProxyWith(stop, conf, "test", path, listen) }()

	return done
}

// requireServed proves a socket is being accepted from, not merely bound. A
// bound socket accepts a TCP connection into its backlog whether or not anyone
// calls Accept, so a successful dial proves nothing; a connection the proxy
// takes, waits on and closes does. Garbage is never a whole handshake, so on
// either door the proxy waits its handshake timeout for the rest and then
// closes -- and only a connection that was handed to the proxy at all is ever
// closed by it.
func requireServed(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)

	defer conn.Close() //nolint: errcheck

	_, err = conn.Write([]byte("this is not a handshake of any kind"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	// The proxy ends the connection either way; what that looks like from
	// here is a clean EOF on one platform and a reset on another. The only
	// outcome that means nobody was accepting is the read outliving its
	// deadline.
	_, err = io.ReadAll(conn)
	require.False(t, errors.Is(err, os.ErrDeadlineExceeded),
		"the connection was never closed: the socket is bound but nothing is accepting from it")
}

func requireReturned(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("the run loop did not return")

		return nil
	}
}

func requireRebindable(t *testing.T, addr string) {
	t.Helper()

	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the socket was still held after the run loop returned")

	require.NoError(t, l.Close())
}

// The sockets a config names are served, the loop returns cleanly when its
// context ends, and both ports are free again when it does.
func TestRunLoopServesUntilItsContextEnds(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf, path := runLoopConfig(t, held[0], held[1])

	public := fmt.Sprintf("127.0.0.1:%d", held[0])
	extra := fmt.Sprintf("127.0.0.1:%d", held[1])

	stop := make(chan struct{})
	done := runInBackground(stop, conf, path, ports.listen)

	requireServed(t, public)
	requireServed(t, extra)

	close(stop)

	require.NoError(t, requireReturned(t, done), "a run ended by its stop signal is not a failure")
	requireRebindable(t, public)
	requireRebindable(t, extra)
}

// A public socket that dies ends the run with an error naming it. Nothing
// cancels the context here: the process has to notice by itself, because a
// proxy that kept running without its public port would look healthy to its
// supervisor while every client got a refused connection.
func TestRunLoopExitsWhenThePublicSocketDies(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf, path := runLoopConfig(t, held[0], held[1])

	public := fmt.Sprintf("127.0.0.1:%d", held[0])
	extra := fmt.Sprintf("127.0.0.1:%d", held[1])

	breakPublic := func(addr string) (net.Listener, error) {
		l, err := ports.listen(addr)
		if err == nil && addr == public {
			return brokenListener{l}, nil
		}

		return l, err
	}

	// Never closed: the run has to end on its own.
	neverStop := make(chan struct{})

	err := requireReturned(t, runInBackground(neverStop, conf, path, breakPublic))

	require.ErrorIs(t, err, errAcceptBroken)
	require.Contains(t, err.Error(), public, "the error must name the socket that died")

	// The run cleaned up on the way out: the extra socket is closed too.
	requireRebindable(t, extra)
}

// A [[listener]] that dies is logged and the public port carries on. Losing
// the WEB backend must never take the public port down, which is the same
// rule that makes its bind failure non-fatal.
func TestRunLoopKeepsServingWhenAnExtraSocketDies(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf, path := runLoopConfig(t, held[0], held[1])

	public := fmt.Sprintf("127.0.0.1:%d", held[0])
	extra := fmt.Sprintf("127.0.0.1:%d", held[1])

	breakExtra := func(addr string) (net.Listener, error) {
		l, err := ports.listen(addr)
		if err == nil && addr == extra {
			return brokenListener{l}, nil
		}

		return l, err
	}

	stop := make(chan struct{})
	done := runInBackground(stop, conf, path, breakExtra)

	// The extra loop has died by now; the public one is still there.
	requireServed(t, public)

	select {
	case err := <-done:
		t.Fatalf("the run ended over an extra listener: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(stop)

	require.NoError(t, requireReturned(t, done))
	requireRebindable(t, public)
}
