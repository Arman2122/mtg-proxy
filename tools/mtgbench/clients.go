package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// telegramDC is the data centre every client asks for.
const telegramDC = 2

// errFronted is an ee hello the proxy did not take for its own: it handed the
// connection to the cover site, which hung up before a byte came back. In a
// run it is the anti-replay cache's false positive, and it is counted apart
// from failures.
var errFronted = errors.New("fronted to the cover site")

// Client is one connection through a door, handshake done: what is written is
// MTProto payload to the data centre, what is read is its answer.
type Client struct {
	essentials.Conn

	close func() error
}

// Close ends the connection the way its door's clients do: a reset for TCP, so
// a run of thousands leaves no TIME_WAIT behind, and a session DELETE for WEB.
func (c *Client) Close() error { return c.close() }

// Dial opens one connection through door as user u, up to the point where the
// proxy has dialled the data centre.
func Dial(ctx context.Context, s Setup, door Door, u User, clientIP string) (*Client, error) {
	switch door {
	case DoorEE:
		return dialEE(ctx, s, u)
	case DoorDD:
		return dialObfuscated(ctx, s, u, obfuscation.TagPaddedIntermediate)
	case DoorPlain:
		return dialObfuscated(ctx, s, u, obfuscation.TagIntermediate)
	case DoorWeb:
		return dialWeb(ctx, s, u, clientIP)
	}

	return nil, fmt.Errorf("no such door: %q", door)
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", addr, err)
	}

	if err := testclient.ResetOnClose(conn); err != nil {
		conn.Close() //nolint: errcheck

		return nil, err //nolint: wrapcheck
	}

	return conn, nil
}

func dialEE(ctx context.Context, s Setup, u User) (*Client, error) {
	conn, err := dialTCP(ctx, s.EEAddr())
	if err != nil {
		return nil, err
	}

	fail := func(err error) (*Client, error) {
		conn.Close() //nolint: errcheck

		return nil, err
	}

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return fail(fmt.Errorf("cannot make a session ID: %w", err))
	}

	hello, err := testclient.ClientHello(u.Key, coverHost, sessionID)
	if err != nil {
		return fail(err) //nolint: wrapcheck
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fail(fmt.Errorf("cannot set the handshake deadline: %w", err))
	}

	if _, err := conn.Write(hello); err != nil {
		return fail(fmt.Errorf("cannot send the ClientHello: %w", err))
	}

	if records, _, err := testclient.ReadServerFlight(conn); err != nil {
		// Not one byte before the hang-up is what fronting looks like from
		// here: mtgbench's cover listener answers nothing. A byte that is not
		// TLS, or a flight cut short, is a failure.
		if len(records) == 0 && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
			return fail(fmt.Errorf("%w: %w", errFronted, err))
		}

		return fail(fmt.Errorf("no ServerHello flight: %w", err))
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("cannot clear the handshake deadline: %w", err))
	}

	obfuscated, err := obfuscation.Obfuscator{Secret: u.Key[:]}.SendHandshake(
		testclient.NewRecordConn(essentials.WrapNetConn(conn)), telegramDC, obfuscation.TagPaddedIntermediate)
	if err != nil {
		return fail(fmt.Errorf("cannot send the obfuscated2 handshake: %w", err))
	}

	return &Client{Conn: obfuscated, close: conn.Close}, nil
}

func dialObfuscated(ctx context.Context, s Setup, u User, tag obfuscation.ConnectionTag) (*Client, error) {
	conn, err := dialTCP(ctx, s.ObfuscatedAddr())
	if err != nil {
		return nil, err
	}

	obfuscated, err := obfuscation.Obfuscator{Secret: u.Key[:]}.SendHandshake(essentials.WrapNetConn(conn), telegramDC, tag)
	if err != nil {
		conn.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot send the obfuscated2 handshake: %w", err)
	}

	return &Client{Conn: obfuscated, close: conn.Close}, nil
}

// DialDirect opens a connection to the direct data centre with no proxy and
// no SOCKS5, keyed on nothing exactly as the proxy keys its own: the latency
// baseline.
func DialDirect(ctx context.Context, s Setup) (*Client, error) {
	conn, err := dialTCP(ctx, s.DirectAddr())
	if err != nil {
		return nil, err
	}

	obfuscated, err := obfuscation.Obfuscator{}.SendHandshake(essentials.WrapNetConn(conn), telegramDC, obfuscation.TagPaddedIntermediate)
	if err != nil {
		conn.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot send the obfuscated2 handshake: %w", err)
	}

	return &Client{Conn: obfuscated, close: conn.Close}, nil
}

func dialWeb(ctx context.Context, s Setup, u User, clientIP string) (*Client, error) {
	capability, err := u.Capability()
	if err != nil {
		return nil, err
	}

	session, err := testclient.OpenWebSession(ctx, "http://"+s.RelayAddr(), capability,
		testclient.WebOptions{Origin: webHost, ForwardedFor: clientIP, ResetOnClose: true})
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	// A session given up on is deleted, not just dropped: a dropped one holds a
	// slot against the relay's session limit for its reconnect grace.
	giveUp := func(err error) (*Client, error) {
		deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		session.Delete(deleteCtx) //nolint: errcheck

		return nil, err
	}

	stream, err := session.OpenStream(1)
	if err != nil {
		return giveUp(err)
	}

	obfuscated, err := obfuscation.Obfuscator{Secret: u.Key[:]}.SendHandshake(stream, telegramDC, obfuscation.TagPaddedIntermediate)
	if err != nil {
		return giveUp(fmt.Errorf("cannot send the obfuscated2 handshake: %w", err))
	}

	return &Client{Conn: obfuscated, close: func() error {
		// Its own short context: the run's may be cancelled by teardown time,
		// and the session should still be deleted.
		deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		return session.Delete(deleteCtx) //nolint: wrapcheck
	}}, nil
}
