package main

import (
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func startTestDC(t *testing.T) *DataCentre {
	t.Helper()

	dc, err := StartSOCKS(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { dc.Close() }) //nolint: errcheck

	return dc
}

// dialAsProxy reaches the data centre through SOCKS5 exactly as the proxy
// does: CONNECT to a Telegram address, then the obfuscated2 handshake with no
// secret -- a direct data-centre connection is keyed on nothing.
func dialAsProxy(t *testing.T, dc *DataCentre, address string) (essentials.Conn, error) {
	t.Helper()

	dialer, err := proxy.SOCKS5("tcp", dc.Addr(), nil, &net.Dialer{Timeout: 5 * time.Second})
	require.NoError(t, err)

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	t.Cleanup(func() { conn.Close() }) //nolint: errcheck
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	return obfuscation.Obfuscator{}.SendHandshake(essentials.WrapNetConn(conn), 2, obfuscation.TagPaddedIntermediate) //nolint: wrapcheck
}

// A CONNECT to one of Telegram's data centres is answered, and the connection
// then is the data centre. Any other destination is refused, so nothing the
// binary dials through mtgbench can leave the machine.
func TestSOCKSServesOnlyTelegram(t *testing.T) {
	t.Parallel()

	dc := startTestDC(t)

	conn, err := dialAsProxy(t, dc, "149.154.167.51:443")
	require.NoError(t, err, "a Telegram data centre is served")
	require.NoError(t, Download(conn, 1<<20), "and answers a download command")

	_, err = dialAsProxy(t, dc, "8.8.8.8:53")
	require.Error(t, err, "anything else is refused")

	assert.Equal(t, int64(1), dc.Served())
}

// The command protocol moves exactly what was asked, both ways, and says so:
// an upload is acknowledged with the count the data centre received.
func TestDataCentreCommands(t *testing.T) {
	t.Parallel()

	dc := startTestDC(t)

	conn, err := dialAsProxy(t, dc, "149.154.175.50:443")
	require.NoError(t, err)

	require.NoError(t, Download(conn, 3<<20))
	require.NoError(t, Upload(conn, 5<<20))
	require.NoError(t, Echo(conn, make([]byte, 100)))

	// The client has its echo the moment the data centre's write returns, a
	// moment before the data centre counts it.
	assert.Eventually(t, func() bool { return dc.BytesSent() == 3<<20+100 }, 5*time.Second, time.Millisecond,
		"payload sent, commands and acks aside: %d", dc.BytesSent())
	assert.Equal(t, int64(5<<20+100), dc.BytesReceived())
}

// The direct data centre is the same, with no SOCKS in front: the baseline the
// latency figures are taken against.
func TestDirectDataCentre(t *testing.T) {
	t.Parallel()

	dc, err := StartDirectDC(t.Context(), "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { dc.Close() }) //nolint: errcheck

	raw, err := net.Dial("tcp", dc.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint: errcheck

	conn, err := obfuscation.Obfuscator{}.SendHandshake(essentials.WrapNetConn(raw), 2, obfuscation.TagPaddedIntermediate)
	require.NoError(t, err)
	require.NoError(t, Echo(conn, []byte("ping")))
}
