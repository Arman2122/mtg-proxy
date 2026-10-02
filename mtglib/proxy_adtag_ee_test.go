package mtglib

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/middleproxy"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An ee client on an ad-tagged secret, through the real FakeTLS door, all the
// way to a middle proxy that speaks the real RPC exchange: the nonce, the
// handshake, AES-CBC framing. Every request reaches the middle proxy carrying
// the ad tag -- which is what makes the sponsored channel appear -- and bytes
// cross exactly, both ways. The client is a real one too: it encrypts with its
// own obfuscated2 keys inside TLS records, because on this path the proxy
// parses the decrypted stream into packets.
func TestFakeTLSClientWithAdTagRoundTripsThroughTheMiddleProxy(t *testing.T) {
	t.Parallel()

	entry := govEntryCases()[0]
	require.Equal(t, SecretModeFakeTLS, entry.mode)

	secret := entry.secret(t)
	globalTag := [AdTagLength]byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	h, accepted := newAdTagHarness(t, map[string]Secret{"alice": secret}, nil, &globalTag)
	h.proxy.doppelGanger.Unpace()
	h.proxy.doppelGanger.Run()
	t.Cleanup(h.proxy.doppelGanger.Shutdown)
	h.proxy.idleTimeout = time.Minute

	client, done := h.dialProxy(t, entry.policy)

	t.Cleanup(func() {
		client.Close() //nolint: errcheck
		<-done
	})

	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	entry.openEntry(t, client, secret.Key)

	var first [1]byte

	_, err := io.ReadFull(client, first[:])
	require.NoError(t, err, "the ee entry must answer a valid ClientHello")
	require.EqualValues(t, tls.TypeHandshake, first[0])

	skipServerFlight(t, client)

	obf, err := obfuscation.Obfuscator{Secret: secret.Key[:]}.SendHandshake(
		tls.New(essentials.WrapNetConn(client), true, true), 2, obfuscation.TagPaddedIntermediate)
	require.NoError(t, err)

	middle := nextUpstream(t, accepted)

	peer, err := middleproxy.ServePeer(middle, []byte("0123456789abcdef"))
	require.NoError(t, err, "the proxy must complete the middle proxy's RPC exchange")

	var connID [8]byte

	for _, size := range []int{8, 1000, 16000} { // client -> Telegram
		payload := bytes.Repeat([]byte{0x42}, size)

		_, err := obf.Write(intermediatePacket(payload))
		require.NoError(t, err)

		req, err := peer.ReadRequest()
		require.NoError(t, err)
		assert.Equal(t, globalTag[:], req.AdTag, "every request must carry the ad tag")
		assert.Equal(t, payload, req.Payload, "the client's packet must arrive whole and unchanged")

		connID = req.ConnID
	}

	for _, size := range []int{16, 2000, 16384} { // Telegram -> client
		answer := bytes.Repeat([]byte{0x24}, size)

		require.NoError(t, peer.WriteAnswer(connID, answer))
		assert.Equal(t, answer, readIntermediate(t, obf), "the answer must reach the client whole and unchanged")
	}

	user := userStatsJSON(t, h.proxy.stats, "alice") // the ad-tag counters are omitted while zero
	assert.NotContains(t, user, "ad_tag_failed", "the middle proxy was reached; nothing failed")
	assert.NotContains(t, user, "ad_tag_skipped", "an intermediate client must not skip the middle proxy")
}

// intermediatePacket frames payload the way an intermediate client does: a
// 4-byte little-endian length, then the payload.
func intermediatePacket(payload []byte) []byte {
	length := uint32(len(payload)) //nolint: gosec // test payloads of a few KiB

	return append(binary.LittleEndian.AppendUint32(nil, length), payload...)
}

// readIntermediate reads one intermediate packet and returns its payload.
func readIntermediate(t *testing.T, r io.Reader) []byte {
	t.Helper()

	var length [4]byte

	_, err := io.ReadFull(r, length[:])
	require.NoError(t, err)

	payload := make([]byte, binary.LittleEndian.Uint32(length[:]))

	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)

	return payload
}
