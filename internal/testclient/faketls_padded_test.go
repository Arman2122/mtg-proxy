package testclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenSessionID is the session ID the golden hello below was built with.
func goldenSessionID() []byte {
	sessionID := make([]byte, 32)

	for i := range sessionID {
		sessionID[i] = byte(0xA0 + i) //nolint: gosec // i < 32
	}

	return sessionID
}

var goldenKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// ClientHello is what tools/mtgbench sends, and its baselines are measured
// against exactly these bytes, so the builder that ClientHelloWith shares
// must never change them. Only the random (bytes 11..42) is masked: it is an
// HMAC XORed with the clock, and TestClientHelloCarriesTheDigest covers it.
//
// wantUnchanged was captured from ClientHello as it stood at a8811ef, BEFORE
// the builder was split in two, by hex-encoding the hello with its random
// zeroed. It is a recording of the old code, not a derivation: do not
// regenerate it to make this test pass.
func TestClientHelloIsUnchangedByTheBuilderSplit(t *testing.T) {
	t.Parallel()

	const wantUnchanged = "160301" + "0069" + // record: handshake, TLS 1.0, 105 bytes follow
		"01" + "000065" + // ClientHello, 101 body bytes
		"0303" + // client version: TLS 1.2
		"0000000000000000000000000000000000000000000000000000000000000000" + // the random, masked
		"20" + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // 32-byte session ID
		"0002" + "1301" + // one cipher suite
		"0100" + // one compression method: null
		"001a" + // 26 bytes of extensions
		"0000" + "0016" + "0014" + "00" + "0011" + // server_name: 22 bytes, 20-byte list, DNS, 17-byte name
		"636f7665722e6578616d706c652e636f6d" // cover.example.com

	masked := func(hello []byte) string {
		hello = append([]byte(nil), hello...)
		clear(hello[randomOffset : randomOffset+randomLen])

		return hex.EncodeToString(hello)
	}

	hello, err := ClientHello(goldenKey, "cover.example.com", goldenSessionID())
	require.NoError(t, err)

	assert.Equal(t, wantUnchanged, masked(hello))

	// No options is no change: the same hello, by whichever name it is asked for.
	hello, err = ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{})
	require.NoError(t, err)

	assert.Equal(t, wantUnchanged, masked(hello))
}

// The hello of the golden test is 110 bytes: 5 of record header, 4 of
// handshake header and a 101-byte body.
const unpaddedGoldenLen = 110

// What a TLS record and the proxy's reader allow, written out here and not
// borrowed from the builder, so a wrong constant in the builder is caught.
const (
	wantRecordPayloadMax = 16384
	wantSingleRecordMax  = 5 + wantRecordPayloadMax
	wantLargestHello     = 5 + 4 + 65531 // the reader refuses a handshake body above 65,531

	// A padding extension (RFC 7685) is a 4-byte header and then its zeros.
	wantPaddingType   = 0x0015
	wantPaddingHeader = 4

	// Where the extensions' own length sits in a hello with a 32-byte session
	// ID: record(5) + handshake header(4) + version(2) + random(32) + session
	// ID length(1) + session ID(32) + cipher suites(2+2) + compression(1+1).
	extensionsLengthAt = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1
)

type testExtension struct {
	typ  uint16
	data []byte
}

// wireHello is a hello taken off the wire the way the proxy's reader takes it:
// every record checked, the handshake message put back together, and the single
// record the digest is taken over rebuilt from it.
type wireHello struct {
	single []byte // 16 03 01 <len> 01 <len24> body
	chunks []int  // the payload length of each record on the wire
}

func reassemble(t *testing.T, wire []byte) wireHello {
	t.Helper()

	var (
		message []byte
		chunks  []int
	)

	for rest := wire; len(rest) > 0; {
		require.GreaterOrEqual(t, len(rest), 5, "a record header")
		require.Equal(t, []byte{0x16, 0x03, 0x01}, rest[:3], "every record is a TLS 1.0 handshake record")

		length := int(binary.BigEndian.Uint16(rest[3:5]))
		require.Positive(t, length, "no empty record")
		require.LessOrEqual(t, length, wantRecordPayloadMax, "a record carries at most 2^14")
		require.GreaterOrEqual(t, len(rest), 5+length, "a record's payload is all there")

		message = append(message, rest[5:5+length]...)
		chunks = append(chunks, length)
		rest = rest[5+length:]
	}

	require.GreaterOrEqual(t, len(message), 4)
	require.Equal(t, byte(0x01), message[0], "a ClientHello")
	require.Equal(t, len(message)-4, int(message[1])<<16|int(message[2])<<8|int(message[3]),
		"the handshake length covers exactly the rest of the message")
	require.LessOrEqual(t, len(message), 65535)

	single := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(single[3:], uint16(len(message))) //nolint: gosec // checked above
	single = append(single, message...)

	return wireHello{single: single, chunks: chunks}
}

// takeApart reads a single-record hello the way a TLS stack would and fails on
// any length field that disagrees with the bytes. A test that only compared
// len() would pass on a hello that carried junk after the record, or one that
// lied about its own length, and the proxy's reader stops at the length it is
// told.
//
// The hello must have been built with a 32-byte session ID.
func takeApart(t *testing.T, hello []byte) []testExtension {
	t.Helper()

	require.GreaterOrEqual(t, len(hello), unpaddedGoldenLen)

	assert.Equal(t, len(hello)-5, int(binary.BigEndian.Uint16(hello[3:5])),
		"the record length covers exactly the rest of the bytes")

	assert.Equal(t, len(hello)-9, int(hello[6])<<16|int(hello[7])<<8|int(hello[8]),
		"the handshake length covers exactly the rest of the record")

	assert.Equal(t, len(hello)-extensionsLengthAt-2,
		int(binary.BigEndian.Uint16(hello[extensionsLengthAt:])),
		"the extensions run to the very end of the record")

	var extensions []testExtension

	rest := hello[extensionsLengthAt+2:]

	for len(rest) > 0 {
		require.GreaterOrEqual(t, len(rest), 4, "an extension header")

		dataLen := int(binary.BigEndian.Uint16(rest[2:]))
		require.GreaterOrEqual(t, len(rest), 4+dataLen, "an extension body")

		extensions = append(extensions, testExtension{
			typ:  binary.BigEndian.Uint16(rest),
			data: rest[4 : 4+dataLen],
		})
		rest = rest[4+dataLen:]
	}

	return extensions
}

// stampOf recovers the timestamp from a hello's random the way the proxy's
// reader does -- digest over the single-record form with the random zeroed,
// XORed with the random -- and fails unless everything else in the random is
// exactly that digest.
func stampOf(t *testing.T, key [16]byte, single []byte) time.Time {
	t.Helper()

	random := append([]byte(nil), single[randomOffset:randomOffset+randomLen]...)

	zeroed := append([]byte(nil), single...)
	clear(zeroed[randomOffset : randomOffset+randomLen])

	mac := hmac.New(sha256.New, key[:])
	mac.Write(zeroed)
	digest := mac.Sum(nil)

	for i := range random {
		random[i] ^= digest[i]
	}

	require.Equal(t, make([]byte, randomLen-4), random[:randomLen-4], "the random must be the digest")

	return time.Unix(int64(binary.LittleEndian.Uint32(random[randomLen-4:])), 0)
}

func TestClientHelloPaddedHasTheRequestedSize(t *testing.T) {
	t.Parallel()

	for _, size := range []int{517, 600, 4096, 16000, wantSingleRecordMax} {
		hello, err := ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), size)
		require.NoError(t, err, "size %d", size)

		// Not require.Len: a failure there prints the whole hello.
		require.Equal(t, size, len(hello), "the whole record, header included")

		extensions := takeApart(t, hello)
		require.Len(t, extensions, 2, "size %d: the SNI, then the padding", size)

		assert.Equal(t, uint16(0), extensions[0].typ, "the SNI comes first")
		assert.Equal(t, uint16(wantPaddingType), extensions[1].typ, "the padding comes after it")
		assert.Len(t, extensions[1].data, size-unpaddedGoldenLen-wantPaddingHeader)
		assert.Equal(t, make([]byte, len(extensions[1].data)), extensions[1].data, "padding is zeros")
	}
}

// One record carries at most 2^14 bytes of payload. A hello that is longer than
// that is the same handshake message cut across records, and its digest is
// still the one over the single record the reader puts it back into.
func TestClientHelloWithSplitsWhatOneRecordCannotCarry(t *testing.T) {
	t.Parallel()

	for _, size := range []int{wantSingleRecordMax + 1, 40000, wantLargestHello} {
		hello, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{PadTo: size})
		require.NoError(t, err, "size %d", size)

		got := reassemble(t, hello)

		require.Equal(t, size, len(got.single), "size %d: the record the digest covers", size)

		message := size - 5
		records := (message + wantRecordPayloadMax - 1) / wantRecordPayloadMax

		require.Len(t, got.chunks, records, "size %d: as few records as it takes", size)
		require.Equal(t, message+5*records, len(hello), "size %d: every record has its own header", size)

		for _, length := range got.chunks[:records-1] {
			assert.Equal(t, wantRecordPayloadMax, length, "all but the last record are full")
		}

		extensions := takeApart(t, got.single)
		require.Len(t, extensions, 2, "size %d", size)
		assert.Equal(t, uint16(wantPaddingType), extensions[1].typ)
		assert.Len(t, extensions[1].data, size-unpaddedGoldenLen-wantPaddingHeader)
	}

	// A hello that fits one record stays one record, to the last byte.
	hello, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{PadTo: wantSingleRecordMax})
	require.NoError(t, err)
	assert.Len(t, reassemble(t, hello).chunks, 1)
}

// Padding is the only difference: the session ID, the ciphers, the compression
// and the SNI are the unpadded hello's, byte for byte.
func TestClientHelloPaddedKeepsEverythingBeforeThePadding(t *testing.T) {
	t.Parallel()

	plain, err := ClientHello(goldenKey, "cover.example.com", goldenSessionID())
	require.NoError(t, err)

	padded, err := ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), 517)
	require.NoError(t, err)

	assert.Equal(t, plain[:3], padded[:3], "record type and version")
	assert.Equal(t, plain[5], padded[5], "the handshake type")
	assert.Equal(t, plain[9:11], padded[9:11], "client version")
	assert.Equal(t, plain[randomOffset+randomLen:extensionsLengthAt], padded[randomOffset+randomLen:extensionsLengthAt],
		"session ID, ciphers and compression")
	assert.Equal(t, plain[extensionsLengthAt+2:], padded[extensionsLengthAt+2:unpaddedGoldenLen],
		"the SNI extension is where it was")
}

// The padding is part of what the random's HMAC covers, as it is in a real
// hello: the proxy HMACs the whole record, and a client whose digest was taken
// before the padding went in would be rejected. For a hello sent in several
// records the digest is over the one record they rebuild into.
func TestClientHelloWithCarriesTheDigestOverThePadding(t *testing.T) {
	t.Parallel()

	for _, size := range []int{517, wantSingleRecordMax + 1, 40000, wantLargestHello} {
		hello, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{PadTo: size})
		require.NoError(t, err, "size %d", size)

		stamp := stampOf(t, goldenKey, reassemble(t, hello).single)

		assert.WithinDuration(t, time.Now(), stamp, 5*time.Second, "size %d: its last four bytes carry the time", size)
	}
}

func TestClientHelloWithStampsTheTimeItIsGiven(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_700_000_000, 0)

	for _, size := range []int{0, 517, 40000} {
		hello, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{PadTo: size, At: at})
		require.NoError(t, err, "size %d", size)

		assert.Equal(t, at, stampOf(t, goldenKey, reassemble(t, hello).single), "size %d", size)
	}

	// A time in the past is as good as one in the future.
	hello, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(),
		HelloOptions{At: time.Now().Add(-10 * time.Second)})
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().Add(-10*time.Second), stampOf(t, goldenKey, hello), 2*time.Second)
}

func TestClientHelloPaddedAtTheUnpaddedSizeAddsNothing(t *testing.T) {
	t.Parallel()

	hello, err := ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), unpaddedGoldenLen)
	require.NoError(t, err)
	require.Equal(t, unpaddedGoldenLen, len(hello))

	extensions := takeApart(t, hello)
	require.Len(t, extensions, 1, "no padding extension when none is needed")
	assert.Equal(t, uint16(0), extensions[0].typ)

	// The smallest padded hello: a padding extension with no data at all.
	hello, err = ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), unpaddedGoldenLen+wantPaddingHeader)
	require.NoError(t, err)

	extensions = takeApart(t, hello)
	require.Len(t, extensions, 2)
	assert.Equal(t, uint16(wantPaddingType), extensions[1].typ)
	assert.Empty(t, extensions[1].data)
}

func TestClientHelloWithRefusesAnImpossibleSize(t *testing.T) {
	t.Parallel()

	for name, size := range map[string]int{
		"below any hello":               10,
		"negative":                      -517,
		"one under the unpadded length": unpaddedGoldenLen - 1,
		"one byte over: no room for an extension header": unpaddedGoldenLen + 1,
		"three bytes over: still no room":                unpaddedGoldenLen + wantPaddingHeader - 1,
		"a body one byte over what the reader takes":     wantLargestHello + 1,
		"far above": 200000,
	} {
		_, err := ClientHelloWith(goldenKey, "cover.example.com", goldenSessionID(), HelloOptions{PadTo: size})
		require.Error(t, err, name)

		_, err = ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), size)
		require.Error(t, err, "%s, by the other name", name)
	}

	// Padded is a request for padding: nothing, to it, is not "as short as it
	// comes". ClientHelloWith reads PadTo 0 that way, and the golden test pins it.
	_, err := ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), 0)
	require.Error(t, err)

	hello, err := ClientHelloPadded(goldenKey, "cover.example.com", goldenSessionID(), wantLargestHello)
	require.NoError(t, err, "the largest hello the reader takes")
	assert.Equal(t, wantLargestHello, len(reassemble(t, hello).single))
}

func TestClientHelloWithRefusesWhatTLSCannotCarry(t *testing.T) {
	t.Parallel()

	_, err := ClientHelloWith([16]byte{}, "", nil, HelloOptions{PadTo: 517})
	require.Error(t, err, "an empty SNI")

	_, err = ClientHelloWith([16]byte{}, "cover.example.com", make([]byte, 33), HelloOptions{PadTo: 517})
	require.Error(t, err, "a session ID longer than 32 bytes")

	_, err = ClientHelloPadded([16]byte{}, "", nil, 517)
	require.Error(t, err, "an empty SNI, by the other name")

	_, err = ClientHelloPadded([16]byte{}, "cover.example.com", make([]byte, 33), 517)
	require.Error(t, err, "a session ID longer than 32 bytes, by the other name")
}
