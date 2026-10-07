package testclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Copied from mtglib/internal/tls/fake (client_side.go).
const (
	randomLen    = 32
	randomOffset = 1 + 2 + 2 + 1 + 3 + 2
)

// ClientHello forges the exact bytes a Telegram client sends to an ee door: a
// TLS 1.0 record carrying a TLS 1.2 ClientHello naming sni, whose client random
// is the HMAC-SHA256 of the whole message under key (computed with the random
// zeroed) XORed with a little-endian timestamp. It is the inverse of the
// proxy's FakeTLS reader.
//
// It refuses an empty SNI or one over 255 bytes -- a guard: a host name that
// long is no cover anyone uses -- and a session ID over 32 bytes, which TLS
// cannot carry.
func ClientHello(key [16]byte, sni string, sessionID []byte) ([]byte, error) {
	return ClientHelloWith(key, sni, sessionID, HelloOptions{})
}

// HelloOptions shape a hello beyond what ClientHello sends. The zero value is
// ClientHello.
type HelloOptions struct {
	// PadTo is the length of the hello as ONE record, its 5-byte header
	// included: that is the form the proxy's reader rebuilds before it takes
	// the digest, and the length a real client's hello is quoted in (517). The
	// difference from the unpadded hello is made up by a TLS padding extension
	// (type 0x0015, zeros) after the SNI extension, inside the digest's input.
	// 0 means no padding.
	//
	// A hello that does not fit in one record -- PadTo above 16,389, the 5-byte
	// header and 2^14 bytes of payload -- is sent as the same handshake message
	// cut across as many records as it takes, none over 2^14, and the reader
	// puts it back together. The digest is still over the single record, so the
	// bytes on the wire are then PadTo plus 5 for each record after the first.
	//
	// A PadTo of the unpadded length adds no extension. Below it, or in the 1..3
	// bytes above it (an extension header alone is 4), or giving a handshake
	// body above 65,531 bytes (PadTo 65,540), which the reader refuses, is an
	// error.
	PadTo int

	// At is the time the random carries. The zero value is the present, which
	// is what a client sends; a test sets it to send a hello the reader's clock
	// check will refuse.
	At time.Time
}

const (
	// paddingExtensionType is the TLS padding extension (RFC 7685): a 4-byte
	// header, then as many zero bytes as the length field says.
	paddingExtensionType   = 0x0015
	paddingExtensionHeader = 4

	recordHeaderLen = 5

	// maxRecordPayload is what one TLS record may carry, and what the proxy's
	// reader takes from one.
	maxRecordPayload = 1 << 14

	// maxPaddedHello is the largest single-record hello: the reader refuses a
	// handshake body above 65,531 bytes, because the length of the record it
	// rebuilds -- body plus the 4-byte handshake header -- must fit 16 bits.
	maxPaddedHello = recordHeaderLen + 4 + 65531
)

// ClientHelloPadded is ClientHello for a hello of an exact size, see
// HelloOptions.PadTo. size is a request for padding, so 0 is an error here and
// not "none".
func ClientHelloPadded(key [16]byte, sni string, sessionID []byte, size int) ([]byte, error) {
	if size < 1 {
		return nil, fmt.Errorf("a hello of %d bytes cannot be sent", size)
	}

	return ClientHelloWith(key, sni, sessionID, HelloOptions{PadTo: size})
}

// ClientHelloWith is ClientHello shaped by opts.
func ClientHelloWith(key [16]byte, sni string, sessionID []byte, opts HelloOptions) ([]byte, error) {
	if sni == "" || len(sni) > 255 {
		return nil, fmt.Errorf("an SNI of %d bytes cannot be sent", len(sni))
	}

	if len(sessionID) > 32 {
		return nil, fmt.Errorf("a session ID of %d bytes cannot be sent", len(sessionID))
	}

	var extensions bytes.Buffer

	extensions.Write([]byte{0x00, 0x00})                                // extension type: server_name
	binary.Write(&extensions, binary.BigEndian, uint16(2+1+2+len(sni))) //nolint: errcheck,gosec
	binary.Write(&extensions, binary.BigEndian, uint16(1+2+len(sni)))   //nolint: errcheck,gosec
	extensions.WriteByte(0x00)                                          // name type: DNS hostname
	binary.Write(&extensions, binary.BigEndian, uint16(len(sni)))       //nolint: errcheck,gosec
	extensions.WriteString(sni)

	raw := helloRecord(sessionID, extensions.Bytes())

	if opts.PadTo != 0 {
		if opts.PadTo < 0 || opts.PadTo > maxPaddedHello {
			return nil, fmt.Errorf("a hello of %d bytes cannot be sent: at most %d", opts.PadTo, maxPaddedHello)
		}

		gap := opts.PadTo - len(raw)

		switch {
		case gap < 0:
			return nil, fmt.Errorf(
				"a hello of %d bytes cannot be padded to %d bytes: it is already longer", len(raw), opts.PadTo)
		case gap == 0:
			// Already exactly this long.
		case gap < paddingExtensionHeader:
			return nil, fmt.Errorf(
				"a hello of %d bytes cannot be padded to %d bytes: a padding extension is at least %d",
				len(raw), opts.PadTo, paddingExtensionHeader)
		default:
			// After the SNI, before the digest: the HMAC below covers the padding.
			dataLen := gap - paddingExtensionHeader

			binary.Write(&extensions, binary.BigEndian, uint16(paddingExtensionType)) //nolint: errcheck,gosec
			binary.Write(&extensions, binary.BigEndian, uint16(dataLen))              //nolint: errcheck,gosec // PadTo <= 65540
			extensions.Write(make([]byte, dataLen))

			raw = helloRecord(sessionID, extensions.Bytes())
		}
	}

	// The digest is over the hello as ONE record, however it is then sent.
	digest := hmac.New(sha256.New, key[:])
	digest.Write(raw)

	computed := digest.Sum(nil)

	at := opts.At
	if at.IsZero() {
		at = time.Now()
	}

	var timestamp [4]byte

	binary.LittleEndian.PutUint32(timestamp[:], uint32(at.Unix())) //nolint: gosec

	// random = digest XOR (28 zero bytes || timestamp), so the reader's
	// digest^random recovers exactly that.
	random := raw[randomOffset : randomOffset+randomLen]
	copy(random, computed)

	for i := range timestamp {
		random[randomLen-4+i] ^= timestamp[i]
	}

	if len(raw)-recordHeaderLen <= maxRecordPayload {
		return raw, nil
	}

	return fragment(raw), nil
}

// fragment sends a single-record hello as the same handshake message across
// several records, each as full as a record may be, which is what the reader's
// fragment reassembly is for. The message's own header (type and 24-bit length)
// is the first bytes of the first record and says how long the whole is; the
// record header of the single form, which the reader rebuilds, is not sent.
func fragment(single []byte) []byte {
	message := single[recordHeaderLen:]
	wire := make([]byte, 0, len(single)+recordHeaderLen*(len(message)/maxRecordPayload))

	for len(message) > 0 {
		n := min(len(message), maxRecordPayload)

		wire = append(wire, 0x16, 0x03, 0x01, byte(n>>8), byte(n)) //nolint: gosec // n <= 2^14
		wire = append(wire, message[:n]...)
		message = message[n:]
	}

	return wire
}

// helloRecord wraps already-encoded extensions into the whole TLS record, with
// the client random still zero. The caller has checked the session ID.
func helloRecord(sessionID, extensions []byte) []byte {
	var body bytes.Buffer

	body.Write([]byte{0x03, 0x03})       // client version: TLS 1.2
	body.Write(make([]byte, randomLen))  // random, filled in by the caller
	body.WriteByte(byte(len(sessionID))) //nolint: gosec // checked by the caller: at most 32
	body.Write(sessionID)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})                     // one cipher suite, not GREASE
	body.Write([]byte{0x01, 0x00})                                 // one compression method: null
	binary.Write(&body, binary.BigEndian, uint16(len(extensions))) //nolint: errcheck,gosec
	body.Write(extensions)

	var record bytes.Buffer

	// The record layer version has to be 3,1: that is what the reader demands
	// and what it reconstructs before HMACing, so the bytes on the wire and the
	// bytes under the HMAC are the same.
	record.Write([]byte{0x16, 0x03, 0x01})
	binary.Write(&record, binary.BigEndian, uint16(1+3+body.Len())) //nolint: errcheck,gosec
	record.WriteByte(0x01)                                          // handshake type: ClientHello
	// A 24-bit length: the body is a few hundred bytes at most (SNI <= 255), or
	// the padding that PadTo asked for, which the caller has held to 65,531.
	length := body.Len()
	record.Write([]byte{
		byte(length >> 16), byte(length >> 8), byte(length), //nolint: gosec // see above
	})
	record.Write(body.Bytes())

	return record.Bytes()
}

var errShortFlight = errors.New("the server flight is three records")

// ReadServerFlight reads the whole ServerHello flight: exactly three records --
// ServerHello, ChangeCipherSpec and one application-data record standing in for
// the certificate. The concatenated bytes are returned too, because that is
// what the client's digest check covers.
func ReadServerFlight(r io.Reader) ([]Record, []byte, error) {
	records := make([]Record, 0, 3)
	flight := make([]byte, 0, 8192)

	for i := range 3 {
		record, err := ReadRecord(r)
		if err != nil {
			return records, flight, fmt.Errorf("record %d of 3: %w: %w", i+1, errShortFlight, err)
		}

		records = append(records, record)
		flight = append(flight, record.Raw...)
	}

	return records, flight, nil
}
