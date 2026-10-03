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
func ClientHello(key [16]byte, sni string, sessionID []byte) ([]byte, error) {
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

	var body bytes.Buffer

	body.Write([]byte{0x03, 0x03})       // client version: TLS 1.2
	body.Write(make([]byte, randomLen))  // random, filled in below
	body.WriteByte(byte(len(sessionID))) //nolint: gosec // checked above: at most 32
	body.Write(sessionID)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})                      // one cipher suite, not GREASE
	body.Write([]byte{0x01, 0x00})                                  // one compression method: null
	binary.Write(&body, binary.BigEndian, uint16(extensions.Len())) //nolint: errcheck,gosec
	body.Write(extensions.Bytes())

	var record bytes.Buffer

	// The record layer version has to be 3,1: that is what the reader demands
	// and what it reconstructs before HMACing, so the bytes on the wire and the
	// bytes under the HMAC are the same.
	record.Write([]byte{0x16, 0x03, 0x01})
	binary.Write(&record, binary.BigEndian, uint16(1+3+body.Len())) //nolint: errcheck,gosec
	record.WriteByte(0x01)                                          // handshake type: ClientHello
	// A 24-bit length: the body is a few hundred bytes at most (SNI <= 255).
	length := body.Len()
	record.Write([]byte{
		byte(length >> 16), byte(length >> 8), byte(length), //nolint: gosec // see above
	})
	record.Write(body.Bytes())

	raw := record.Bytes()

	digest := hmac.New(sha256.New, key[:])
	digest.Write(raw)

	computed := digest.Sum(nil)

	var timestamp [4]byte

	binary.LittleEndian.PutUint32(timestamp[:], uint32(time.Now().Unix())) //nolint: gosec

	// random = digest XOR (28 zero bytes || timestamp), so the reader's
	// digest^random recovers exactly that.
	random := raw[randomOffset : randomOffset+randomLen]
	copy(random, computed)

	for i := range timestamp {
		random[randomLen-4+i] ^= timestamp[i]
	}

	return raw, nil
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
