package testclient

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// Copied from mtglib/internal/tls (conn.go), which this package cannot import.
const (
	RecordHeaderSize     = 5
	TypeChangeCipherSpec = 0x14
	TypeHandshake        = 0x16
	TypeApplicationData  = 0x17

	// MaxRecordPayload is the most the proxy writes into one record
	// (tls.MaxRecordPayloadSize): 16384 less the header.
	MaxRecordPayload = 16384 - RecordHeaderSize
)

var errNotTLS = errors.New("not a TLS record layer")

// Record is one TLS record as it arrived. Raw is the whole record, header
// included, because the ServerHello digest is computed over the records' bytes.
type Record struct {
	Type    byte
	Version [2]byte
	Payload []byte
	Raw     []byte
}

// ReadRecord reads exactly one TLS record. A header declaring more than a record
// may carry, or nothing at all, is refused by name: that is how raw obfuscated2
// or raw relayed bytes show up when a record layer was expected.
func ReadRecord(r io.Reader) (Record, error) {
	var header [RecordHeaderSize]byte

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Record{}, fmt.Errorf("a TLS record header must be readable: %w", err)
	}

	length := int(binary.BigEndian.Uint16(header[3:]))
	if length == 0 || length > MaxRecordPayload {
		return Record{}, fmt.Errorf("record of type %#x declares %d bytes: %w", header[0], length, errNotTLS)
	}

	raw := make([]byte, RecordHeaderSize+length)
	copy(raw, header[:])

	if _, err := io.ReadFull(r, raw[RecordHeaderSize:]); err != nil {
		return Record{}, fmt.Errorf("a record must carry the %d bytes it declares: %w", length, err)
	}

	return Record{
		Type:    header[0],
		Version: [2]byte{header[1], header[2]},
		Payload: raw[RecordHeaderSize:],
		Raw:     raw,
	}, nil
}

// ApplicationRecord frames payload as one TLS 1.2 application-data record, the
// way a client sends its obfuscated2 handshake after the ServerHello.
func ApplicationRecord(payload []byte) []byte {
	record := make([]byte, RecordHeaderSize, RecordHeaderSize+len(payload))
	putHeader(record, len(payload))

	return append(record, payload...)
}

func putHeader(dst []byte, length int) {
	dst[0] = TypeApplicationData
	dst[1], dst[2] = 3, 3
	binary.BigEndian.PutUint16(dst[3:], uint16(length)) //nolint: gosec // length <= MaxRecordPayload
}

// recordsPerWrite is how many full records one Write sends in a single call.
const recordsPerWrite = 4

// recordConn is the client side of the FakeTLS record layer after the
// handshake: writes go out as application-data records, reads return their
// payloads and skip any record that carries none.
type recordConn struct {
	essentials.Conn

	r       *bufio.Reader
	pending []byte
	inbuf   []byte
	outbuf  []byte
}

// NewRecordConn wraps c, whose ServerHello flight has been read, in the client
// side of the FakeTLS record layer.
func NewRecordConn(c essentials.Conn) essentials.Conn {
	return &recordConn{
		Conn:   c,
		r:      bufio.NewReaderSize(c, 64<<10),
		inbuf:  make([]byte, MaxRecordPayload),
		outbuf: make([]byte, 0, recordsPerWrite*(RecordHeaderSize+MaxRecordPayload)),
	}
}

func (c *recordConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		var header [RecordHeaderSize]byte

		if _, err := io.ReadFull(c.r, header[:]); err != nil {
			return 0, err //nolint: wrapcheck
		}

		length := int(binary.BigEndian.Uint16(header[3:]))
		if length > MaxRecordPayload {
			return 0, fmt.Errorf("record of type %#x declares %d bytes: %w", header[0], length, errNotTLS)
		}

		if header[0] != TypeApplicationData {
			if _, err := c.r.Discard(length); err != nil {
				return 0, err //nolint: wrapcheck
			}

			continue
		}

		if _, err := io.ReadFull(c.r, c.inbuf[:length]); err != nil {
			return 0, err //nolint: wrapcheck
		}

		c.pending = c.inbuf[:length]
	}

	n := copy(p, c.pending)
	c.pending = c.pending[n:]

	return n, nil
}

func (c *recordConn) Write(p []byte) (int, error) {
	written := 0

	for written < len(p) {
		batch := c.outbuf[:0]

		for len(batch)+RecordHeaderSize < cap(batch) && written < len(p) {
			n := min(len(p)-written, MaxRecordPayload, cap(batch)-len(batch)-RecordHeaderSize)
			start := len(batch)
			batch = batch[:start+RecordHeaderSize+n]
			putHeader(batch[start:], n)
			copy(batch[start+RecordHeaderSize:], p[written:written+n])
			written += n
		}

		if _, err := c.Conn.Write(batch); err != nil {
			return 0, err //nolint: wrapcheck
		}
	}

	return written, nil
}
