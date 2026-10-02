package tls

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Arman2122/mtg-proxy/essentials"
)

const (
	SizeRecordType = 1
	SizeVersion    = 2
	SizeSize       = 2
	SizeHeader     = SizeRecordType + SizeVersion + SizeSize

	MaxRecordSize        = 16384
	MaxRecordPayloadSize = MaxRecordSize - SizeHeader
	DefaultBufferSize    = 4096

	// ReadBufferSize is how much of a client's record stream one read system
	// call may bring in. Every ee connection that reads records holds one.
	ReadBufferSize = 16 << 10

	TypeChangeCipherSpec = 0x14
	TypeHandshake        = 0x16
	TypeApplicationData  = 0x17
)

// TLS 1.2 is used for both TLS 1.2 and 1.3
var TLSVersion = [SizeVersion]byte{3, 3}

// Conn presents an established TLS 1.3 connection, after handshake
type Conn struct {
	essentials.Conn

	p *connPayload
}

type connPayload struct {
	conn         essentials.Conn
	connBuffered *bufio.Reader
	read         bool
	write        bool

	// remaining is how many payload bytes of the current application-data
	// record have not been read yet.
	remaining int
}

func (c Conn) Write(p []byte) (int, error) {
	if !c.p.write {
		return c.Conn.Write(p)
	}

	return len(p), WriteRecord(c.Conn, p)
}

// Read returns the payload of application-data records, copied straight from
// the buffered reader into p; other records are skipped. Records the reader
// already holds are taken together, so one Read can span several. Once Read
// has bytes for the caller it never waits for more: it stops at the first
// record that has not fully arrived, or not at all.
func (c Conn) Read(p []byte) (int, error) {
	if !c.p.read {
		return c.Conn.Read(p)
	}

	r := c.p.reader()
	n := 0

	for n < len(p) {
		if c.p.remaining == 0 {
			ok, err := c.p.openRecord(n > 0)
			if err != nil {
				return n, err
			}

			if !ok {
				break
			}

			continue
		}

		want := min(len(p)-n, c.p.remaining)
		if n > 0 {
			want = min(want, r.Buffered())
			if want == 0 {
				break
			}
		}

		m, err := r.Read(p[n : n+want])
		n += m
		c.p.remaining -= m

		if err != nil {
			return n, err //nolint: wrapcheck
		}
	}

	return n, nil
}

func (p *connPayload) reader() *bufio.Reader {
	if p.connBuffered == nil {
		p.connBuffered = bufio.NewReaderSize(p.conn, ReadBufferSize)
	}

	return p.connBuffered
}

// openRecord consumes the next record's header and sets remaining to its
// payload length if it carries application data; any other record is skipped
// whole. With nonBlocking it touches only what is already buffered and
// reports false, consuming nothing, when the next record cannot be opened
// without waiting -- or would fail: the caller returns what it has and meets
// the error on its next Read.
func (p *connPayload) openRecord(nonBlocking bool) (bool, error) {
	r := p.reader()

	if nonBlocking && r.Buffered() < SizeHeader {
		return false, nil
	}

	header, err := r.Peek(SizeHeader)
	if err != nil {
		if errors.Is(err, io.EOF) && r.Buffered() > 0 {
			return false, io.ErrUnexpectedEOF
		}

		return false, err //nolint: wrapcheck
	}

	if !bytes.Equal(TLSVersion[:], header[SizeRecordType:SizeRecordType+SizeVersion]) {
		if nonBlocking {
			return false, nil
		}

		return false, fmt.Errorf("incorrect tls version %v", header[SizeRecordType:SizeRecordType+SizeVersion])
	}

	recordType := header[0]
	length := int(binary.BigEndian.Uint16(header[SizeRecordType+SizeVersion:]))

	if recordType != TypeApplicationData {
		if nonBlocking && r.Buffered() < SizeHeader+length {
			return false, nil
		}

		if _, err := r.Discard(SizeHeader + length); err != nil {
			return false, err //nolint: wrapcheck
		}

		return true, nil
	}

	r.Discard(SizeHeader) //nolint: errcheck // peeked above
	p.remaining = length

	return true, nil
}

func New(conn essentials.Conn, read, write bool) Conn {
	return Conn{
		Conn: conn,
		p: &connPayload{
			conn:  conn,
			read:  read,
			write: write,
		},
	}
}
