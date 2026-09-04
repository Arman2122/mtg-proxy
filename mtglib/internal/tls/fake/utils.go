package fake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
)

const (
	maxFragmentsCount = 10

	// RFC 5246 6.2.1: a TLSPlaintext fragment MUST NOT exceed 2^14 bytes, and
	// the length field excludes the 5 byte header. Both bounds are checked
	// before the length they carry drives any buffering: this is a
	// pre-authentication path on the public listener.
	maxRecordPayload = tls.MaxRecordSize

	// A handshake message MAY span fragments, so the hello bound is not the
	// record bound. 65531 is where uint16(1+3+length) below would wrap.
	//
	// Not tightened to one record, even though a real hello is ~517 bytes: on
	// this path a failed handshake is relayed to the cover site, and
	// ReadClientHelloMulti still reports the matched SNI when only the digest
	// failed. Rejecting a 20 KiB hello earlier than a wrong secret would front
	// it to a DIFFERENT host, so two connections would tell a prober this is an
	// MTProto proxy -- with no secret needed. Parity with the wrong-secret path
	// is worth the buffer.
	maxClientHelloSize = 65531
)

var (
	ErrTooManyFragments = errors.New("too many fragments")
	ErrRecordTooLarge   = errors.New("record is too large")
	ErrHelloTooLarge    = errors.New("client hello is too large")
)

// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1
// client hello can be fragmented in a series of packets:
//
//	Bytes on the wire:
//
// 16 03 01 00 F8 01 00 00 F4 03 03 [32 bytes random] [session_id] [ciphers] [SNI...]
// ├─────────────┤├──────────────────────────────────────────────────────────────────┤
//
//	TLS record       Payload (248 bytes)
//	header (5B)
//
//	16    = Handshake
//	03 01 = TLS 1.0 (record layer version)
//	00 F8 = 248 bytes follow
//
//	01       = ClientHello (handshake type)
//	00 00 F4 = 244 bytes of handshake body
//	03 03    = TLS 1.2 (actual protocol version)
//	...rest of ClientHello...
//
// Fragmented record look like:
//
//	Record 1:
//
// 16 03 01 00 03 01 00 00
// ├─────────────┤├──────┤
//
//	TLS header    3 bytes of payload
//
//	16    = Handshake
//	03 01 = TLS 1.0
//	00 03 = only 3 bytes follow
//
//	01       = ClientHello type
//	00 00    = first 2 bytes of the uint24 length (INCOMPLETE!)
//
// Record 2:
// 16 03 01 00 F5 F4 03 03 [32 bytes random] [session_id] [ciphers] [SNI...]
// ├─────────────┤├────────────────────────────────────────────────────────────┤
//
//	TLS header    remaining 245 bytes of payload
//
//	16    = Handshake
//	03 01 = TLS 1.0
//	00 F5 = 245 bytes follow
//
//	F4    = last byte of uint24 length (now complete: 00 00 F4 = 244)
//	03 03 = TLS 1.2
//	...rest of ClientHello continues...
//
// So it means that there could be a series of handshake packets of different
// lengths. The goal of this function is to concatenate these fragments.
type fragmentedHandshakeReader struct {
	r             io.Reader
	buf           bytes.Buffer
	readFragments int
}

func (f *fragmentedHandshakeReader) Read(p []byte) (int, error) {
	if n, err := f.buf.Read(p); err == nil {
		return n, nil
	}

	f.buf.Reset()

	for f.buf.Len() == 0 {
		if f.readFragments > maxFragmentsCount {
			return 0, ErrTooManyFragments
		}

		if err := f.parseNextFragment(); err != nil {
			return 0, err
		}

		f.readFragments++
	}

	return f.buf.Read(p)
}

func (f *fragmentedHandshakeReader) parseNextFragment() error {
	// record_type(1) + version(2) + size(2)
	//   16 - type is 0x16 (handshake record)
	//   03 01 - protocol version is "3,1" (also known as TLS 1.0)
	//   00 f8 - 0xF8 (248) bytes of handshake message follows
	header := [1 + 2 + 2]byte{}

	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return fmt.Errorf("cannot read record header: %w", err)
	}

	if header[0] != tls.TypeHandshake {
		// G602 false positive: header is [1+2+2]byte and 0 is a constant.
		return fmt.Errorf("unexpected record type %#x", header[0]) //nolint:gosec
	}

	// G602 false positive: header is [1+2+2]byte; 1 and 2 are constants.
	if header[1] != 3 || header[2] != 1 { //nolint:gosec
		return fmt.Errorf("unexpected protocol version %#x %#x", header[1], header[2])
	}

	length := int64(binary.BigEndian.Uint16(header[3:]))
	if length > maxRecordPayload {
		// Refuse before io.CopyN buffers it: this bounds the first fragment,
		// which is read before the handshake length is even visible.
		return fmt.Errorf("%w: %d bytes", ErrRecordTooLarge, length)
	}

	_, err := io.CopyN(&f.buf, f.r, length)

	return err
}

func parseClientHello(r io.Reader) (*bytes.Buffer, *bytes.Buffer, error) {
	r = &fragmentedHandshakeReader{r: r}
	header := [1 + 3]byte{}

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, fmt.Errorf("cannot read handshake header: %w", err)
	}

	if header[0] != TypeHandshakeClient {
		return nil, nil, fmt.Errorf("incorrect handshake type: %#x", header[0])
	}

	// unfortunately there is not uint24 in golang, so we just reuse header
	header[0] = 0
	length := int64(binary.BigEndian.Uint32(header[:]))

	if length > maxClientHelloSize {
		// An unauthenticated 24-bit length reaching 16 MiB would otherwise be
		// copied into two buffers below before any HMAC is computed, and above
		// 65531 it also wraps the uint16 record length written into the copy.
		return nil, nil, fmt.Errorf("%w: %d bytes", ErrHelloTooLarge, length)
	}

	clientHelloCopy := &bytes.Buffer{}
	clientHelloCopy.Write([]byte{tls.TypeHandshake, 3, 1})
	binary.Write( //nolint: errcheck
		clientHelloCopy,
		binary.BigEndian,
		// 1 for handshake type
		// 3 for handshake length
		//
		//nolint:gosec // G115: guarded by the maxClientHelloSize check above
		// (65531), and the value is non-negative because it comes from a
		// uint32 of three bytes, so this is 4..65535 and cannot wrap.
		uint16(1+3+length),
	)
	clientHelloCopy.WriteByte(TypeHandshakeClient)
	clientHelloCopy.Write(header[1:])

	handshakeCopy := &bytes.Buffer{}
	writer := io.MultiWriter(clientHelloCopy, handshakeCopy)

	_, err := io.CopyN(writer, r, length)

	return clientHelloCopy, handshakeCopy, err
}
