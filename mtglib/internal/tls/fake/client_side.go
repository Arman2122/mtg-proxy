package fake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	TypeHandshakeClient = 0x01

	RandomLen = 32
	// record_type(1) + version(2) + size(2) + handshake_type(1) + uint24_length(3) + client_version(2)
	RandomOffset = 1 + 2 + 2 + 1 + 3 + 2

	// https://datatracker.ietf.org/doc/html/rfc8701#name-grease-values
	// https://medium.com/asecuritysite-when-bob-met-alice/in-cybersecurity-what-is-grease-9f8850558dea
	GreaseMask      = 0x0f0f
	GreaseValueType = 0x0a0a

	sniDNSNamesListType = 0
)

var (
	emptyRandom = [RandomLen]byte{}
	extTypeSNI  = [2]byte{}

	ErrCannotFindCipher = errors.New("cannot find a cipher")
)

type ClientHello struct {
	Random      [RandomLen]byte
	SessionID   []byte
	CipherSuite uint16
}

// ReadClientHelloResult contains the parsed ClientHello and the index of the
// secret that matched the HMAC validation.
type ReadClientHelloResult struct {
	Hello        *ClientHello
	MatchedIndex int
	MatchedHost  string
}

func ReadClientHello(
	conn net.Conn,
	secret []byte,
	hostname string,
	tolerateTimeSkewness time.Duration,
) (*ClientHello, error) {
	result, err := ReadClientHelloMulti(conn, [][]byte{secret}, []string{hostname}, tolerateTimeSkewness)
	if err != nil {
		return nil, err
	}

	return result.Hello, nil
}

// ReadClientHelloMulti is like ReadClientHello but accepts multiple secrets.
// It tries each secret until one validates the HMAC. On success it returns
// the ClientHello, the index of the matched secret, and the SNI hostname that
// matched one of the allowed hostnames.
//
// It is ParseClientHelloFor, then a plain Verify per secret in order.
func ReadClientHelloMulti(
	conn net.Conn,
	secrets [][]byte,
	hostnames []string,
	tolerateTimeSkewness time.Duration,
) (*ReadClientHelloResult, error) {
	parsed, err := ParseClientHelloFor(conn, hostnames)
	if err != nil {
		return nil, err
	}

	for idx, secret := range secrets {
		if !parsed.Verify(NewPlainCandidate(secret), tolerateTimeSkewness) {
			continue
		}

		return &ReadClientHelloResult{
			Hello:        parsed.Hello,
			MatchedIndex: idx,
			MatchedHost:  parsed.MatchedHost,
		}, nil
	}

	// Return a partial result so the caller can use matchedHost for domain
	// fronting even when no secret matched the HMAC (e.g. a DPI probe with
	// a valid SNI but garbage payload).
	return &ReadClientHelloResult{
		MatchedIndex: -1,
		MatchedHost:  parsed.MatchedHost,
	}, ErrBadDigest
}

func parseHandshake(r io.Reader) (*ClientHello, error) {
	//  A protocol version of "3,3" (meaning TLS 1.2) is given.
	header := [2]byte{}

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("cannot read client version: %w", err)
	}

	hello := &ClientHello{}

	if _, err := io.ReadFull(r, hello.Random[:]); err != nil {
		return nil, fmt.Errorf("cannot read client random: %w", err)
	}

	if _, err := io.ReadFull(r, header[:1]); err != nil {
		return nil, fmt.Errorf("cannot read session ID length: %w", err)
	}

	hello.SessionID = make([]byte, int(header[0]))

	if _, err := io.ReadFull(r, hello.SessionID); err != nil {
		return nil, fmt.Errorf("cannot read session id: %w", err)
	}

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("cannot read cipher suite length: %w", err)
	}

	cipherSuiteLen := int64(binary.BigEndian.Uint16(header[:]))

	// Pick the first non-GREASE cipher suite from the list.
	// Real TLS servers never select GREASE values (RFC 8701, pattern 0x?a?a),
	// so echoing them back is a trivial DPI fingerprint.
	// cipherSuiteLen is in bytes; each cipher suite is 2 bytes.
	for range cipherSuiteLen / 2 {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, fmt.Errorf("cannot read cipher suite: %w", err)
		}

		if hello.CipherSuite != 0 {
			// do not forget we have to scan until the end
			continue
		}

		if cs := binary.BigEndian.Uint16(header[:]); cs&GreaseMask != GreaseValueType {
			hello.CipherSuite = cs
		}
	}

	if hello.CipherSuite == 0 {
		return nil, ErrCannotFindCipher
	}

	if _, err := io.ReadFull(r, header[:1]); err != nil {
		return nil, fmt.Errorf("cannot read compression methods length: %w", err)
	}

	if _, err := io.CopyN(io.Discard, r, int64(header[0])); err != nil {
		return nil, fmt.Errorf("cannot skip compression methods: %w", err)
	}

	return hello, nil
}

func parseSNI(r io.Reader) ([]string, error) {
	header := [2]byte{}

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("cannot read length of TLS extensions: %w", err)
	}

	extensionsLength := int64(binary.BigEndian.Uint16(header[:]))
	buf := &bytes.Buffer{}

	// No Grow on this length. It is 2 unauthenticated bytes off the wire, so
	// Grow would allocate up to 64 KiB for a 60-byte connection that then fails
	// -- a ~1300x pre-auth amplification. CopyN grows the buffer to what really
	// arrives, and r is already bounded by the caller's hello limit.
	if _, err := io.CopyN(buf, r, extensionsLength); err != nil {
		return nil, fmt.Errorf("cannot read extensions: %w", err)
	}

	for buf.Len() > 0 {
		// 00 00 - assigned value for extension "server name"
		// 00 18 - 0x18 (24) bytes of "server name" extension data follows
		// 00 16 - 0x16 (22) bytes of first (and only) list entry follows
		// 00 - list entry is type 0x00 "DNS hostname"
		// 00 13 - 0x13 (19) bytes of hostname follows
		// 65 78 61 ... 6e 65 74 - "example.ulfheim.net"

		// 00 00 - assigned value for extension "server name"
		extTypeB := buf.Next(2)
		if len(extTypeB) != 2 {
			return nil, fmt.Errorf("cannot read extension type: %v", extTypeB)
		}

		// 00 18 - 0x18 (24) bytes of "server name" extension data follows
		lengthB := buf.Next(2)
		if len(lengthB) != 2 {
			return nil, fmt.Errorf("cannot read extension %v length: %v", extTypeB, lengthB)
		}
		length := int(binary.BigEndian.Uint16(lengthB))

		extDataB := buf.Next(length)
		if len(extDataB) != length {
			return nil, fmt.Errorf("cannot read extension %v data: len %d != %d", extTypeB, length, len(extDataB))
		}

		if !bytes.Equal(extTypeB, extTypeSNI[:]) {
			continue
		}

		buf.Reset()
		buf.Write(extDataB)

		// 00 16 - 0x16 (22) bytes of first (and only) list entry follows
		lengthB = buf.Next(2)
		if len(lengthB) != 2 {
			return nil, fmt.Errorf("cannot read the length of the SNI record: %v", lengthB)
		}

		length = int(binary.BigEndian.Uint16(lengthB))
		if length == 0 {
			return nil, nil
		}

		listType, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("cannot read SNI list type: %w", err)
		}

		// 00 - list entry is type 0x00 "DNS hostname"
		if listType != sniDNSNamesListType {
			return nil, fmt.Errorf("incorrect SNI list type %#x", listType)
		}

		names := []string{}

		for buf.Len() > 0 {
			// 00 13 - 0x13 (19) bytes of hostname follows
			lengthB = buf.Next(2)
			if len(lengthB) != 2 {
				return nil, fmt.Errorf("incorrect length of the hostname: %v", lengthB)
			}
			length = int(binary.BigEndian.Uint16(lengthB))

			name := buf.Next(length)
			if len(name) != length {
				return nil, fmt.Errorf("incorrect length of SNI hostname: len %d != %d", length, len(name))
			}

			names = append(names, string(name))
		}

		return names, nil
	}

	return nil, nil
}
