package benchmarks

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// =========================================================================
// obfuscated2 trial decryption: the cost an unauthenticated peer can force
// with 64 bytes, before any per-secret throttle can run (there is no name yet).
//
// The MISS is the number that matters: a matching key breaks the loop, so the
// DoS figure is N candidates all failing.
// =========================================================================

// benchConn is the smallest essentials.Conn that MatchHandshake will accept. A
// testify mock here would put reflection in the measurement at N=1.
type benchConn struct {
	reader bytes.Reader
}

func (b *benchConn) Read(p []byte) (int, error)         { return b.reader.Read(p) }
func (b *benchConn) Write(p []byte) (int, error)        { return len(p), nil }
func (b *benchConn) Close() error                       { return nil }
func (b *benchConn) CloseRead() error                   { return nil }
func (b *benchConn) CloseWrite() error                  { return nil }
func (b *benchConn) LocalAddr() net.Addr                { return nil }
func (b *benchConn) RemoteAddr() net.Addr               { return nil }
func (b *benchConn) SetDeadline(_ time.Time) error      { return nil }
func (b *benchConn) SetReadDeadline(_ time.Time) error  { return nil }
func (b *benchConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ essentials.Conn = (*benchConn)(nil)

func benchRandom(size int) []byte {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return buf
}

// benchFrame is a real 64-byte handshake produced by the obfuscator, so the
// frame layout the matcher walks is exactly the production one.
func benchFrame(secret []byte, tag obfuscation.ConnectionTag) []byte {
	sink := &capturingConn{}
	obfs := obfuscation.Obfuscator{Secret: secret}

	if _, err := obfs.SendHandshake(sink, 2, tag); err != nil {
		panic(err)
	}

	return sink.buf.Bytes()
}

type capturingConn struct {
	benchConn

	buf bytes.Buffer
}

func (c *capturingConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

// BenchmarkTrialDecrypt measures the no-early-exit case cited by the DoS
// analysis: N configured secrets, none of which decrypts the frame.
func BenchmarkTrialDecrypt(b *testing.B) {
	allowed := obfuscation.TagSetOf(
		obfuscation.TagPaddedIntermediate,
		obfuscation.TagIntermediate,
		obfuscation.TagAbridged)

	// Built under a key that is deliberately NOT in the candidate set.
	frame := benchFrame(benchRandom(16), obfuscation.TagPaddedIntermediate)

	for _, total := range []int{1, 10, 100, 1000} {
		keys := make([][]byte, total)
		for i := range keys {
			keys[i] = benchRandom(16)
		}

		b.Run(fmt.Sprintf("N=%d", total), func(b *testing.B) {
			transport := &benchConn{}

			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				transport.reader.Reset(frame)

				if _, err := obfuscation.MatchHandshake(transport, keys, allowed); err == nil {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}

// BenchmarkTrialDecryptHit is the legitimate-client cost: the match sits at the
// last index, so it pays the full loop plus the commit (second SHA-256, revert,
// 64-byte keystream).
func BenchmarkTrialDecryptHit(b *testing.B) {
	allowed := obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate)

	for _, total := range []int{1, 10, 100, 1000} {
		keys := make([][]byte, total)
		for i := range keys {
			keys[i] = benchRandom(16)
		}

		frame := benchFrame(keys[total-1], obfuscation.TagPaddedIntermediate)

		b.Run(fmt.Sprintf("N=%d", total), func(b *testing.B) {
			transport := &benchConn{}

			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				transport.reader.Reset(frame)

				if _, err := obfuscation.MatchHandshake(transport, keys, allowed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
