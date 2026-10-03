package webrelay

import (
	"cmp"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/require"
)

// The WEB door, benchmarked the way mtglib's door benchmarks measure the others
// (mtglib/door_bench_test.go), and named so benchstat lines them up: a client
// through the real relay and the real proxy to a fake Telegram.
//
// The client sends raw bytes after its 64-byte obfuscated2 frame and the fake
// Telegram never decrypts, so the cipher work measured is the proxy's. The test
// client's own cost -- WebSocket masking, a reader goroutine per session -- is
// part of every figure here; Tier B (tools/mtgbench) reads the relay's and the
// proxy's memory per process instead.

// webChunk is what one bulk iteration moves through each stream.
const webChunk = 1 << 20

var webZeros = make([]byte, webChunk)

// webStream is one stream carried into the proxy, with the fake Telegram end it
// reached, and a read buffer of its own.
type webStream struct {
	client   *testclient.WebStream
	upstream net.Conn
	buf      []byte
}

func benchChain(tb testing.TB) *chain {
	tb.Helper()

	// The proxy's idle timeout is the shipped default's order, not the churn
	// test's 2s: the idle benchmark holds its streams while it opens a thousand.
	return newChainWith(tb, chainOptions{telegram: telegramHandover, quiet: true, idleTimeout: 10 * time.Minute})
}

// openWebSession opens one session, as one browser tab does.
func (c *chain) openWebSession(tb testing.TB, o testclient.WebOptions) *testclient.WebSession {
	tb.Helper()

	o.Origin = originHost
	o.ResetOnClose = true

	session, err := testclient.OpenWebSession(tb.Context(), c.server.URL, c.capability.String(), o)
	require.NoError(tb, err)

	tb.Cleanup(func() { session.Close() }) //nolint: errcheck

	return session
}

// openWebStream opens stream id on session, sends its raw obfuscated2 frame,
// and takes the connection the proxy made to Telegram for it.
func (c *chain) openWebStream(tb testing.TB, session *testclient.WebSession, id uint32) webStream {
	tb.Helper()

	stream, err := session.OpenStream(id)
	require.NoError(tb, err)

	frame, err := testclient.ObfuscatedFrame(c.key, obfuscation.TagPaddedIntermediate, 2)
	require.NoError(tb, err)

	_, err = stream.Write(frame)
	require.NoError(tb, err)

	select {
	case upstream := <-c.upstreams:
		tb.Cleanup(func() { upstream.Close() }) //nolint: errcheck

		return webStream{client: stream, upstream: upstream, buf: make([]byte, 64<<10)}
	case <-time.After(10 * time.Second):
		tb.Fatal("the proxy never dialled Telegram for the stream")

		return webStream{}
	}
}

// drain reads exactly n bytes from r into buf, a piece at a time. Fewer is an
// error: every byte has to arrive.
func drain(r io.Reader, n int64, buf []byte) error {
	for got := int64(0); got < n; {
		m, err := r.Read(buf[:min(int64(len(buf)), n-got)])
		got += int64(m)

		if err != nil && got < n {
			return fmt.Errorf("%d of %d bytes arrived: %w", got, n, cmp.Or(err, io.ErrUnexpectedEOF))
		}
	}

	return nil
}

// moveWebChunk moves webChunk through every stream at once, in the given
// direction, and fails on any short count.
func moveWebChunk(streams []webStream, download bool) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		fail error
	)

	note := func(err error) {
		if err != nil {
			mu.Lock()
			fail = cmp.Or(fail, err)
			mu.Unlock()
		}
	}

	for _, s := range streams {
		if download {
			wg.Go(func() { _, err := s.upstream.Write(webZeros); note(err) })
			wg.Go(func() { note(drain(s.client, webChunk, s.buf)) })

			continue
		}

		wg.Go(func() { _, err := s.client.Write(webZeros); note(err) })
		wg.Go(func() { note(drain(s.upstream, webChunk, s.buf)) })
	}

	wg.Wait()

	return fail
}

// The bulk benchmark fails on a short count: a Telegram that sends one byte
// less than it was asked to and hangs up must not pass as a full transfer.
func TestDoorWebBenchmarkFailsOnAShortCount(t *testing.T) {
	t.Parallel()

	c := benchChain(t)
	s := c.openWebStream(t, c.openWebSession(t, testclient.WebOptions{}), 1)
	s.upstream = shortTelegram{s.upstream}

	done := make(chan error, 1)

	go func() { done <- moveWebChunk([]webStream{s}, true) }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("a short transfer hung instead of failing")
	}
}

// shortTelegram drops the last byte of what it is asked to send, then hangs up.
type shortTelegram struct{ net.Conn }

func (s shortTelegram) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p[:len(p)-1])
	s.Close() //nolint: errcheck

	if err != nil {
		return n, err //nolint: wrapcheck
	}

	return len(p), nil
}

func benchWebBulk(b *testing.B, download bool, conns int) {
	b.Helper()

	c := benchChain(b)
	session := c.openWebSession(b, testclient.WebOptions{})

	streams := make([]webStream, conns)
	for i := range streams {
		streams[i] = c.openWebStream(b, session, uint32(i+1)) //nolint: gosec // a small index
	}

	b.SetBytes(int64(conns) * webChunk)
	b.ReportAllocs()

	for b.Loop() {
		if err := moveWebChunk(streams, download); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDoor is the WEB row of mtglib's BenchmarkDoor: one session, its
// streams sharing one carrier, as one browser carries a client's connections.
func BenchmarkDoor(b *testing.B) {
	for _, dir := range []string{"download", "upload"} {
		for _, conns := range []int{1, 16, 64} {
			b.Run(fmt.Sprintf("web/%s/conns=%d", dir, conns), func(b *testing.B) {
				benchWebBulk(b, dir == "download", conns)
			})
		}
	}
}

// BenchmarkDoorRoundTrip sends 100 bytes through to Telegram, which answers with
// 100, and reports the percentiles of the round trip. Take these on Linux.
func BenchmarkDoorRoundTrip(b *testing.B) {
	const size = 100

	b.Run("web", func(b *testing.B) {
		c := benchChain(b)
		s := c.openWebStream(b, c.openWebSession(b, testclient.WebOptions{}), 1)

		go func() {
			buf := make([]byte, size)

			for {
				if _, err := io.ReadFull(s.upstream, buf); err != nil {
					return
				}

				if _, err := s.upstream.Write(buf); err != nil {
					return
				}
			}
		}()

		message := make([]byte, size)
		answer := make([]byte, size)
		samples := make([]time.Duration, 0, 1<<16)

		for b.Loop() {
			started := time.Now()

			if _, err := s.client.Write(message); err != nil {
				b.Fatal(err)
			}

			if _, err := io.ReadFull(s.client, answer); err != nil {
				b.Fatal(err)
			}

			samples = append(samples, time.Since(started))
		}

		reportPercentiles(b, samples)
	})
}

// BenchmarkDoorHandshake is one whole WEB connection per iteration: bridge
// page, session, carrier, stream, the proxy's dial to Telegram, and the
// session's DELETE.
func BenchmarkDoorHandshake(b *testing.B) {
	b.Run("web", func(b *testing.B) {
		c := benchChain(b)

		for b.Loop() {
			// A small read buffer: the client's own 256 KiB default would
			// otherwise be most of what this reports per connection.
			session, err := testclient.OpenWebSession(b.Context(), c.server.URL, c.capability.String(),
				testclient.WebOptions{Origin: originHost, ResetOnClose: true, ReadBufferSize: 4 << 10})
			if err != nil {
				b.Fatal(err)
			}

			s := c.openWebStream(b, session, 1)

			if err := testclient.ResetOnClose(s.upstream); err != nil {
				b.Fatal(err)
			}

			if err := session.Delete(b.Context()); err != nil {
				b.Fatal(err)
			}

			s.upstream.Close() //nolint: errcheck
		}
	})
}

// BenchmarkDoorIdle holds 1,000 sessions of one stream each open and reports
// what each costs. The figures include the test client's own side: a 4 KiB read
// buffer and a reader goroutine per session.
func BenchmarkDoorIdle(b *testing.B) {
	const sessions = 1000

	b.Run("web", func(b *testing.B) {
		c := benchChain(b)

		var before, after runtime.MemStats

		runtime.GC()
		runtime.ReadMemStats(&before)
		goroutines := runtime.NumGoroutine()

		for range sessions {
			c.openWebStream(b, c.openWebSession(b, testclient.WebOptions{ReadBufferSize: 4 << 10}), 1)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)

		for b.Loop() {
			// Nothing to time: the figures are about holding the sessions.
		}

		perSession := func(a, b uint64) float64 { return (float64(a) - float64(b)) / sessions }

		b.ReportMetric(perSession(after.HeapInuse, before.HeapInuse), "heap-B/conn")
		b.ReportMetric(perSession(after.StackInuse, before.StackInuse), "stack-B/conn")
		b.ReportMetric(float64(runtime.NumGoroutine()-goroutines)/sessions, "goroutines/conn")
	})
}

// reportPercentiles is mtglib's (door_bench_test.go), for this package.
func reportPercentiles(b *testing.B, samples []time.Duration) {
	b.Helper()

	if len(samples) == 0 {
		return
	}

	slices.Sort(samples)

	at := func(q float64) float64 {
		return float64(samples[min(len(samples)-1, int(q*float64(len(samples))))].Nanoseconds()) / 1e3
	}

	b.ReportMetric(at(0.50), "p50-µs")
	b.ReportMetric(at(0.99), "p99-µs")
	b.ReportMetric(at(0.999), "p999-µs")
}
