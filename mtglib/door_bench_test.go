package mtglib

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/stretchr/testify/require"
)

// Every door, end to end through ServeConn: real loopback TCP on both legs and
// a fake Telegram that pushes and sinks bytes without decrypting them, so
// nearly all the CPU a benchmark spends is the proxy's own. The load
// generator's side keeps its buffers from setup, so allocs/op is the proxy's
// too. benchmarks/README.md says how these are run on the bench box and
// compared.

// doorChunk is what every stream moves per iteration of a bulk benchmark.
const doorChunk = 1 << 20

// benchRecordPayload is the payload of each TLS record an ee client sends:
// 2^14, the TLS maximum, so a doorChunk is exactly 64 records.
const benchRecordPayload = 1 << 14

// benchRecord is one full application-data record a client sends upstream.
// Read-only, so concurrent writers can share it.
var benchRecord = tlsApplicationRecord(make([]byte, benchRecordPayload))

type doorCase struct {
	name  string
	entry govEntryCase
	build func(tb testing.TB, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness
}

func doorCases() []doorCase {
	cases := govEntryCases()

	return []doorCase{
		{name: "ee-record", entry: cases[0], build: pacedHarness},
		{name: "ee-burst", entry: cases[0], build: burstHarness},
		{name: "ee-unpaced", entry: cases[0], build: cases[0].harness},
		{name: "dd", entry: cases[1], build: cases[1].harness},
		{name: "plain", entry: cases[2], build: cases[2].harness},
	}
}

func doorNamed(name string) doorCase {
	for _, dc := range doorCases() {
		if dc.name == name {
			return dc
		}
	}

	panic("no door case " + name)
}

// pacedHarness is govEntryCase.harness without Unpace: the doppelganger paces
// the ee write path exactly as it does in production by default.
func pacedHarness(tb testing.TB, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness {
	tb.Helper()

	return shapedHarness(tb, secrets, limits, doppel.ShapingRecord)
}

// burstHarness runs the doppelganger as [defense.doppelganger] shaping =
// "burst" does.
func burstHarness(tb testing.TB, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness {
	tb.Helper()

	return shapedHarness(tb, secrets, limits, doppel.ShapingBurst)
}

func shapedHarness(
	tb testing.TB, secrets map[string]Secret, limits map[string]SecretLimits, shaping doppel.Shaping,
) *entryHarness {
	tb.Helper()

	h := newEntryHarness(tb, secrets, limits)
	h.proxy.doppelGanger = doppel.NewGanger(h.proxy.ctx, h.network, testLogger(), time.Hour, 1, nil, false, shaping, false)
	h.proxy.doppelGanger.Run()
	tb.Cleanup(h.proxy.doppelGanger.Shutdown)
	h.proxy.idleTimeout = time.Minute
	h.proxy.handshakeTimeout = 3 * govDenyBudget

	return h
}

// doorStream is one client carried into the relay, with the fake Telegram end
// it reached.
type doorStream struct {
	client   net.Conn
	reader   *bufio.Reader
	upstream net.Conn
}

// openStream carries one client of user name into the relay. readerSize 0
// leaves the client end unbuffered, for tests that only hold streams open.
func openStream(tb testing.TB, dc doorCase, h *entryHarness, name string, key [SecretKeyLength]byte, readerSize int) doorStream {
	tb.Helper()

	client, done := h.dialProxy(tb, dc.entry.policy)
	upstream := connectThrough(tb, dc.entry, h, client, name, key)

	// Reset, not closed, for the reason BenchmarkDoorHandshake gives: the idle
	// benchmark alone ends thousands of streams per run.
	tb.Cleanup(func() {
		resetOnClose(tb, client)
		resetOnClose(tb, upstream)
		endStream(client, upstream, done)
	})

	stream := doorStream{client: client, upstream: upstream}

	var flight io.Reader = client

	if readerSize > 0 {
		stream.reader = bufio.NewReaderSize(client, readerSize)
		flight = stream.reader
	}

	if dc.entry.mode == SecretModeFakeTLS {
		skipServerFlight(tb, flight)
	}

	// connectThrough leaves short deadlines meant for setup; a benchmark runs
	// longer, but must still not hang for ever on a regression.
	deadline := time.Now().Add(10 * time.Minute)
	require.NoError(tb, client.SetDeadline(deadline))
	require.NoError(tb, upstream.SetDeadline(deadline))

	return stream
}

// skipServerFlight consumes the rest of the ee server flight after
// connectThrough read its first byte: the handshake record, then the
// change-cipher-spec and noise records.
func skipServerFlight(tb testing.TB, r io.Reader) {
	tb.Helper()

	var header [tls.SizeHeader - 1]byte

	_, err := io.ReadFull(r, header[:])
	require.NoError(tb, err)

	_, err = io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint16(header[2:])))
	require.NoError(tb, err)

	for range 2 {
		_, _, err = tls.ReadRecord(r, io.Discard)
		require.NoError(tb, err)
	}
}

// readRecordPayload reads TLS records until n payload bytes have arrived. It
// discards through the bufio.Reader so the load generator allocates nothing.
func readRecordPayload(r *bufio.Reader, n int) error {
	var header [tls.SizeHeader]byte

	for got := 0; got < n; {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return err //nolint: wrapcheck
		}

		length := int(binary.BigEndian.Uint16(header[3:]))

		if _, err := r.Discard(length); err != nil {
			return err //nolint: wrapcheck
		}

		got += length
	}

	return nil
}

// writeRecords sends n payload bytes as application records of
// benchRecordPayload bytes; n must be a multiple of it.
func writeRecords(w io.Writer, n int) error {
	if n%benchRecordPayload != 0 {
		return fmt.Errorf("writeRecords: %d is not a multiple of %d", n, benchRecordPayload)
	}

	for sent := 0; sent < n; sent += benchRecordPayload {
		if _, err := w.Write(benchRecord); err != nil {
			return err //nolint: wrapcheck
		}
	}

	return nil
}

// zeroChunk is what the raw writers send. Read-only, shared.
var zeroChunk = make([]byte, doorChunk)

// moveChunk moves doorChunk bytes through every stream at once, in the given
// direction, and reports the first failure. A short count is a failure: every
// byte has to arrive.
func moveChunk(dc doorCase, streams []doorStream, download bool) error {
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

	ee := dc.entry.mode == SecretModeFakeTLS

	for _, s := range streams {
		if download {
			wg.Go(func() { _, err := s.upstream.Write(zeroChunk); note(err) })
			wg.Go(func() {
				if ee {
					note(readRecordPayload(s.reader, doorChunk))
				} else {
					_, err := io.CopyN(io.Discard, s.reader, doorChunk)
					note(err)
				}
			})

			continue
		}

		wg.Go(func() {
			if ee {
				note(writeRecords(s.client, doorChunk))
			} else {
				_, err := s.client.Write(zeroChunk)
				note(err)
			}
		})
		wg.Go(func() { _, err := io.CopyN(io.Discard, s.upstream, doorChunk); note(err) })
	}

	wg.Wait()

	return fail
}

// benchDoorBulk opens one stream per entry of users -- the entry is the user
// that stream belongs to -- and moves doorChunk through all of them per
// iteration.
func benchDoorBulk(b *testing.B, dc doorCase, download bool, users []string, limits map[string]SecretLimits) {
	b.Helper()

	secrets := make(map[string]Secret)

	for _, user := range users {
		if _, ok := secrets[user]; !ok {
			secrets[user] = dc.entry.secret(b)
		}
	}

	h := dc.build(b, secrets, limits)
	streams := make([]doorStream, len(users))

	for i, user := range users {
		streams[i] = openStream(b, dc, h, user, secrets[user].Key, 256<<10)
	}

	b.SetBytes(int64(len(streams)) * doorChunk)
	b.ReportAllocs()

	for b.Loop() {
		if err := moveChunk(dc, streams, download); err != nil {
			b.Fatal(err)
		}
	}
}

func repeatUser(name string, n int) []string {
	users := make([]string, n)
	for i := range users {
		users[i] = name
	}

	return users
}

func manyUsers(n int) []string {
	users := make([]string, n)
	for i := range users {
		users[i] = fmt.Sprintf("u%02d", i)
	}

	return users
}

func BenchmarkDoor(b *testing.B) {
	for _, dc := range doorCases() {
		for _, dir := range []string{"download", "upload"} {
			for _, conns := range []int{1, 16, 64} {
				b.Run(fmt.Sprintf("%s/%s/conns=%d", dc.name, dir, conns), func(b *testing.B) {
					benchDoorBulk(b, dc, dir == "download", repeatUser("alice", conns), nil)
				})
			}
		}
	}

	dd := doorNamed("dd")

	// The same bytes, through one user's sixteen connections and through
	// sixteen users: the difference is what sharing a user's counters and
	// bucket costs.
	b.Run("dd/one-user-16-conns", func(b *testing.B) {
		benchDoorBulk(b, dd, true, repeatUser("alice", 16), nil)
	})
	b.Run("dd/16-users", func(b *testing.B) {
		benchDoorBulk(b, dd, true, manyUsers(16), nil)
	})

	// A speed limit far above anything a socket can carry: the limiter never
	// waits, so whatever this costs over dd/download/conns=1 is its bookkeeping.
	b.Run("dd/cap-far-above", func(b *testing.B) {
		benchDoorBulk(b, dd, true, []string{"alice"},
			map[string]SecretLimits{"alice": {SpeedBytesPerSecond: 1 << 40}})
	})
}

// BenchmarkDoorRoundTrip sends a 100-byte message to the fake Telegram, which
// answers with 100 bytes, and reports the percentiles of the round trip. Take
// these numbers on Linux: Go's clock on Windows advances in steps of about
// half a millisecond, so there the percentiles come out as 0 or ~500 µs.
func BenchmarkDoorRoundTrip(b *testing.B) {
	const size = 100

	for _, dc := range doorCases() {
		b.Run(dc.name, func(b *testing.B) {
			secret := dc.entry.secret(b)
			h := dc.build(b, map[string]Secret{"alice": secret}, nil)
			s := openStream(b, dc, h, "alice", secret.Key, 64<<10)

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

			ee := dc.entry.mode == SecretModeFakeTLS
			message := make([]byte, size)
			answer := make([]byte, size)

			if ee {
				message = tlsApplicationRecord(message)
			}

			samples := make([]time.Duration, 0, 1<<16)

			for b.Loop() {
				started := time.Now()

				if _, err := s.client.Write(message); err != nil {
					b.Fatal(err)
				}

				var err error
				if ee {
					err = readRecordPayload(s.reader, size)
				} else {
					_, err = io.ReadFull(s.reader, answer)
				}

				if err != nil {
					b.Fatal(err)
				}

				samples = append(samples, time.Since(started))
			}

			reportPercentiles(b, samples)
		})
	}

	// The same round trip with no proxy at all: a door's added latency is its
	// figure minus this one.
	b.Run("direct", func(b *testing.B) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(b, err)

		b.Cleanup(func() { listener.Close() }) //nolint: errcheck

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			defer conn.Close() //nolint: errcheck

			buf := make([]byte, size)

			for {
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}

				if _, err := conn.Write(buf); err != nil {
					return
				}
			}
		}()

		client, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(b, err)

		b.Cleanup(func() { client.Close() }) //nolint: errcheck

		message := make([]byte, size)
		answer := make([]byte, size)
		samples := make([]time.Duration, 0, 1<<16)

		for b.Loop() {
			started := time.Now()

			if _, err := client.Write(message); err != nil {
				b.Fatal(err)
			}

			if _, err := io.ReadFull(client, answer); err != nil {
				b.Fatal(err)
			}

			samples = append(samples, time.Since(started))
		}

		reportPercentiles(b, samples)
	})
}

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

// BenchmarkDoorHandshake is one whole connection per iteration: dial, open the
// entry, reach the relay, end the stream.
//
// The test's own two sockets are reset rather than closed. Thousands of
// iterations a second would otherwise fill the kernel's TIME_WAIT table
// (16,384 on the bench box) within seconds; past that the kernel reuses ports
// whose old connections are still settling, a fresh SYN is dropped and
// retried with backoff, and one iteration stalls ~15 s. That is the test's
// churn, not the proxy's cost, so the test does not create it.
func BenchmarkDoorHandshake(b *testing.B) {
	for _, dc := range doorCases() {
		b.Run(dc.name, func(b *testing.B) {
			secret := dc.entry.secret(b)
			h := dc.build(b, map[string]Secret{"alice": secret}, nil)

			for b.Loop() {
				client, done := h.dialProxy(b, dc.entry.policy)
				upstream := connectThrough(b, dc.entry, h, client, "alice", secret.Key)

				resetOnClose(b, client)
				resetOnClose(b, upstream)
				endStream(client, upstream, done)
			}
		})
	}
}

// BenchmarkDoorIdle holds 1,000 streams open and reports what each costs. The
// figures include the test's own two sockets per stream, a few hundred bytes.
func BenchmarkDoorIdle(b *testing.B) {
	const streams = 1000

	for _, dc := range doorCases() {
		b.Run(dc.name, func(b *testing.B) {
			secret := dc.entry.secret(b)
			h := dc.build(b, map[string]Secret{"alice": secret}, nil)

			var before, after runtime.MemStats

			runtime.GC()
			runtime.ReadMemStats(&before)
			goroutines := runtime.NumGoroutine()

			for range streams {
				openStream(b, dc, h, "alice", secret.Key, 0)
			}

			runtime.GC()
			runtime.ReadMemStats(&after)

			for b.Loop() {
				// Nothing to time: the figures are about holding the streams.
			}

			perStream := func(a, b uint64) float64 { return (float64(a) - float64(b)) / streams }

			b.ReportMetric(perStream(after.HeapInuse, before.HeapInuse), "heap-B/conn")
			b.ReportMetric(perStream(after.StackInuse, before.StackInuse), "stack-B/conn")
			b.ReportMetric(float64(runtime.NumGoroutine()-goroutines)/streams, "goroutines/conn")
		})
	}
}
