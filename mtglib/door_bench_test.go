package mtglib

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
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

	return openStreamFrom(tb, dc, h, name, key, readerSize, nil)
}

// openStreamFrom is openStream for a client the proxy sees at addr -- the
// address the accepted end reports, whatever the loopback socket really is. A
// nil addr is the plain loopback client of openStream.
func openStreamFrom(
	tb testing.TB, dc doorCase, h *entryHarness, name string, key [SecretKeyLength]byte, readerSize int, addr net.Addr,
) doorStream {
	tb.Helper()

	var (
		client net.Conn
		done   <-chan struct{}
	)

	if addr == nil {
		client, done = h.dialProxy(tb, dc.entry.policy)
	} else {
		client, done = dialProxyFrom(tb, h, dc.entry.policy, addr)
	}

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

// benchStampedNet is where the addresses of the stamped rows come from: the
// documentation range of RFC 5737, which looks public to the proxy (its address
// classes are loopback, private, link-local, unspecified and multicast) and
// never routes anywhere.
var benchStampedNet = netip.MustParsePrefix("203.0.113.0/24")

// benchSharedAddr is the one address every connection of an addr=shared row
// comes from.
const benchSharedAddr = "203.0.113.7"

// distinctAddr is the address of connection i of an addr=stamped row: one place
// per connection, and one port each, so the sockets are distinct as well.
func distinctAddr(i int) net.Addr {
	return tcpFrom(fmt.Sprintf("203.0.113.%d", 1+i), 40000+i)
}

// sharedAddr is the address of connection i of an addr=shared row: one place for
// every connection, and one port each, so they are still distinct sockets.
func sharedAddr(i int) net.Addr {
	return tcpFrom(benchSharedAddr, 40000+i)
}

// BenchmarkDoorBulk is the download of BenchmarkDoor from clients that are not
// on loopback, each connection stamped with a documentation address. It exists
// because a loopback peer is unkeyed: it gets no address entry of its own and
// joins the secret's shared one, so BenchmarkDoor's rows cannot show what a
// keyed address's own entry costs. These can. The rows are meant to be run old
// binary against new in one session.
//
// Two shapes of keyed place. <door>/conns=<n>/addr=stamped gives every
// connection a place of its own, so 1 or 16 distinct addresses, each touched by
// one stream: the best case for state kept per address, nothing shared.
// <door>/conns=16/addr=shared puts all sixteen connections at one address, as a
// client that opens several does and as a carrier's NAT does for many: the
// streams of one place share that place's state, which is where a counter costs
// more than it does unshared. Only at 16, because one connection at one address
// is the stamped row at 1.
//
// Download only: the bytes go Telegram -> proxy -> client, through the client
// wrapper's Write. The Read side is timed directly by BenchmarkCountingConn, and
// a second direction here would double the bytes and the rows for the same
// per-address step.
//
// The harness has no limits at all -- no ip-limit in particular -- so every
// connection is admitted whatever its address.
//
// Each row has a twin named <row>/tracked: the same streams on a proxy that
// keeps client addresses (track-client-ips), which is how a panel always runs
// the proxy. A proxy that keeps addresses gives every keyed stream a
// per-address entry, so the twins are the panel's case end to end and the rows
// without the suffix are the case of a proxy with no entries. Each twin is a
// row of its own beside the other, not a sub-benchmark of it, so the row
// without the suffix still reports. The twins use only what the old binary of
// an A/B has too, so both binaries run them.
func BenchmarkDoorBulk(b *testing.B) {
	for _, name := range []string{"ee-unpaced", "dd", "plain"} {
		dc := doorNamed(name)

		for _, conns := range []int{1, 16} {
			row := fmt.Sprintf("%s/conns=%d/addr=stamped", name, conns)

			b.Run(row, func(b *testing.B) {
				benchDoorBulkStamped(b, dc, conns, distinctAddr, conns, false)
			})
			b.Run(row+"/tracked", func(b *testing.B) {
				benchDoorBulkStamped(b, dc, conns, distinctAddr, conns, true)
			})
		}

		row := name + "/conns=16/addr=shared"

		b.Run(row, func(b *testing.B) {
			benchDoorBulkStamped(b, dc, 16, sharedAddr, 1, false)
		})
		b.Run(row+"/tracked", func(b *testing.B) {
			benchDoorBulkStamped(b, dc, 16, sharedAddr, 1, true)
		})
	}
}

// benchDoorBulkStamped moves doorChunk down every one of conns streams per
// iteration, connection i from a client at addrOf(i), which the proxy must see
// as places distinct addresses. moveChunk fails a short count, and the proxy's
// own counters are read back at the end: every byte must have been counted once,
// as the stamped user's. tracked runs the proxy with track-client-ips on, and
// the proxy's own address report must then list the places.
func benchDoorBulkStamped(b *testing.B, dc doorCase, conns int, addrOf func(i int) net.Addr, places int, tracked bool) {
	b.Helper()

	secret := dc.entry.secret(b)
	h := dc.build(b, map[string]Secret{"alice": secret}, nil)

	// The harness builds a Proxy literal, so ProxyOpts.TrackClientIPs cannot
	// reach it; this is the field that option sets. Before the first stream:
	// admission reads it.
	h.proxy.trackClientIPs = tracked

	streams := make([]doorStream, conns)

	for i := range streams {
		streams[i] = openStreamFrom(b, dc, h, "alice", secret.Key, 256<<10, addrOf(i))
	}

	requireStampedAddresses(b, h.proxy, "alice", conns, places)
	requireTracking(b, h.proxy, "alice", places, tracked)

	b.SetBytes(int64(conns) * doorChunk)
	b.ReportAllocs()

	iterations := 0

	for b.Loop() {
		if err := moveChunk(dc, streams, true); err != nil {
			b.Fatal(err)
		}

		iterations++
	}

	st := h.proxy.stats.getOrCreate("alice")
	want := int64(iterations) * int64(conns) * doorChunk

	// The wrapper counts a byte after the socket write that carried it returns,
	// which can be after the client has read it, so the last chunk's count may
	// still be arriving.
	for deadline := time.Now().Add(10 * time.Second); st.bytesOut.Load() != want && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}

	require.Equal(b, want, st.bytesOut.Load(), "every byte sent down must be counted, once")
	require.Zero(b, st.bytesIn.Load(), "a download reads nothing from the client")
}

// requireStampedAddresses reads back, from the proxy's own registry, what the
// stamping did: every one of conns streams is admitted under name, is counted in
// the address ledger, and sits at an address inside benchStampedNet that
// hintKey -- the class the automatic per-address controls use -- keys; and the
// streams are at places distinct addresses, no more and no fewer, with the
// ledger holding the same connections at the same places. It is not derived from
// the addresses the benchmark chose, which a stamping bug would change with it:
// a loopback peer, an unstamped one, sixteen connections of an addr=stamped row
// all stamped with one address, and one connection of an addr=shared row at
// another each fail it.
func requireStampedAddresses(tb testing.TB, p *Proxy, name string, conns, places int) {
	tb.Helper()

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	live := p.liveConns[name]
	require.Len(tb, live, conns, "every stamped connection must have been admitted")

	seen := make(map[addressKey]struct{}, conns)

	for stream := range live {
		require.True(tb, stream.addrCounted, "the connection must be counted at its address")

		addr, err := netip.ParseAddr(string(stream.addrKey))
		require.NoError(tb, err)
		require.True(tb, benchStampedNet.Contains(addr),
			"the proxy must see a stamped documentation address, saw %s", addr)

		_, keyed := hintKey(net.IP(addr.AsSlice()))
		require.True(tb, keyed, "%s must be a keyed address", addr)

		seen[stream.addrKey] = struct{}{}
	}

	require.Len(tb, seen, places, "the connections must be at %d distinct addresses", places)

	// The ledger is what a per-address count reads: the same places, holding all
	// the connections between them.
	ledger := p.addresses[name]
	require.NotNil(tb, ledger, "the address ledger must be counting the stamped user")
	require.Len(tb, ledger.local, places)

	held := 0
	for _, n := range ledger.local {
		held += n
	}

	require.Equal(tb, conns, held, "the ledger must hold every connection")
}

// requireTracking reads back, from the proxy's own address report, whether it
// keeps client addresses: a tracked row's proxy lists the user's places, every
// one inside benchStampedNet, and an untracked row's lists nothing. A row that
// claims to be tracked without the proxy keeping addresses would time the
// untracked path under the panel's name.
func requireTracking(tb testing.TB, p *Proxy, name string, places int, tracked bool) {
	tb.Helper()

	listed := p.connectedIPs()[name]

	if !tracked {
		require.Empty(tb, listed, "an untracked proxy lists no addresses")

		return
	}

	require.Len(tb, listed, places, "a tracking proxy lists every place the user is at")

	for _, text := range listed {
		addr, err := netip.ParseAddr(text)
		require.NoError(tb, err)
		require.True(tb, benchStampedNet.Contains(addr), "the proxy must list a stamped address, listed %s", addr)
	}
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
//
// The rows named <door> are one secret and the short forged hello. The rows
// named <door>/secrets=<N>/<first|last> are the same connection against a door
// that hosts N secrets -- N-1 decoys and the client's -- with the client's
// sorting first or last, so the scan finds it at once or walks them all. They
// exist for ee-unpaced and dd only, and the ee ones send a 517-byte hello, the
// size a real client sends.
//
// ee-unpaced alone has a third kind, <door>/secrets=<N>/last/hinted: the same
// connection from one fixed, keyed client address that has connected before, so
// the door verifies the hello against the address's hint and never scans. The
// other rows cannot show that, since their peers are loopback, which gets no
// hints. The row proves what it timed (see benchDoorHandshakeHinted), and its
// figure at N = 5,000 over its figure at N = 1 is the hint path's cost of
// hosting many secrets.
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

	for _, name := range []string{"ee-unpaced", "dd"} {
		dc := doorNamed(name)

		if dc.entry.mode == SecretModeFakeTLS {
			dc.entry = dc.entry.withHelloSize(benchHelloSize)
		}

		for _, n := range []int{1, 100, 1000, 5000} {
			for _, target := range []string{"first", "last"} {
				b.Run(fmt.Sprintf("%s/secrets=%d/%s", name, n, target), func(b *testing.B) {
					benchDoorHandshakeAmong(b, dc, n, target)
				})
			}

			if name == "ee-unpaced" && slices.Contains(benchHintedSecrets, n) {
				b.Run(fmt.Sprintf("%s/secrets=%d/last/hinted", name, n), func(b *testing.B) {
					benchDoorHandshakeHinted(b, dc, n)
				})
			}
		}
	}
}

// benchHintedSecrets are the secrets counts that have a hinted row.
var benchHintedSecrets = []int{1, 1000, 5000}

// benchHintedAddr is the client address of the hinted rows: a documentation
// address (RFC 5737), public-looking, so the hint cache keys on it; loopback,
// private and link-local ones are not keyed.
const benchHintedAddr = "203.0.113.7"

// benchHelloSize is the size of the whole ClientHello record a Telegram client
// sends to an ee door.
const benchHelloSize = 517

// benchTargetFirst and benchTargetLast are the names the client of a
// secrets-count benchmark is hosted under. buildSecretSet sorts names, and every
// decoy's name starts with a letter between these two, so where the name sorts
// is where the secret sits in the list the door scans.
const (
	benchTargetFirst = "aaa"
	benchTargetLast  = "zzz"
)

// hostedAmongDecoys is n secrets of the door's wire form: n-1 decoys and the
// client's, named so that the client's sorts first or last. It returns them and
// the client's name.
func hostedAmongDecoys(tb testing.TB, ec govEntryCase, n int, target string) (map[string]Secret, string) {
	tb.Helper()

	var name string

	switch target {
	case "first":
		name = benchTargetFirst
	case "last":
		name = benchTargetLast
	default:
		tb.Fatalf("no such target %q", target)
	}

	secrets := make(map[string]Secret, n)
	secrets[name] = ec.secret(tb)

	for i := range n - 1 {
		secrets[fmt.Sprintf("d%05d", i)] = ec.secret(tb)
	}

	return secrets, name
}

// hostedDoorAmong is a door built over n secrets, as hostedAmongDecoys makes
// them, with the client's name and key.
func hostedDoorAmong(
	b *testing.B, dc doorCase, n int, target string,
) (*entryHarness, string, [SecretKeyLength]byte) {
	b.Helper()

	secrets, name := hostedAmongDecoys(b, dc.entry, n, target)
	h := dc.build(b, secrets, nil)

	// Where the client really sits in the door's list, read back from the door
	// and not trusted from the names: a target that is not where its row says
	// would time the wrong scan, and every iteration would still succeed.
	set := h.proxy.secrets.Load()
	require.Len(b, set.names, n)

	index := map[string]int{"first": 0, "last": n - 1}[target]
	require.Equal(b, name, set.names[index], "the client must sort %s", target)
	require.Equal(b, secrets[name].Key, set.secrets[index].Key)

	return h, name, secrets[name].Key
}

// benchDoorHandshakeAmong is one whole connection per iteration, as the loop in
// BenchmarkDoorHandshake, against a door that hosts n secrets.
func benchDoorHandshakeAmong(b *testing.B, dc doorCase, n int, target string) {
	b.Helper()

	h, name, key := hostedDoorAmong(b, dc, n, target)

	for b.Loop() {
		client, done := h.dialProxy(b, dc.entry.policy)
		upstream := connectThrough(b, dc.entry, h, client, name, key)

		resetOnClose(b, client)
		resetOnClose(b, upstream)
		endStream(client, upstream, done)
	}
}

// benchDoorHandshakeHinted is one whole connection per iteration against a door
// that hosts n secrets, the client's sorting last, as benchDoorHandshakeAmong
// does -- from one fixed, keyed address, with hints on.
//
// One untimed connection comes first. It scans (the address has no hint yet),
// and the hint is written after admit, before the Telegram dial that
// connectThrough waits for, so it is in place when the timed ones begin.
//
// What the timed connections went through is read back from the door's own
// counters, because every one of them would succeed as a scan too: each must
// have been a hint hit, none a scan, and a hit costs exactly one verification.
// A setup that does not hit -- hints off, an unkeyed address -- fails the
// benchmark rather than time a scan under the hinted name.
func benchDoorHandshakeHinted(b *testing.B, dc doorCase, n int) {
	b.Helper()

	h, name, key := hostedDoorAmong(b, dc, n, "last")

	// The entry harness builds a Proxy literal, which has no hint cache.
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	// One address, one port: a hint belongs to the address, so the port does not
	// matter, and the connections are distinct sockets either way.
	addr := tcpFrom(benchHintedAddr, 41000)

	connect := func() {
		client, done := dialProxyFrom(b, h, dc.entry.policy, addr)
		upstream := connectThrough(b, dc.entry, h, client, name, key)

		resetOnClose(b, client)
		resetOnClose(b, upstream)
		endStream(client, upstream, done)
	}

	connect()

	warm := tallyOf(h.proxy)
	require.EqualValues(b, 1, warm.scanned, "the untimed connection is the scan that writes the hint")
	require.Zero(b, warm.hinted)

	iterations := 0

	for b.Loop() {
		connect()

		iterations++
	}

	moved := tallyOf(h.proxy).minus(warm)

	require.EqualValues(b, iterations, moved.hinted,
		"every timed connection must be a hint hit: the benchmark would otherwise time a scan")
	require.Zero(b, moved.scanned, "no timed connection may scan")
	require.LessOrEqual(b, moved.verifications, 2*int64(iterations),
		"a hint hit costs one verification, not a walk of the candidates")
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
