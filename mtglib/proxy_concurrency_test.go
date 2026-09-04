package mtglib

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// upstreamSink accepts every Telegram dial the proxy makes and reads the
// obfuscated handshake off each one, so that streams can be admitted
// concurrently.
//
// govEntryCase.connect cannot do this: it accepts exactly one dial inline and
// documents that it must be called one client at a time, because a second
// concurrent dial would be accepted by the wrong caller. Every assertion in
// this file is about what happens when connections overlap, so the serialised
// form would test the opposite of the thing.
type upstreamSink struct {
	mu     sync.Mutex
	conns  []net.Conn
	failed atomic.Int64

	accepted atomic.Int64
	done     chan struct{}
}

func newUpstreamSink(t *testing.T, listener net.Listener) *upstreamSink {
	t.Helper()

	sink := &upstreamSink{done: make(chan struct{})}

	go func() {
		defer close(sink.done)

		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			sink.mu.Lock()
			sink.conns = append(sink.conns, conn)
			sink.mu.Unlock()

			// Each dial is drained on its own goroutine: the handshake read
			// must not block the accept loop, or one slow client would
			// serialise every other admission and quietly undo the
			// concurrency this harness exists to produce.
			go func(c net.Conn) {
				var handshake [64]byte

				// Errors are counted rather than asserted. require from a
				// spawned goroutine calls Goexit, which skips the rest of the
				// body and hangs whatever is waiting on it.
				if err := c.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
					sink.failed.Add(1)

					return
				}

				if _, err := io.ReadFull(c, handshake[:]); err != nil {
					sink.failed.Add(1)

					return
				}

				sink.accepted.Add(1)
			}(conn)
		}
	}()

	t.Cleanup(sink.closeAll)

	return sink
}

// closeAll ends every accepted Telegram side, which is what lets the relay's
// other direction finish once the clients are gone.
func (s *upstreamSink) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, conn := range s.conns {
		conn.Close() //nolint: errcheck
	}

	s.conns = nil
}

// liveCount totals the live connection registry, which is the structure the
// stats report is derived from and the one a leak would show up in.
func liveCount(p *Proxy) map[string]int {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	rv := make(map[string]int, len(p.liveConns))
	for name, conns := range p.liveConns {
		rv[name] = len(conns)
	}

	return rv
}

// Connections are attributed to the user whose secret opened them, and to no
// other, when many users are connected at once.
//
// The counter is per user and the secrets differ only in their key bytes, so a
// misattribution -- a stream filed under the empty name, or under whichever
// secret happened to be first in the set -- is invisible in any total and shows
// up only here.
func TestConnectionsAreCountedPerUser(t *testing.T) {
	t.Parallel()

	// Deliberately uneven: equal counts would let a report that divided the
	// total by the number of users pass.
	wanted := map[string]int{"alice": 4, "bob": 1, "carol": 3}

	secrets := make(map[string]Secret, len(wanted))

	for name := range wanted {
		secret, err := GenerateSecretMode(SecretModeDD, "")
		require.NoError(t, err)

		secrets[name] = secret
	}

	entry := govEntryCases()[1] // dd: one flight, no server round trip
	h := entry.harness(t, secrets, nil)
	h.proxy.trackClientIPs = true

	sink := newUpstreamSink(t, h.upstream)

	type live struct {
		client net.Conn
		done   <-chan struct{}
	}

	var (
		streams []live
		total   int
	)

	for name, count := range wanted {
		for i := range count {
			// A distinct address per connection, so the address report is
			// exercised at the same time and cannot collapse to one entry by
			// accident.
			client, done := dialProxyFrom(t, h, entry.policy, &net.TCPAddr{
				IP:   net.IPv4(203, 0, 113, byte(total+1)),
				Port: 40000 + i,
			})

			entry.openEntry(t, client, secrets[name].Key)

			streams = append(streams, live{client: client, done: done})
			total++
		}
	}

	// Both conditions, not just the registry. A stream is registered in admit,
	// which runs BEFORE its Telegram handshake completes, so waiting on the
	// registry alone would let teardown begin while a dial was still mid-read
	// -- and the handshake it interrupted would be counted as a failure of the
	// proxy rather than of the test's own timing.
	require.Eventually(t, func() bool {
		counts := liveCount(h.proxy)
		for name, count := range wanted {
			if counts[name] != count {
				return false
			}
		}

		return len(counts) == len(wanted) && sink.accepted.Load() == int64(total)
	}, 20*time.Second, 20*time.Millisecond,
		"every stream must register under its own secret and reach Telegram")

	stats := statsFor(t, h.proxy)

	for name, count := range wanted {
		require.EqualValues(t, count, stats.Users[name].Connections, "connections for %s", name)
		require.Len(t, stats.Users[name].ConnectedIPs, count,
			"each connection of %s came from its own address", name)
	}

	require.EqualValues(t, total, stats.TotalConnections)
	require.Zero(t, sink.failed.Load(), "no Telegram handshake may fail")

	sink.closeAll()

	for _, stream := range streams {
		stream.client.Close() //nolint: errcheck
	}

	for _, stream := range streams {
		<-stream.done
	}

	require.Eventually(t, func() bool {
		return len(liveCount(h.proxy)) == 0
	}, 20*time.Second, 20*time.Millisecond,
		"every registry entry must be released once its stream ends")

	after := statsFor(t, h.proxy)

	for name := range wanted {
		require.Zero(t, after.Users[name].Connections, "connections for %s after close", name)
		require.Empty(t, after.Users[name].ConnectedIPs, "addresses for %s after close", name)
		require.NotEmpty(t, after.Users[name].LastIP, "last_ip for %s outlives the connection", name)
	}

	require.Zero(t, after.TotalConnections)
}

// The counters stay exact while connections are opening, being scraped and
// closing at the same time.
//
// This is the assertion the race detector cannot make on its own: a report
// built by reading the registry without the lock, or a counter incremented
// outside the admission path, produces a number that is merely wrong rather
// than a data race, and a wrong gauge is what an operator bills from.
func TestCountersStayExactUnderConcurrentChurn(t *testing.T) {
	t.Parallel()

	const (
		users       = 4
		perUser     = 6
		connections = users * perUser
	)

	secrets := make(map[string]Secret, users)
	names := make([]string, 0, users)

	for i := range users {
		name := string(rune('a'+i)) + "-user"

		secret, err := GenerateSecretMode(SecretModeDD, "")
		require.NoError(t, err)

		secrets[name] = secret

		names = append(names, name)
	}

	entry := govEntryCases()[1]
	h := entry.harness(t, secrets, nil)
	h.proxy.trackClientIPs = true

	sink := newUpstreamSink(t, h.upstream)

	// A scraper running for the whole test, so every report below is taken
	// while the registry is being mutated rather than after it settles. Under
	// -race this is what proves the snapshot's lock discipline; without it the
	// reports would all be of a quiescent proxy.
	scrape := make(chan struct{})
	scrapes := &atomic.Int64{}
	scraper := &sync.WaitGroup{}

	scraper.Go(func() {
		for {
			select {
			case <-scrape:
				return
			default:
			}

			h.proxy.connectedIPs()
			h.proxy.stats.buildResponse()
			scrapes.Add(1)
		}
	})

	clients := make([]net.Conn, 0, connections)
	dones := make([]<-chan struct{}, 0, connections)

	for i := range connections {
		name := names[i%users]

		client, done := dialProxyFrom(t, h, entry.policy, &net.TCPAddr{
			IP:   net.IPv4(198, 51, 100, byte(i+1)),
			Port: 40000 + i,
		})

		entry.openEntry(t, client, secrets[name].Key)

		clients = append(clients, client)
		dones = append(dones, done)
	}

	// The registry AND the handshakes: see the note in the test above. Under a
	// loaded CI runner the gap between the two is wide enough to matter, and it
	// is what made this assertion fail there while passing locally.
	require.Eventually(t, func() bool {
		total := 0
		for _, count := range liveCount(h.proxy) {
			total += count
		}

		return total == connections && sink.accepted.Load() == int64(connections)
	}, 30*time.Second, 20*time.Millisecond,
		"every stream must be admitted and reach Telegram")

	stats := statsFor(t, h.proxy)
	require.EqualValues(t, connections, stats.TotalConnections)

	for _, name := range names {
		require.EqualValues(t, perUser, stats.Users[name].Connections,
			"each user opened the same number of connections")
	}

	// Asserted here rather than after teardown: once this test starts closing
	// sockets, a failed handshake read no longer distinguishes a proxy fault
	// from the test's own shutdown.
	require.Zero(t, sink.failed.Load(), "no Telegram handshake may fail under load")

	sink.closeAll()

	// Closed concurrently, so unregistration overlaps the scraper the same way
	// admission did.
	closers := &sync.WaitGroup{}
	for _, client := range clients {
		closers.Go(func() { client.Close() }) //nolint: errcheck
	}

	closers.Wait()

	for _, done := range dones {
		<-done
	}

	close(scrape)
	scraper.Wait()

	require.Positive(t, scrapes.Load(), "the scraper must have run against live traffic")

	require.Eventually(t, func() bool {
		return len(liveCount(h.proxy)) == 0
	}, 30*time.Second, 20*time.Millisecond,
		"the registry must drain completely -- a leftover entry is a leaked stream")

	after := statsFor(t, h.proxy)

	require.Zero(t, after.TotalConnections)

	for _, name := range names {
		require.Zero(t, after.Users[name].Connections,
			"a connection counter that does not return to zero double-counts every restart")
		require.Empty(t, after.Users[name].ConnectedIPs)
	}
}

// A user's connections are attributed to that user on both doors at once.
//
// The dd and ee entries attribute at different points -- ee after the
// ClientHello's HMAC is matched, dd by trial-decrypting the frame -- and the
// same secret is valid on both. One user arriving through both doors must
// still be one bucket.
func TestBothDoorsCountIntoOneBucket(t *testing.T) {
	t.Parallel()

	hosted := GenerateSecret(govCoverHost)

	// The same sixteen key bytes, presented in the other wire form: this is
	// the property the whole three-mode design rests on.
	obfuscated := Secret{Mode: SecretModeDD, Key: hosted.Key}

	ee := govEntryCases()[0]
	dd := govEntryCases()[1]

	h := ee.harness(t, map[string]Secret{"alice": hosted}, nil)
	h.proxy.trackClientIPs = true

	eeClient, eeDone := dialProxyFrom(t, h, ee.policy,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000})
	eeUpstream := connectThrough(t, ee, h, eeClient, "alice", hosted.Key)

	ddClient, ddDone := dialProxyFrom(t, h, dd.policy,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40001})
	ddUpstream := connectThrough(t, dd, h, ddClient, "alice", obfuscated.Key)

	stats := statsFor(t, h.proxy)

	require.EqualValues(t, 2, stats.Users["alice"].Connections,
		"one secret, two doors, one user")
	require.Equal(t, []string{"192.0.2.10", "192.0.2.20"}, stats.Users["alice"].ConnectedIPs)
	require.Len(t, stats.Users, 1, "no second bucket may appear for the other wire form")

	endStream(eeClient, eeUpstream, eeDone)
	endStream(ddClient, ddUpstream, ddDone)
}
