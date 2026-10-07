package mtglib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Per-address usage on its own endpoint, GET /secrets/{name}/clients, and the
// two counts /stats carries inside the user object. The endpoint lists
// addresses only where connected_ips would -- with track-client-ips -- and
// answers the counts either way. Nothing here is ever a key under users: the
// panel bills every key there as a client. The addresses are stamped on the
// probe's streams: documentation ranges for places (keyed), loopback and a
// private range for peers that are not.

// clientsStatsProbe is a table probe with two secrets, alice and bob, where
// alice has the limits lim. A per-address control holds entries with tracking
// off, which is how a test gets entries the endpoint must not list.
func clientsStatsProbe(t *testing.T, tracking bool, lim SecretLimits) *denyProbe {
	t.Helper()

	probe := newClientTableProbe(t, tracking)
	probe.proxy.secrets.Store(buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
	}, nil, nil, map[string]SecretLimits{"alice": lim}))
	probe.proxy.stats.PreRegister("bob")

	return probe
}

// clientsBody is GET target on p's management API: the status and the body.
func clientsBody(t *testing.T, p *Proxy, target string) (int, []byte) {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, target, "")

	return rec.Code, rec.Body.Bytes()
}

// clientsOf is alice's GET /secrets/alice/clients with query, which must answer
// 200, decoded.
func clientsOf(t *testing.T, p *Proxy, query string) ClientsReport {
	t.Helper()

	code, body := clientsBody(t, p, "/secrets/alice/clients"+query)
	require.Equal(t, http.StatusOK, code, string(body))

	var report ClientsReport

	require.NoError(t, json.Unmarshal(body, &report))

	return report
}

// clientsRaw is the same answer decoded loosely, so a test sees which keys are
// on the wire rather than what a struct accepts.
func clientsRaw(t *testing.T, p *Proxy, query string) map[string]any {
	t.Helper()

	code, body := clientsBody(t, p, "/secrets/alice/clients"+query)
	require.Equal(t, http.StatusOK, code, string(body))

	return statsRaw(t, body)
}

// rawRowsByAddress is the loosely decoded clients array, by address.
func rawRowsByAddress(t *testing.T, raw map[string]any) map[string]map[string]any {
	t.Helper()

	rows, ok := raw["clients"].([]any)
	require.True(t, ok, "clients must be a JSON array")

	out := make(map[string]map[string]any, len(rows))

	for _, row := range rows {
		fields, ok := row.(map[string]any)
		require.True(t, ok)

		address, ok := fields["address"].(string)
		require.True(t, ok, "every row names its address")

		out[address] = fields
	}

	return out
}

// addressesOf is the report's addresses, in its order.
func addressesOf(report ClientsReport) []string {
	out := make([]string, len(report.Clients))
	for i, row := range report.Clients {
		out[i] = row.Address
	}

	return out
}

// statsUsersOf is the users object of p's GET /stats, decoded loosely, with
// its keys required to be exactly the given secret names: anything else under
// users would be billed by the panel as a client.
func statsUsersOf(t *testing.T, p *Proxy, names ...string) map[string]map[string]any {
	t.Helper()

	code, body := clientsBody(t, p, "/stats")
	require.Equal(t, http.StatusOK, code)

	users, ok := statsRaw(t, body)["users"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, names, slices.Sorted(maps.Keys(users)), "the keys under users are the secrets and nothing else")

	out := make(map[string]map[string]any, len(users))

	for name, user := range users {
		fields, ok := user.(map[string]any)
		require.True(t, ok)

		out[name] = fields
	}

	return out
}

// The gate is connected_ips's, and it is the only gate: with track-client-ips
// off the answer is 200 with the counts and "tracking": false, and no address
// appears anywhere in it -- not as a field, not as a key, not as the rest
// entry -- though the table holds entries, because a per-address cap needs
// them. With tracking on the same table is listed. The counts are not
// addresses, so neither they nor the /stats scalar are gated.
func TestClientsListAddressesOnlyWhenTracked(t *testing.T) {
	t.Parallel()

	for _, tracking := range []bool{false, true} {
		t.Run(fmt.Sprintf("tracking=%v", tracking), func(t *testing.T) {
			t.Parallel()

			probe := clientsStatsProbe(t, tracking, SecretLimits{ClientConns: 8})
			p := probe.proxy

			admitFrom(t, probe, tcpFrom("203.0.113.7", 50001))
			admitFrom(t, probe, tcpFrom("203.0.113.7", 50002))
			admitFrom(t, probe, tcpFrom("2001:db8::5", 50003))
			admitFrom(t, probe, tcpFrom("127.0.0.1", 50004))

			require.Len(t, p.clients.snapshot("alice"), 3,
				"two places and the rest entry are held whatever tracking says")

			code, body := clientsBody(t, p, "/secrets/alice/clients")
			require.Equal(t, http.StatusOK, code)

			raw := statsRaw(t, body)

			assert.Equal(t, float64(2), raw["total"], "a count is not an address")
			assert.Equal(t, float64(0), raw["overflow"])
			assert.Equal(t, tracking, raw["tracking"])

			_, statsBody := clientsBody(t, p, "/stats")

			assert.Equal(t, float64(2), statsUsersOf(t, p, "alice", "bob")["alice"]["clients"],
				"nor is the scalar on /stats")

			if !tracking {
				assert.Equal(t, map[string]any{"total": float64(2), "overflow": float64(0), "tracking": false}, raw,
					"the counts and nothing else")

				for _, address := range []string{"203.0.113", "2001:db8", "127.0.0.1"} {
					assert.NotContains(t, string(body), address, "no address anywhere in the answer")
					assert.NotContains(t, string(statsBody), address, "nor in /stats")
				}

				return
			}

			assert.Equal(t, []string{"2001:db8::/64", "203.0.113.7"}, slices.Sorted(maps.Keys(rawRowsByAddress(t, raw))),
				"the places, in the unit the ledger counts")
			assert.Contains(t, raw, "rest", "and the rest entry the loopback peer joined")
		})
	}
}

// Entries are listed by the bytes they moved, both ways together, most first;
// equal totals are ordered by address, so two reads of an unchanged table give
// the same list. Address order and byte order disagree here on purpose, two
// pairs tie and five entries have moved nothing: the table hands its entries
// over in random order, so a list without the tie rule comes out in the right
// order about once in 480 reads.
func TestClientsAreListedByBytesWithStableTies(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy

	for _, row := range []struct {
		key     addressKey
		in, out int64
	}{
		{"203.0.113.1", 10, 90},
		{"203.0.113.200", 0, 0},
		{"203.0.113.2", 400, 100},
		{"198.51.100.9", 0, 100},
		{"2001:db8:0:1::/64", 0, 0},
		{"203.0.113.30", 300, 0},
		{"198.51.100.100", 0, 0},
		{"2001:db8::/64", 0, 0},
		{"198.51.100.20", 250, 250},
		{"198.51.100.1", 0, 0},
		{"203.0.113.9", 0, 1000},
	} {
		entry := p.clients.acquire("alice", row.key, true, entryInit{})
		entry.bytesIn.Add(row.in)
		entry.bytesOut.Add(row.out)
	}

	want := []string{
		"203.0.113.9",   // 1000
		"198.51.100.20", // 500, ahead of the other 500 by address
		"203.0.113.2",   // 500
		"203.0.113.30",  // 300
		"198.51.100.9",  // 100, ahead of the other 100 by address
		"203.0.113.1",   // 100
		"198.51.100.1",  // nothing yet: the five by address
		"198.51.100.100",
		"2001:db8:0:1::/64",
		"2001:db8::/64",
		"203.0.113.200",
	}

	first := addressesOf(clientsOf(t, p, ""))

	assert.Equal(t, want, first)
	assert.Equal(t, first, addressesOf(clientsOf(t, p, "")), "two reads of an unchanged table agree")
}

// limit: 100 when absent, the most-moving entries first whatever it is, at most
// 1,000 however many are asked for, and total is every entry the secret holds,
// not the page. A limit that is not a whole number above zero is refused with
// 400 and says which parameter it was, as the API refuses every malformed
// request; a number too large to read is past the maximum and is clamped.
func TestClientsLimitDefaultsAndClamps(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy

	const held = 1200

	// Bytes distinct for every entry, the last made the largest: the table's
	// map order is random, so a list cut before it is sorted keeps the wrong
	// rows.
	for i, entry := range fillClients(t, p.clients, "alice", held) {
		entry.bytesOut.Add(int64(i + 1))
	}

	requireTop := func(t *testing.T, query string, n int) {
		t.Helper()

		report := clientsOf(t, p, query)

		assert.Equal(t, held, report.Total, "total counts every entry, not the page")

		want := make([]int64, n)
		for i := range want {
			want[i] = int64(held - i)
		}

		got := make([]int64, len(report.Clients))
		for i, row := range report.Clients {
			got[i] = row.BytesOut
		}

		require.Equal(t, want, got, "limit%s is the %d entries that moved the most", query, n)
	}

	requireTop(t, "", defaultClientsLimit)
	requireTop(t, "?limit=", defaultClientsLimit)
	requireTop(t, "?limit=3", 3)
	requireTop(t, "?limit=1000", maxClientsLimit)
	requireTop(t, "?limit=5000", maxClientsLimit)
	requireTop(t, "?limit=99999999999999999999999", maxClientsLimit)

	for _, bad := range []string{"0", "-1", "-99999999999999999999999", "abc", "1.5", "0x10", "1e3", "1_000"} {
		code, body := clientsBody(t, p, "/secrets/alice/clients?limit="+bad)

		assert.Equal(t, http.StatusBadRequest, code, "limit=%s", bad)
		assert.Contains(t, string(body), "limit", "the error names the parameter")
	}
}

// Spec §4 gives these numbers verbatim; the test above is written against the
// constants, so this is the one that notices them change.
func TestClientsLimitConstantsAreTheSpecs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 100, defaultClientsLimit)
	assert.Equal(t, 1000, maxClientsLimit)
}

// The rest entry stands apart: it is its own object, with no address, never a
// row of the list and never in total. Its connections are the streams it
// governs -- unkeyed peers, which are not an overflow, and the places a full
// table turned away, which are, once per connection.
func TestClientsRestEntryStandsApart(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy

	loopback := admitFrom(t, probe, tcpFrom("127.0.0.1", 50001))
	admitFrom(t, probe, tcpFrom("10.1.2.3", 50002))
	admitFrom(t, probe, tcpFrom("203.0.113.9", 50003))

	rest := loopback.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	rest.bytesIn.Add(700)
	rest.bytesOut.Add(300)

	report := clientsOf(t, p, "")

	assert.Equal(t, 1, report.Total, "the rest entry is not an address")
	assert.Zero(t, report.Overflow, "and an unkeyed peer is not an overflow")
	assert.Equal(t, []string{"203.0.113.9"}, addressesOf(report))

	require.NotNil(t, report.Rest)
	assert.Equal(t, 2, report.Rest.Connections, "the two unkeyed streams it governs")
	assert.EqualValues(t, 700, report.Rest.BytesIn)
	assert.EqualValues(t, 300, report.Rest.BytesOut)

	restRaw, ok := clientsRaw(t, p, "")["rest"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, restRaw, "address", "the rest entry has no address to show")

	assert.Equal(t, float64(1), statsUsersOf(t, p, "alice", "bob")["alice"]["clients"])

	// The secret's part of the table full: a new place joins the rest entry.
	fillClients(t, p.clients, "alice", maxClientsPerSecret-1)

	overflowed := admitFrom(t, probe, tcpFrom("198.51.100.4", 50004))
	require.Same(t, rest, overflowed.addrEntry.Load())

	report = clientsOf(t, p, fmt.Sprintf("?limit=%d", maxClientsLimit))

	assert.Equal(t, maxClientsPerSecret, report.Total)
	assert.EqualValues(t, 1, report.Overflow)
	require.NotNil(t, report.Rest)
	assert.Equal(t, 3, report.Rest.Connections, "the overflowed place is governed there too")
	require.Len(t, report.Clients, maxClientsLimit)

	for _, row := range report.Clients {
		require.NotEmpty(t, row.Address, "no row of the list is the rest entry")
	}

	alice := statsUsersOf(t, p, "alice", "bob")["alice"]
	assert.Equal(t, float64(maxClientsPerSecret), alice["clients"])
	assert.Equal(t, float64(1), alice["clients_overflow"])
}

// connections is the ledger's count of the place's live streams, not how many
// streams hold its entry. They differ here: two streams were opened while
// nothing asked for entries and hold none, and the third, opened after tracking
// was turned on, holds the entry alone. Every socket from the place counts, a
// v4-mapped one as its IPv4 address, and a stream that closes is one less. An
// IPv6 place is its /64.
func TestClientsConnectionsComeFromTheLedger(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, false, SecretLimits{})
	p := probe.proxy

	early := admitFrom(t, probe, tcpFrom("203.0.113.9", 50001))
	admitFrom(t, probe, tcpFrom("203.0.113.9", 50002))
	require.Nil(t, early.addrEntry.Load(), "nothing asked for an entry yet")

	// No stream goroutine runs in a probe, so the setting can be flipped under
	// the streams already registered.
	p.trackClientIPs = true

	late := admitFrom(t, probe, tcpFrom("::ffff:203.0.113.9", 50003))

	entry := late.addrEntry.Load()
	require.NotNil(t, entry)
	require.Equal(t, 1, clientRefs(p.clients, entry), "one stream holds the entry")

	connectionsAt := func(t *testing.T, address string) int {
		t.Helper()

		for _, row := range clientsOf(t, p, "").Clients {
			if row.Address == address {
				return row.Connections
			}
		}

		t.Fatalf("no row for %s", address)

		return -1
	}

	assert.Equal(t, 3, connectionsAt(t, "203.0.113.9"), "every live stream of the place counts, whatever it holds")

	admitFrom(t, probe, tcpFrom("203.0.113.9", 50004))
	assert.Equal(t, 4, connectionsAt(t, "203.0.113.9"), "another socket from the place is one more")

	p.unregisterConn(early)
	assert.Equal(t, 3, connectionsAt(t, "203.0.113.9"), "a stream that closes is one less")

	p.unregisterConn(late)
	assert.Equal(t, 2, connectionsAt(t, "203.0.113.9"))

	admitFrom(t, probe, tcpFrom("2001:db8::1", 50005))
	admitFrom(t, probe, tcpFrom("2001:db8::ffff:2", 50006))
	assert.Equal(t, 2, connectionsAt(t, "2001:db8::/64"), "one /64 is one place")
}

// A row carries its entry's own numbers: bytes both ways, the time its streams
// were held by its own limiters, when it was first and last seen (RFC 3339,
// UTC, as every time on this API), and the per-address rates in force -- the
// combined one the tighter of the ceiling and the fair share, the directional
// ones the fair shares of the user's directional limits. A rate there is none
// of, a throttled time of nothing, and a ban (there are none yet) are absent.
func TestClientsRowCarriesTheEntrysNumbers(t *testing.T) {
	t.Parallel()

	const (
		ceiling = 1 << 20
		fair    = 1 << 19
		up      = 3 << 16
		down    = 5 << 16
	)

	clock := newFakeAddrClock()
	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy
	p.clients = newClientTable(clock.clock())

	held := p.clients.acquire("alice", "203.0.113.9", true, entryInit{CeilingRate: ceiling})
	held.fairSpeed.install(fair, fairBurst(fair))
	held.fairUp.install(up, fairBurst(up))
	held.fairDown.install(down, fairBurst(down))
	held.bytesIn.Add(1234)
	held.bytesOut.Add(5678)
	held.throttledNanos.Add(int64(2500 * time.Millisecond))

	clock.advance(90 * time.Second)
	held.seen(clock.read())

	p.clients.acquire("alice", "198.51.100.7", true, entryInit{CeilingRate: ceiling})
	p.clients.acquire("alice", "198.51.100.8", true, entryInit{}).fairSpeed.install(fair, fairBurst(fair))
	p.clients.acquire("alice", "198.51.100.9", true, entryInit{})

	rows := rawRowsByAddress(t, clientsRaw(t, p, ""))

	assert.Equal(t, map[string]any{
		"address":          "203.0.113.9",
		"connections":      float64(0),
		"bytes_in":         float64(1234),
		"bytes_out":        float64(5678),
		"throttled_ms":     float64(2500),
		"first_seen":       fakeAddrClockBase.UTC().Format(time.RFC3339),
		"last_seen":        fakeAddrClockBase.Add(90 * time.Second).UTC().Format(time.RFC3339),
		"speed_limit":      float64(fair),
		"speed_limit_up":   float64(up),
		"speed_limit_down": float64(down),
	}, rows["203.0.113.9"])

	assert.Equal(t, float64(ceiling), rows["198.51.100.7"]["speed_limit"], "the ceiling alone")
	assert.Equal(t, float64(fair), rows["198.51.100.8"]["speed_limit"], "the fair share alone")

	for _, key := range []string{"throttled_ms", "speed_limit", "speed_limit_up", "speed_limit_down", "banned_until"} {
		assert.NotContains(t, rows["198.51.100.9"], key, "absent where there is none")
	}
}

// The route answers as every secret route does: 404 for a secret the set does
// not have, 200 for one with nothing held -- an empty list with tracking, the
// counts alone without, and on a proxy with no table at all -- and nothing
// without the bearer token.
func TestClientsAnswersLikeEverySecretRoute(t *testing.T) {
	t.Parallel()

	t.Run("an unknown secret is 404", func(t *testing.T) {
		t.Parallel()

		probe := clientsStatsProbe(t, true, SecretLimits{})

		code, body := clientsBody(t, probe.proxy, "/secrets/nobody/clients")

		assert.Equal(t, http.StatusNotFound, code)
		assert.Contains(t, string(body), "nobody")
	})

	t.Run("a secret with nothing held", func(t *testing.T) {
		t.Parallel()

		for tracking, want := range map[bool]string{
			true:  `{"total":0,"overflow":0,"tracking":true,"clients":[]}`,
			false: `{"total":0,"overflow":0,"tracking":false}`,
		} {
			probe := clientsStatsProbe(t, tracking, SecretLimits{})

			code, body := clientsBody(t, probe.proxy, "/secrets/bob/clients")

			assert.Equal(t, http.StatusOK, code)
			assert.JSONEq(t, want, string(body), "tracking %v", tracking)
		}
	})

	t.Run("a proxy with no table", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		require.Nil(t, p.clients)

		code, body := clientsBody(t, p, "/secrets/alice/clients")

		assert.Equal(t, http.StatusOK, code)
		assert.JSONEq(t, `{"total":0,"overflow":0,"tracking":false}`, string(body))
	})

	t.Run("behind the bearer token", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

		rec := httptest.NewRecorder()
		p.buildAPIHandler("s3cret").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets/alice/clients", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, http.StatusOK, doAPI(t, p, "s3cret", http.MethodGet, "/secrets/alice/clients", "").Code)
	})
}

// /stats carries clients and clients_overflow inside the user object, absent
// while zero, and adds no key under users: the keys there are the secrets and
// nothing else, even when the table holds a name /stats does not know. The two
// numbers are the ones GET /clients reports as total and overflow. GET /secrets
// carries neither: spec §4 puts the counters in the /stats user object, and
// what /secrets reads back is the limits.
func TestStatsCountsClientsInsideTheUserObject(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy

	alice := statsUsersOf(t, p, "alice", "bob")["alice"]
	assert.NotContains(t, alice, "clients", "absent while zero")
	assert.NotContains(t, alice, "clients_overflow")

	admitFrom(t, probe, tcpFrom("203.0.113.7", 50001))
	admitFrom(t, probe, tcpFrom("203.0.113.8", 50002))
	admitFrom(t, probe, tcpFrom("127.0.0.1", 50003))

	// Nothing in the proxy makes an entry for a name /stats does not know, but
	// the overlay must not be the thing that adds one under users.
	p.clients.acquire("carol", "203.0.113.9", true, entryInit{})

	users := statsUsersOf(t, p, "alice", "bob")
	assert.Equal(t, float64(2), users["alice"]["clients"], "two places; the rest entry is not one")
	assert.NotContains(t, users["alice"], "clients_overflow", "no cap turned anybody away")
	assert.NotContains(t, users["bob"], "clients")

	fillClients(t, p.clients, "alice", maxClientsPerSecret-2)
	admitFrom(t, probe, tcpFrom("198.51.100.4", 50004))
	admitFrom(t, probe, tcpFrom("198.51.100.4", 50005))

	alice = statsUsersOf(t, p, "alice", "bob")["alice"]
	assert.Equal(t, float64(maxClientsPerSecret), alice["clients"])
	assert.Equal(t, float64(2), alice["clients_overflow"], "once per connection")

	report := clientsOf(t, p, "")
	assert.Equal(t, float64(report.Total), alice["clients"], "/stats and /clients agree")
	assert.Equal(t, float64(report.Overflow), alice["clients_overflow"])

	secret := map[string]any{}
	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &secret))
	assert.NotContains(t, secret, "clients")
	assert.NotContains(t, secret, "clients_overflow")
}

// blockedResponseWriter is a ResponseWriter whose Write waits to be let go, so
// a test can look at the proxy's locks while a handler is writing its answer.
type blockedResponseWriter struct {
	header  http.Header
	writing chan struct{}
	release chan struct{}
	once    sync.Once
	body    bytes.Buffer
}

func newBlockedResponseWriter() *blockedResponseWriter {
	return &blockedResponseWriter{
		header:  make(http.Header),
		writing: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockedResponseWriter) Header() http.Header { return w.header }

func (w *blockedResponseWriter) WriteHeader(int) {}

func (w *blockedResponseWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.writing) })
	<-w.release

	return w.body.Write(b)
}

// The report is taken under liveMu and the table's lock, and written after both
// are let go: a panel reading slowly must not hold up every admission and
// every stream's end. Both locks are free while the answer is being written.
func TestClientsHoldsNoLockWhileWriting(t *testing.T) {
	t.Parallel()

	probe := clientsStatsProbe(t, true, SecretLimits{})
	p := probe.proxy

	admitFrom(t, probe, tcpFrom("203.0.113.7", 50001))
	admitFrom(t, probe, tcpFrom("127.0.0.1", 50002))

	w := newBlockedResponseWriter()
	done := make(chan struct{})

	go func() {
		defer close(done)

		p.buildAPIHandler("").ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/secrets/alice/clients", nil))
	}()

	reached := govAwait(w.writing, 5*time.Second)

	liveFree := p.liveMu.TryLock()
	if liveFree {
		p.liveMu.Unlock()
	}

	tableFree := p.clients.mu.TryLock()
	if tableFree {
		p.clients.mu.Unlock()
	}

	close(w.release)
	<-done

	require.True(t, reached, "the handler must reach its write")
	assert.True(t, liveFree, "liveMu is let go before the answer is written")
	assert.True(t, tableFree, "and so is the table's lock")
	assert.Contains(t, w.body.String(), "203.0.113.7", "the answer is the report")
}

// Through the real door: the stamped address, not the transport's, with the
// bytes the relay moved for it both ways and its one live connection, and the
// loopback peer in the rest entry. The address outlives its connection -- the
// entry is kept ten minutes -- with no connection left.
func TestClientsReportsTheRelayThroughTheDoor(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)

	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.21", 50001))
	upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

	t.Cleanup(func() { endStream(client, upstream, done) })

	entry := liveStreamAt(t, h.proxy, "alice", "203.0.113.21").addrEntry.Load()
	require.NotNil(t, entry)

	local, localDone := h.dialProxy(t, ec.policy)
	localUp := connectThrough(t, ec, h, local, "alice", secret.Key)

	defer endStream(local, localUp, localDone)

	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, upstream.SetDeadline(deadline))

	_, err := client.Write(make([]byte, 1000))
	require.NoError(t, err)

	_, err = io.ReadFull(upstream, make([]byte, 1000))
	require.NoError(t, err)

	_, err = upstream.Write(make([]byte, 3000))
	require.NoError(t, err)

	_, err = io.ReadFull(client, make([]byte, 3000))
	require.NoError(t, err)

	// The wrapper counts a write after the socket write returns, which can be
	// after the client has read it.
	require.Eventually(t, func() bool {
		return entry.bytesIn.Load() == 1000 && entry.bytesOut.Load() == 3000
	}, 5*time.Second, time.Millisecond)

	report := clientsOf(t, h.proxy, "")

	require.Len(t, report.Clients, 1)

	row := report.Clients[0]
	assert.Equal(t, "203.0.113.21", row.Address, "the address the socket reported")
	assert.Equal(t, 1, row.Connections)
	assert.EqualValues(t, 1000, row.BytesIn)
	assert.EqualValues(t, 3000, row.BytesOut)

	require.NotNil(t, report.Rest, "the loopback peer is governed as the rest entry")
	assert.Equal(t, 1, report.Rest.Connections)

	endStream(client, upstream, done)

	report = clientsOf(t, h.proxy, "")

	require.Len(t, report.Clients, 1, "the entry outlives its connection")
	assert.Zero(t, report.Clients[0].Connections, "with none left")
	assert.EqualValues(t, 1000, report.Clients[0].BytesIn)
}
