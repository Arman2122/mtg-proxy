package mtglib

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Bans: an operator refuses a secret to an address for a while, through the
// management API, in memory only. A ban is held at the unit kick and the
// address limit count -- an IPv4 address, an IPv6 /64 -- and it ends the
// address's live streams in the same critical section that records it, so no
// stream can register between the two. The addresses themselves are listed and
// echoed only where connected_ips would be: with track-client-ips.

// banProbe is the clients probe -- alice and bob, a table, no limits -- with
// the ban list on a clock the test moves.
func banProbe(t *testing.T, tracking bool) (*denyProbe, *fakeAddrClock) {
	t.Helper()

	probe := clientsStatsProbe(t, tracking, SecretLimits{})
	clock := newFakeAddrClock()
	probe.proxy.bans.now = clock.read

	return probe, clock
}

// postBan is POST /secrets/{name}/bans with body: the status and the body.
func postBan(t *testing.T, p *Proxy, name, body string) (int, string) {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodPost, "/secrets/"+name+"/bans", body)

	return rec.Code, rec.Body.String()
}

// mustBan is postBan that must answer 200, decoded.
func mustBan(t *testing.T, p *Proxy, name, body string) BanResult {
	t.Helper()

	code, text := postBan(t, p, name, body)
	require.Equal(t, http.StatusOK, code, text)

	var result BanResult

	require.NoError(t, json.Unmarshal([]byte(text), &result))

	return result
}

// liftBan is DELETE /secrets/{name}/bans/{address}: the status and the body.
func liftBan(t *testing.T, p *Proxy, name, address string) (int, string) {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodDelete, "/secrets/"+name+"/bans/"+address, "")

	return rec.Code, rec.Body.String()
}

// listBans is GET /secrets/{name}/bans: the status and the body.
func listBans(t *testing.T, p *Proxy, name string) (int, string) {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, "/secrets/"+name+"/bans", "")

	return rec.Code, rec.Body.String()
}

// isBanned asks the ban list whether ip is banned from name now.
func isBanned(p *Proxy, name, ip string) bool {
	key, ok := addressKeyOf(net.ParseIP(ip))

	return ok && p.bans.banned(name, key)
}

// bansHeld counts the bans the list holds across every secret, expired ones
// not yet pruned included, from the maps themselves under the list's lock, and
// requires the count it keeps beside them to agree.
func bansHeld(t *testing.T, p *Proxy) int {
	t.Helper()

	p.bans.mu.Lock()
	defer p.bans.mu.Unlock()

	n := 0
	for _, secret := range p.bans.bans {
		n += len(secret)
	}

	require.EqualValues(t, n, p.bans.held.Load(), "the kept count agrees with the maps")

	return n
}

// A request is checked before anything is done with it, as the rest of the
// API checks its requests: a body the strict decoder refuses, no address, a
// string that is neither an address nor an IPv6 /64, a zone, any other prefix,
// and a ttl that does not parse or is outside (0, 30 days] are 400 and ban
// nothing. An unknown secret is 404 on every bans route, once the request is
// well formed.
func TestBanRequestsAreValidatedLikeTheRestOfTheAPI(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, true)
	p := probe.proxy

	for _, body := range []string{
		`{}`,
		`{"ips":[]}`,
		`{"ips":["not-an-ip"]}`,
		`{"ips":["fe80::1%eth0"]}`,
		`{"ips":["203.0.113.0/24"]}`,
		`{"ips":["203.0.113.9/32"]}`,
		`{"ips":["2001:db8::/48"]}`,
		`{"ips":["2001:db8::/128"]}`,
		`{"ips":["::ffff:203.0.113.9/64"]}`,
		`{"ips":["203.0.113.9"],"ttl":"soon"}`,
		`{"ips":["203.0.113.9"],"ttl":"0s"}`,
		`{"ips":["203.0.113.9"],"ttl":"-1h"}`,
		`{"ips":["203.0.113.9"],"ttl":"720h0m1s"}`,
		`{"ips":["203.0.113.9"],"ttl":"30d"}`,
		`{"ips":["203.0.113.9"],"until":"1h"}`,
		`{"ips":["203.0.113.9"],"force":"yes"}`,
		`{"ips":["203.0.113.9","nope"]}`,
	} {
		code, text := postBan(t, p, "alice", body)
		assert.Equal(t, http.StatusBadRequest, code, "%s: %s", body, text)
	}

	assert.Zero(t, bansHeld(t, p), "a refused request bans nothing")

	code, _ := postBan(t, p, "nobody", `{"ips":[]}`)
	assert.Equal(t, http.StatusBadRequest, code, "a malformed request is 400 whatever the secret, as kick answers")

	code, text := postBan(t, p, "nobody", `{"ips":["203.0.113.9"]}`)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Contains(t, text, "nobody")

	code, _ = listBans(t, p, "nobody")
	assert.Equal(t, http.StatusNotFound, code)

	code, _ = liftBan(t, p, "nobody", "203.0.113.9")
	assert.Equal(t, http.StatusNotFound, code)

	assert.Zero(t, bansHeld(t, p), "nor does a ban of a secret that is not there")

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"],"ttl":"720h"}`)
	mustBan(t, p, "alice", `{"ips":["203.0.113.10"],"ttl":"1m"}`)
	assert.Equal(t, 2, bansHeld(t, p), "the longest ttl and a short one are taken")
}

// The ttl's bounds and default are the spec's numbers.
func TestBanConstantsAreTheSpecs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, time.Hour, DefaultBanTTL)
	assert.Equal(t, 30*24*time.Hour, MaxBanTTL)
	assert.Equal(t, 4096, maxBans)
}

// An address that does not stand for one place -- loopback, private,
// link-local, unspecified, multicast, read off the unmapped address -- is
// refused with 400 unless the request says force: behind a front or a
// PROXY-protocol listener one such address is every client. So is an address
// that stands for one place but is held at a unit that takes in such an
// address: ::2 and the IPv4-compatible ::203.0.113.9 are keyed, and a ban of
// either is held at ::/64, where ::1 and :: are too. A request with one such
// address among keyed ones is refused whole; a keyed IPv6 address whose /64 is
// all keyed needs no force.
func TestAnUnkeyedAddressIsBannedOnlyWhenForced(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, true)
	p := probe.proxy

	for _, address := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.1.1", "0.0.0.0", "224.0.0.1",
		"::1", "::", "fe80::1", "fd00::7", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"fd00:1:2:3::/64", "fe80::/64",
		"::2", "::203.0.113.9", "::1:0:0:1",
	} {
		before := bansHeld(t, p)

		code, text := postBan(t, p, "alice", `{"ips":["`+address+`"]}`)
		assert.Equal(t, http.StatusBadRequest, code, address)
		assert.Contains(t, text, "force", "%s: the answer says how to ban it anyway", address)
		assert.Equal(t, before, bansHeld(t, p), address)

		result := mustBan(t, p, "alice", `{"ips":["`+address+`"],"force":true}`)
		assert.Equal(t, 1, result.Banned, address)
	}

	before := bansHeld(t, p)

	code, _ := postBan(t, p, "alice", `{"ips":["203.0.113.9","127.0.0.2"]}`)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, before, bansHeld(t, p), "refused whole: the keyed address is not banned either")
	assert.False(t, isBanned(p, "alice", "203.0.113.9"))

	result := mustBan(t, p, "alice", `{"ips":["2001:db8::1","::ffff:203.0.113.9"]}`)
	assert.Equal(t, []string{"2001:db8::/64", "203.0.113.9"}, result.Addresses,
		"the control: a keyed /64, and a v4-mapped address, which is its IPv4 address, need no force")
}

// A request names at most as many places as the list can hold. One that names
// more could never fit, and is refused with 400 before anything is taken for
// it -- in particular before liveMu, which every admission waits on. One that
// names exactly that many fits an empty list.
func TestABanRequestNamesAtMost4096Places(t *testing.T) {
	t.Parallel()

	places := func(n int) string {
		ips := make([]string, n)
		for i := range ips {
			ips[i] = string(syntheticClientKey(i))
		}

		body, err := json.Marshal(banRequest{IPs: ips})
		require.NoError(t, err)

		return string(body)
	}

	probe, _ := banProbe(t, false)
	p := probe.proxy

	code, text := postBan(t, p, "alice", places(maxBans+1))
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, text, "4096", "the answer names the bound")
	assert.Zero(t, bansHeld(t, p))

	assert.Equal(t, maxBans, mustBan(t, p, "alice", places(maxBans)).Banned)
	assert.Equal(t, maxBans, bansHeld(t, p))
}

// With no ban held, asking whether a place is banned costs nothing: no address
// key is built, so a hello that matched a secret pays no allocation for the
// ban check, on either address family. With bans held the answers are as
// before. Not parallel: AllocsPerRun counts every allocation in the process.
func TestABanCheckWithNoBansHeldAllocatesNothing(t *testing.T) { //nolint: paralleltest // see above
	probe, _ := banProbe(t, false)
	p := probe.proxy

	v4, v6 := net.ParseIP("203.0.113.9"), net.ParseIP("2001:db8:1:2::5")

	allocs := testing.AllocsPerRun(100, func() {
		if p.bannedFrom("alice", v4) || p.bannedFrom("alice", v6) {
			panic("nothing is banned")
		}
	})
	assert.Zero(t, allocs)

	mustBan(t, p, "alice", `{"ips":["203.0.113.9","2001:db8:1:2::/64"]}`)

	assert.True(t, p.bannedFrom("alice", v4))
	assert.True(t, p.bannedFrom("alice", v6))
	assert.False(t, p.bannedFrom("bob", v4))
	assert.False(t, p.bannedFrom("alice", net.ParseIP("198.51.100.7")))
	assert.False(t, p.bannedFrom("alice", nil), "no address is no place")
}

// A ban is held at the unit kick counts and ends every live stream the
// secret has there: both sockets of an IPv4 address, a v4-mapped one among
// them, and the /64 of an IPv6 address named by another host in it. Another
// place, another /64 and another secret keep theirs.
func TestABanClosesTheAddressesLiveStreamsAtTheUnit(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy

	phone := admitFrom(t, probe, tcpFrom("203.0.113.9", 50001))
	mapped := admitFrom(t, probe, tcpFrom("::ffff:203.0.113.9", 50002))
	laptop := admitFrom(t, probe, tcpFrom("2001:db8:1:2:aaaa::1", 50003))
	other := admitFrom(t, probe, tcpFrom("198.51.100.7", 50004))
	nextNet := admitFrom(t, probe, tcpFrom("2001:db8:1:3::1", 50005))

	result := mustBan(t, p, "alice", `{"ips":["203.0.113.9","2001:db8:1:2:ffff::9"]}`)
	assert.Equal(t, BanResult{Banned: 2, Closed: 3}, result)

	for _, sc := range []*streamContext{phone, mapped, laptop} {
		assert.Error(t, sc.ctx.Err(), "a stream at a banned place is closed")
	}

	for _, sc := range []*streamContext{other, nextNet} {
		assert.NoError(t, sc.ctx.Err(), "a stream elsewhere is not")
	}

	assert.True(t, isBanned(p, "alice", "203.0.113.9"))
	assert.True(t, isBanned(p, "alice", "2001:db8:1:2::77"), "the whole /64")
	assert.False(t, isBanned(p, "alice", "198.51.100.7"))
	assert.False(t, isBanned(p, "alice", "2001:db8:1:3::1"))
	assert.False(t, isBanned(p, "bob", "203.0.113.9"), "a ban is of one secret")

	// What ServeConn's release does for the closed streams.
	for _, sc := range []*streamContext{phone, mapped, laptop} {
		p.unregisterConn(sc)
	}

	result = mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)
	assert.Equal(t, BanResult{Banned: 1, Closed: 0}, result, "banned again: nothing left to close")
	assert.Equal(t, 2, bansHeld(t, p), "and still one ban for the place")
}

// The answer says how many places were banned and how many streams were
// closed, and echoes the places only when the proxy lists addresses at all, as
// PUT external-ips does: in the unit they are held at, each once, sorted.
func TestABanEchoesTheAddressesOnlyWhenTracked(t *testing.T) {
	t.Parallel()

	const body = `{"ips":["203.0.113.9","2001:db8:1:2::5","2001:db8:1:2::6"]}`

	t.Run("tracking off", func(t *testing.T) {
		t.Parallel()

		probe, _ := banProbe(t, false)

		code, text := postBan(t, probe.proxy, "alice", body)
		require.Equal(t, http.StatusOK, code)
		assert.JSONEq(t, `{"banned":2,"closed":0}`, text)
		assert.NotContains(t, text, "203.0.113")
		assert.NotContains(t, text, "2001:db8")
	})

	t.Run("tracking on", func(t *testing.T) {
		t.Parallel()

		probe, _ := banProbe(t, true)

		code, text := postBan(t, probe.proxy, "alice", body)
		require.Equal(t, http.StatusOK, code)
		assert.JSONEq(t, `{"banned":2,"closed":0,"addresses":["2001:db8:1:2::/64","203.0.113.9"]}`, text)
	})
}

// GET /bans is gated as external_ips is: with track-client-ips the secret's
// bans are listed, by address, each with the moment it lapses; without it the
// answer is the count alone, and no address appears in it. Another secret's
// bans are its own.
func TestBansAreListedOnlyWhenTracked(t *testing.T) {
	t.Parallel()

	for tracking, want := range map[bool]string{
		false: `{"total":2,"tracking":false}`,
		true: `{"total":2,"tracking":true,"bans":[` +
			`{"address":"2001:db8:1:2::/64","expires_at":"2001-09-09T02:56:40Z"},` +
			`{"address":"203.0.113.9","expires_at":"2001-09-09T03:16:40Z"}]}`,
	} {
		probe, clock := banProbe(t, tracking)
		p := probe.proxy

		mustBan(t, p, "alice", `{"ips":["203.0.113.9"],"ttl":"90m"}`)
		clock.advance(10 * time.Minute)
		mustBan(t, p, "alice", `{"ips":["2001:db8:1:2::5"]}`)
		mustBan(t, p, "bob", `{"ips":["198.51.100.7"]}`)

		code, text := listBans(t, p, "alice")
		require.Equal(t, http.StatusOK, code)
		assert.JSONEq(t, want, text, "tracking %v", tracking)
		assert.NotContains(t, text, "198.51.100.7", "bob's ban is bob's")

		if !tracking {
			assert.NotContains(t, text, "203.0.113")
			assert.NotContains(t, text, "2001:db8")
		}
	}

	for tracking, want := range map[bool]string{
		false: `{"total":0,"tracking":false}`,
		true:  `{"total":0,"tracking":true,"bans":[]}`,
	} {
		probe, _ := banProbe(t, tracking)

		code, text := listBans(t, probe.proxy, "alice")
		require.Equal(t, http.StatusOK, code)
		assert.JSONEq(t, want, text, "no bans, tracking %v", tracking)
	}
}

// A ban lapses at its ttl on the list's own clock -- an hour when none is
// named -- and from that moment it is neither in force, nor listed, nor held.
func TestABanLapsesAtItsTTL(t *testing.T) {
	t.Parallel()

	probe, clock := banProbe(t, true)
	p := probe.proxy

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)
	mustBan(t, p, "alice", `{"ips":["198.51.100.7"],"ttl":"2h"}`)

	clock.advance(time.Hour - time.Second)
	assert.True(t, isBanned(p, "alice", "203.0.113.9"), "a second before its hour")
	assert.True(t, isBanned(p, "alice", "198.51.100.7"))

	clock.advance(time.Second)
	assert.False(t, isBanned(p, "alice", "203.0.113.9"), "the default ttl is an hour")
	assert.True(t, isBanned(p, "alice", "198.51.100.7"))

	_, text := listBans(t, p, "alice")
	assert.JSONEq(t,
		`{"total":1,"tracking":true,"bans":[{"address":"198.51.100.7","expires_at":"2001-09-09T03:46:40Z"}]}`, text)

	clock.advance(time.Hour)
	assert.False(t, isBanned(p, "alice", "198.51.100.7"))

	_, text = listBans(t, p, "alice")
	assert.JSONEq(t, `{"total":0,"tracking":true,"bans":[]}`, text)
	assert.Zero(t, bansHeld(t, p), "a lapsed ban is not held")

	// Without tracking the answer is a count, and a lapsed ban is not in it. The
	// list is asked first: a check of the place would prune the ban itself.
	untracked, untrackedClock := banProbe(t, false)

	mustBan(t, untracked.proxy, "alice", `{"ips":["203.0.113.9"]}`)

	_, text = listBans(t, untracked.proxy, "alice")
	assert.JSONEq(t, `{"total":1,"tracking":false}`, text)

	untrackedClock.advance(DefaultBanTTL)

	_, text = listBans(t, untracked.proxy, "alice")
	assert.JSONEq(t, `{"total":0,"tracking":false}`, text, "a lapsed ban is not counted")
}

// The list holds 4,096 bans across every secret and refuses the request that
// would take it past that with 409, whole: none of that request's places is
// banned. A place already held is not a new ban, two hosts of one /64 are one
// place, a lifted ban frees its slot and so does a lapsed one.
func TestTheBanListHoldsAtMost4096(t *testing.T) {
	t.Parallel()

	probe, clock := banProbe(t, false)
	p := probe.proxy

	keys := make([]addressKey, maxBans-1)
	for i := range keys {
		keys[i] = syntheticClientKey(i)
	}

	// Bob's part lapses in a minute, alice's in an hour.
	_, err := p.bans.add("bob", keys[:1000], time.Minute)
	require.NoError(t, err)
	_, err = p.bans.add("alice", keys[1000:], time.Hour)
	require.NoError(t, err)
	require.Equal(t, maxBans-1, bansHeld(t, p))

	mustBan(t, p, "alice", `{"ips":["203.0.113.1"]}`)
	require.Equal(t, maxBans, bansHeld(t, p), "the 4,096th fits")

	code, text := postBan(t, p, "alice", `{"ips":["203.0.113.2"]}`)
	assert.Equal(t, http.StatusConflict, code)
	assert.Contains(t, text, "ban list full")
	assert.False(t, isBanned(p, "alice", "203.0.113.2"))
	assert.Equal(t, maxBans, bansHeld(t, p))

	assert.Equal(t, 1, mustBan(t, p, "alice", `{"ips":["203.0.113.1"]}`).Banned,
		"a place already banned is banned again at the cap: it takes no new slot")

	code, _ = liftBan(t, p, "alice", "203.0.113.1")
	require.Equal(t, http.StatusOK, code)

	assert.Equal(t, 1, mustBan(t, p, "alice", `{"ips":["2001:db8::1","2001:db8::2"]}`).Banned,
		"two hosts of one /64 are one place, and one slot")
	assert.Equal(t, maxBans, bansHeld(t, p))

	code, _ = liftBan(t, p, "alice", "2001:db8::/64")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, maxBans-1, bansHeld(t, p))

	code, _ = postBan(t, p, "alice", `{"ips":["203.0.113.3","203.0.113.4"]}`)
	assert.Equal(t, http.StatusConflict, code, "one slot, two places")
	assert.False(t, isBanned(p, "alice", "203.0.113.3"), "refused whole")
	assert.False(t, isBanned(p, "alice", "203.0.113.4"))
	assert.Equal(t, maxBans-1, bansHeld(t, p))

	clock.advance(time.Minute)

	assert.Equal(t, 2, mustBan(t, p, "alice", `{"ips":["203.0.113.3","203.0.113.4"]}`).Banned,
		"bob's lapsed bans hold no slot")
	assert.Equal(t, maxBans-1000+1, bansHeld(t, p))
}

// A ban is lifted by the address it names or by the /64 form the listing
// shows, or by any other spelling of the same place -- another host of the
// /64, the v4-mapped form of an IPv4 address -- and lifting needs no force.
// It lifts the named secret's ban and no other secret's at the same place.
// Lifting a ban that is not there is not an error, as a kick of zero is not:
// it says it removed nothing. Anything else is 400, and an unknown secret 404.
func TestABanIsLiftedByAddressOrByPrefix(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, true)
	p := probe.proxy

	lift := func(address string) string {
		t.Helper()

		code, text := liftBan(t, p, "alice", address)
		require.Equal(t, http.StatusOK, code, "%s: %s", address, text)

		return text
	}

	mustBan(t, p, "alice", `{"ips":["203.0.113.9","2001:db8:1:2::5"]}`)

	assert.JSONEq(t, `{"removed":1}`, lift("203.0.113.9"))
	assert.False(t, isBanned(p, "alice", "203.0.113.9"))
	assert.JSONEq(t, `{"removed":0}`, lift("203.0.113.9"), "lifted already")

	assert.JSONEq(t, `{"removed":1}`, lift("2001:db8:1:2::/64"), "the listing's spelling")
	assert.False(t, isBanned(p, "alice", "2001:db8:1:2::5"))

	mustBan(t, p, "alice", `{"ips":["2001:db8:1:2::5"]}`)
	assert.JSONEq(t, `{"removed":1}`, lift("2001:db8:1:2:aaaa::1"), "another host of the /64")

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)
	assert.JSONEq(t, `{"removed":1}`, lift("::ffff:203.0.113.9"), "the v4-mapped spelling")

	mustBan(t, p, "alice", `{"ips":["127.0.0.1"],"force":true}`)
	assert.JSONEq(t, `{"removed":1}`, lift("127.0.0.1"), "lifting needs no force")

	assert.Zero(t, bansHeld(t, p))

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)
	mustBan(t, p, "bob", `{"ips":["203.0.113.9"]}`)
	assert.JSONEq(t, `{"removed":1}`, lift("203.0.113.9"))
	assert.False(t, isBanned(p, "alice", "203.0.113.9"))
	assert.True(t, isBanned(p, "bob", "203.0.113.9"), "lifting alice's ban leaves bob's at the same place")

	code, _ := liftBan(t, p, "bob", "203.0.113.9")
	require.Equal(t, http.StatusOK, code)
	assert.Zero(t, bansHeld(t, p))

	for _, bad := range []string{"not-an-ip", "203.0.113.0/24", "2001:db8::/48"} {
		code, _ := liftBan(t, p, "alice", bad)
		assert.Equal(t, http.StatusBadRequest, code, bad)
	}

	code, _ = liftBan(t, p, "nobody", "203.0.113.9")
	assert.Equal(t, http.StatusNotFound, code)
}

// Bans live as long as their secret, in memory: a reload keeps them, and so
// does a re-key, which is the same user under a new key; removing the secret
// drops them, and a secret of that name added back starts with none.
func TestBansFollowTheirSecret(t *testing.T) {
	t.Parallel()

	alice, bob := GenerateSecret("alice.example.com"), GenerateSecret("bob.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice, "bob": bob})

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)
	mustBan(t, p, "bob", `{"ips":["198.51.100.7"]}`)

	require.NoError(t, p.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": alice, "bob": bob},
		Limits:  map[string]SecretLimits{"alice": {IPLimit: 3}},
	}))
	assert.True(t, isBanned(p, "alice", "203.0.113.9"), "a reload keeps them")
	assert.True(t, isBanned(p, "bob", "198.51.100.7"))

	require.NoError(t, p.PutSecret("alice", GenerateSecret("alice.example.com"), nil, nil))
	assert.True(t, isBanned(p, "alice", "203.0.113.9"), "a re-key keeps them")

	require.NoError(t, p.DeleteSecret("bob"))
	assert.False(t, isBanned(p, "bob", "198.51.100.7"), "a removal drops them")
	assert.Equal(t, 1, bansHeld(t, p), "and gives their slots back")

	require.NoError(t, p.PutSecret("bob", bob, nil, nil))
	assert.False(t, isBanned(p, "bob", "198.51.100.7"), "a secret added back starts with none")

	_, text := listBans(t, p, "bob")
	assert.JSONEq(t, `{"total":0,"tracking":false}`, text)
}

// A ban forgets the banned secret's hints at the banned places, in both
// generations and at the unit the hints are kept at, so a banned address is
// never verified against the secret first. The hints the place earned for
// other secrets are its own and stay, and so do the secret's hints elsewhere.
func TestABanForgetsTheSecretsHintsAtThosePlaces(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy
	p.hints = newMatchHints(t.Context())

	at := func(ip string) []string { return p.hints.recall(net.ParseIP(ip)) }

	p.hints.remember(net.ParseIP("203.0.113.9"), "bob")
	p.hints.remember(net.ParseIP("203.0.113.9"), "alice")
	p.hints.remember(net.ParseIP("2001:db8:1:2::1"), "alice")
	p.hints.remember(net.ParseIP("198.51.100.7"), "alice")
	p.hints.remember(net.ParseIP("203.0.113.10"), "alice")
	p.hints.rotate()
	p.hints.remember(net.ParseIP("198.51.100.7"), "bob")

	mustBan(t, p, "alice", `{"ips":["203.0.113.9","2001:db8:1:2::/64","203.0.113.10"]}`)

	assert.Equal(t, []string{"bob"}, at("203.0.113.9"), "the place's hint for bob is its own")
	assert.Nil(t, at("2001:db8:1:2:ffff::1"), "the /64 had alice's alone")
	assert.Nil(t, at("203.0.113.10"), "the older generation too")
	assert.Equal(t, []string{"bob", "alice"}, at("198.51.100.7"), "alice's hints elsewhere stay")
}

// boundedClientsRows is the /clients rows of alice by address, read on a
// goroutine of its own so that a handler that deadlocks fails here.
func boundedClientsRows(t *testing.T, p *Proxy) map[string]map[string]any {
	t.Helper()

	var (
		code int
		body []byte
		done = make(chan struct{})
	)

	go func() {
		defer close(done)

		code, body = clientsBody(t, p, "/secrets/alice/clients")
	}()

	require.True(t, govAwait(done, 10*time.Second), "GET /clients must answer, not deadlock")
	require.Equal(t, http.StatusOK, code, string(body))

	return rawRowsByAddress(t, statsRaw(t, body))
}

// A /clients row carries banned_until while its place is banned from the
// secret: the moment it lapses, in UTC. A place with no ban, or with a ban of
// another secret's, has none, and a lapsed ban leaves none.
func TestClientsRowsCarryBannedUntil(t *testing.T) {
	t.Parallel()

	probe, clock := banProbe(t, true)
	p := probe.proxy

	admitFrom(t, probe, tcpFrom("203.0.113.9", 50001))
	admitFrom(t, probe, tcpFrom("198.51.100.7", 50002))
	admitFrom(t, probe, tcpFrom("2001:db8:1:2::1", 50003))

	mustBan(t, p, "alice", `{"ips":["203.0.113.9","2001:db8:1:2::/64"],"ttl":"90m"}`)
	mustBan(t, p, "bob", `{"ips":["198.51.100.7"]}`)

	until := fakeAddrClockBase.Add(90 * time.Minute).UTC().Format(time.RFC3339)
	rows := boundedClientsRows(t, p)

	require.Len(t, rows, 3)
	assert.Equal(t, until, rows["203.0.113.9"]["banned_until"])
	assert.Equal(t, until, rows["2001:db8:1:2::/64"]["banned_until"])
	assert.NotContains(t, rows["198.51.100.7"], "banned_until", "bob's ban is not alice's")

	clock.advance(90 * time.Minute)

	for address, row := range boundedClientsRows(t, p) {
		assert.NotContains(t, row, "banned_until", "%s: a lapsed ban leaves none", address)
	}
}

// The ban is recorded in the critical section admission registers a stream
// in: while liveMu is held -- by an admission, here by the test -- a ban that
// was asked for is not yet in force, and it is once the lock is let go.
func TestABanIsRecordedUnderLiveMu(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy

	p.liveMu.Lock()

	done := make(chan struct{})

	go func() {
		defer close(done)

		_, err := p.Ban("alice", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, time.Hour)
		assert.NoError(t, err)
	}()

	assert.Never(t, func() bool { return isBanned(p, "alice", "203.0.113.9") }, 200*time.Millisecond, 5*time.Millisecond,
		"nothing is recorded while liveMu is held elsewhere")

	p.liveMu.Unlock()

	require.True(t, govAwait(done, 5*time.Second))
	assert.True(t, isBanned(p, "alice", "203.0.113.9"))
}

// The same, from inside: the ban is set -- its lapse worked out from the list's
// clock and written -- while the ban itself holds liveMu, the hold it finds the
// streams to close in. Set before that hold, or after it is let go, a stream
// could register between the two unseen by either; the test above sees the
// first and not the second. The clock is read nowhere else in a ban.
func TestABanIsSetWhileItHoldsLiveMu(t *testing.T) {
	t.Parallel()

	probe, clock := banProbe(t, false)
	p := probe.proxy

	var reads, unheld atomic.Int32

	p.bans.now = func() time.Time {
		reads.Add(1)

		if p.liveMu.TryLock() {
			unheld.Add(1)
			p.liveMu.Unlock()
		}

		return clock.read()
	}

	_, err := p.Ban("alice", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, time.Hour)
	require.NoError(t, err)

	require.Positive(t, reads.Load(), "the ban was set by the list's clock")
	assert.Zero(t, unheld.Load(), "with liveMu held")

	p.bans.now = clock.read

	assert.True(t, isBanned(p, "alice", "203.0.113.9"))
}

// closeObserverConn is a client socket that runs onClose when it is closed.
type closeObserverConn struct {
	essentials.Conn

	onClose func()
}

func (c closeObserverConn) Close() error {
	c.onClose()

	return c.Conn.Close() //nolint: wrapcheck
}

// The streams a ban ends are closed after liveMu is let go, as Kick closes
// them: a stream's close is a socket's, and every admission and every stream's
// end waits on that lock. By the time the first of them is closed the ban is
// already in force.
func TestABanClosesStreamsAfterLettingGoOfLiveMu(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy

	var (
		closes        atomic.Int32
		liveFree      atomic.Bool
		bannedAtClose atomic.Bool
	)

	sc := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)
	sc.clientSocket = closeObserverConn{Conn: sc.clientSocket, onClose: func() {
		closes.Add(1)

		if p.liveMu.TryLock() {
			liveFree.Store(true)
			p.liveMu.Unlock()
		}

		bannedAtClose.Store(isBanned(p, "alice", "203.0.113.9"))
	}}

	require.Equal(t, DenyNone, p.tryRegisterConn(sc))

	assert.Equal(t, 1, mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`).Closed)
	require.EqualValues(t, 1, closes.Load(), "the stream's socket was closed")
	assert.True(t, liveFree.Load(), "liveMu was let go before the close")
	assert.True(t, bannedAtClose.Load(), "and the ban was in force by then")
}

// A stream that gets through admission while a ban waits for liveMu is
// registered by the time the ban takes the lock, and the ban's kick finds it:
// whichever comes first, the stream does not outlive the ban. The ban is asked
// for from inside tryRegisterConn's critical section, after every check has
// passed, so the order is fixed and not a race.
func TestAStreamRegisteredWhileABanWaitsIsClosedByIt(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe, _ := banProbe(t, false)
	p := probe.proxy

	results := make(chan BanResult, 1)

	installRegisterStepHook(t, func(step registerStep, _ *streamContext) DenyReason {
		if step == stepEntryAcquired {
			go func() {
				result, err := p.Ban("alice", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, time.Hour)
				assert.NoError(t, err)

				results <- result
			}()
		}

		return DenyNone
	})

	sc := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)
	require.Equal(t, DenyNone, p.tryRegisterConn(sc), "every check passed before the ban was asked for")

	select {
	case result := <-results:
		assert.Equal(t, 1, result.Closed, "the ban's kick finds the stream")
	case <-time.After(5 * time.Second):
		t.Fatal("the ban never finished")
	}

	assert.Error(t, sc.ctx.Err(), "and closes it")
}

// The bans routes are behind the bearer token like every route.
func TestBansAreBehindTheBearerToken(t *testing.T) {
	t.Parallel()

	p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

	for _, route := range []struct{ method, target, body string }{
		{http.MethodPost, "/secrets/alice/bans", `{"ips":["203.0.113.9"]}`},
		{http.MethodGet, "/secrets/alice/bans", ""},
		{http.MethodDelete, "/secrets/alice/bans/203.0.113.9", ""},
	} {
		rec := httptest.NewRecorder()
		p.buildAPIHandler("s3cret").ServeHTTP(rec,
			httptest.NewRequest(route.method, route.target, strings.NewReader(route.body)))

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s without the token", route.method, route.target)
		assert.Equal(t, http.StatusOK, doAPI(t, p, "s3cret", route.method, route.target, route.body).Code,
			"%s %s with it", route.method, route.target)
	}
}

// A banned place is turned away at every door the way a wrong secret is, before
// anything is counted: fronted on the FakeTLS door before the server's flight,
// disposed of silently on the obfuscated ones. Every spelling of the place is
// the place -- the v4-mapped form, another host of a banned /64 -- and the
// refusal is no limit being felt: neither the address limit's counter nor the
// connection cap's moves. Another place gets in, and so does the banned one
// once its ban is lifted or has lapsed.
func TestABannedPlaceIsTurnedAwayAtEveryDoor(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			clock := newFakeAddrClock()
			h.proxy.bans.now = clock.read

			mustBan(t, h.proxy, "alice", `{"ips":["203.0.113.9"],"ttl":"2h"}`)
			mustBan(t, h.proxy, "alice", `{"ips":["2001:db8:1:2::/64"]}`)

			port := 50000

			for _, from := range []string{"203.0.113.9", "::ffff:203.0.113.9", "2001:db8:1:2:aaaa::1"} {
				port++
				refuseFrom(t, ec, h, secret.Key, tcpFrom(from, port))
			}

			user := h.proxy.stats.users["alice"]

			assert.Zero(t, user.connections.Load(), "a banned place was never counted")
			assert.Zero(t, user.ipLimitRefused.Load(), "a ban is not the address limit")
			assert.Zero(t, user.clientConnsRefused.Load(), "nor the connection cap")
			assert.Equal(t, 3*ec.frontingsOnEntryDeny, h.events.frontings(), "turned away as a wrong secret is")
			assert.Zero(t, h.network.telegramDials())

			connectFrom(t, h, ec, tcpFrom("198.51.100.7", 50101), "alice", secret.Key)

			code, _ := liftBan(t, h.proxy, "alice", "203.0.113.9")
			require.Equal(t, http.StatusOK, code)

			connectFrom(t, h, ec, tcpFrom("203.0.113.9", 50102), "alice", secret.Key)

			refuseFrom(t, ec, h, secret.Key, tcpFrom("2001:db8:1:2::5", 50103))
			clock.advance(DefaultBanTTL)
			connectFrom(t, h, ec, tcpFrom("2001:db8:1:2::5", 50104), "alice", secret.Key)
		})
	}
}

// A forced ban of an address that does not stand for one place holds at the
// doors like any other: a loopback client -- behind a carrier that forwards no
// address, every client -- is turned away at attribution as a wrong secret is,
// not let through to be closed after the server's flight.
func TestAForcedBanOfAnUnkeyedAddressHoldsAtTheDoors(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			mustBan(t, h.proxy, "alice", `{"ips":["127.0.0.1"],"force":true}`)

			client, done := h.dialProxy(t, ec.policy)
			ec.openEntry(t, client, secret.Key)

			require.True(t, govAwait(done, govDenyBudget), "refused, not relayed")
			assert.Equal(t, ec.frontingsOnEntryDeny, h.events.frontings(), "turned away as a wrong secret is")
			assert.Zero(t, h.network.telegramDials())
			assert.Zero(t, h.proxy.stats.users["alice"].connections.Load())
		})
	}
}

// frontFrom sends wire to the FakeTLS door from addr, ends the client's side,
// and returns everything the cover site received for it and everything the
// client heard back before the proxy hung up.
func (c *coverSite) frontFrom(t *testing.T, h *entryHarness, addr net.Addr, wire []byte) ([]byte, []byte) {
	t.Helper()

	client, done := dialProxyFrom(t, h, nil, addr)

	_, err := client.Write(wire)
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	var received []byte

	select {
	case received = <-c.got:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the cover site received nothing: the hello was not fronted")
	}

	require.True(t, govAwait(done, govDenyBudget))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	reply, err := io.ReadAll(client)
	require.NoError(t, err)

	return received, reply
}

// No oracle: a hello from a banned place reaches the cover site exactly as a
// hello that matches no secret does. The very same bytes are sent twice from
// the banned place: first while they are alice's hello, which the ban turns
// away after the match, then after alice is re-keyed, when they match nothing
// (the ban, kept, is no longer what fronts them). The cover site gets the
// client's own bytes both times, byte for byte the same, and the client hears
// nothing from the proxy either time: no server hello is sent to a banned place.
func TestABannedHelloReachesTheCoverSiteAsAWrongSecretDoes(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.9"

	ec := fakeTLSDoor()
	h := ec.harness(t, map[string]Secret{"alice": ec.secret(t)}, nil)
	cover := newCoverSite(t, h)

	alice := h.proxy.secrets.Load().secrets[0]
	hello := ec.clientHello(t, alice.Key, bytes.Repeat([]byte{0x3c}, 32))

	// The control, with a hello of its own: alice gets in from another place.
	connectFrom(t, h, ec, tcpFrom("198.51.100.7", 51001), "alice", alice.Key)

	mustBan(t, h.proxy, "alice", `{"ips":["`+place+`"]}`)

	before := tallyOf(h.proxy)
	banned, bannedReply := cover.frontFrom(t, h, tcpFrom(place, 51002), hello)

	assert.Equal(t, doorTally{verifications: 1, scanned: 1}, tallyOf(h.proxy).minus(before),
		"the hello matched alice: it is the ban that turned it away")

	reloadSecrets(t, h.proxy, map[string]Secret{"alice": ec.secret(t)})
	require.True(t, isBanned(h.proxy, "alice", place), "the re-key kept the ban")

	before = tallyOf(h.proxy)
	wrong, wrongReply := cover.frontFrom(t, h, tcpFrom(place, 51003), hello)

	assert.Equal(t, doorTally{verifications: 1, unmatched: 1}, tallyOf(h.proxy).minus(before),
		"the same bytes now match no secret")

	assert.Equal(t, hello, banned, "the cover site gets the client's own bytes")
	assert.Equal(t, wrong, banned, "byte for byte what a hello for no secret gives it")
	assert.Empty(t, bannedReply, "the banned client hears nothing from the proxy")
	assert.Empty(t, wrongReply)
	assert.Equal(t, 2, h.events.frontings())
}

// The re-check: a stream attributed before the ban was recorded -- it passed
// the ban check at attribution -- is refused when it comes to register, under
// liveMu, before the cap and the limit, and leaves the ledger, the registry and
// the counters as they were. The refusal is logged as a ban and counted
// nowhere. A stream attributed after the ban is refused at attribution, and
// says why.
func TestTheReCheckRefusesAStreamThatPassedAttribution(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy
	user := p.stats.users["alice"]

	set := p.secrets.Load()
	alice := slices.Index(set.names, "alice")

	early := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(early, set, alice), "not banned yet")

	assert.Equal(t, 0, mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`).Closed,
		"the stream is not registered: there is nothing to close")

	require.False(t, p.admit(early))

	assert.Equal(t, []string{"banned"}, probe.log.denyReasons())
	assert.Nil(t, probe.ledgerCounts(), "the ledger is as it was")
	assert.Zero(t, probe.registered())
	assert.False(t, early.addrCounted)
	assert.Zero(t, user.connections.Load())
	assert.Zero(t, user.ipLimitRefused.Load())
	assert.Zero(t, user.clientConnsRefused.Load())
	assert.Zero(t, probe.events.count(func(Event) bool { return true }), "a ban has no event")

	late := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
	assert.Equal(t, DenyBanned, p.attribute(late, set, alice))
	assert.Equal(t, []string{"banned", "banned"}, probe.log.denyReasons())
}

// The ban re-check precedes the limits of registration (spec §2): a banned
// place is refused as banned, whatever the steps after it would have said --
// the connection cap with the place at its cap, the address limit with the user
// at hers -- and a forced ban of an unkeyed address holds there too. Only the
// key re-check comes before it: see
// TestARevokedKeyFromABannedPlaceIsRefusedAsKeyRevoked.
func TestTheBanReCheckPrecedesTheLimits(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy

	// Three places held: a cap of one on the first, a limit of three on the user.
	require.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, tcpFrom("203.0.113.9", 50001), 1)))
	require.Equal(t, DenyNone, p.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.7", 50002), 3)))
	require.Equal(t, DenyNone, p.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.8", 50003), 3)))

	require.Equal(t, DenyClientConns, p.tryRegisterConn(capStream(t, probe, tcpFrom("203.0.113.9", 50004), 1)),
		"the control: the place is at its cap")
	require.Equal(t, DenyIPLimit, p.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.9", 50005), 3)),
		"the control: the user is at her limit")

	mustBan(t, p, "alice", `{"ips":["203.0.113.9","198.51.100.9"]}`)
	mustBan(t, p, "alice", `{"ips":["127.0.0.1"],"force":true}`)

	before := probe.ledgerCounts()

	assert.Equal(t, DenyBanned, p.tryRegisterConn(capStream(t, probe, tcpFrom("203.0.113.9", 50006), 1)))
	assert.Equal(t, DenyBanned, p.tryRegisterConn(probe.stream(t, tcpFrom("198.51.100.9", 50007), 3)))
	assert.Equal(t, DenyBanned, p.tryRegisterConn(probe.stream(t, tcpFrom("127.0.0.1", 50008), 0)),
		"a forced ban of an unkeyed address")
	assert.Equal(t, before, probe.ledgerCounts(), "none of the refusals touched the ledger")
}

// obfsTokens is what the obfuscated door's failure limiter holds for ip's
// place, read under its lock and without a refill, and false when it holds no
// bucket for the place.
func obfsTokens(t *testing.T, l *obfuscatedLimiter, ip string) (float64, bool) {
	t.Helper()

	key, ok := limiterKey(net.ParseIP(ip))
	require.True(t, ok)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.current[key]
	if !ok {
		bucket, ok = l.previous[key]
	}

	if !ok {
		return 0, false
	}

	return bucket.tokens, true
}

// On the obfuscated door a banned client is charged to the per-address failure
// limiter as a frame that matched nothing is, so one that keeps reconnecting is
// soon refused before the trial loop instead of costing a trial decryption
// every time. It is not counted as a miss: its frame did match. A place that is
// not banned is charged nothing for getting in.
//
// The charge is read off the bucket, exactly, rather than through Allow, so no
// wall time enters the test: Allow makes no bucket, Fail makes one full and
// spends a token from it at the same instant, and nothing refills it until the
// next Allow or Fail for the place.
func TestABannedObfuscatedClientIsChargedLikeAMiss(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.9"

	ec := govEntryCases()[1]
	ec.policy = &ListenerPolicy{
		Modes:           ModeSetOf(SecretModeDD),
		Public:          true,
		HandshakesPerIP: 1,
		OnUnknownSecret: UnknownSecretClose,
	}

	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)
	limiter, stats := h.proxy.obfsLimiter, &h.proxy.obfsStats

	connectFrom(t, h, ec, tcpFrom("198.51.100.7", 52001), "alice", secret.Key)

	_, charged := obfsTokens(t, limiter, "198.51.100.7")
	assert.False(t, charged, "getting in costs nothing: the limiter holds no bucket for the place")

	mustBan(t, h.proxy, "alice", `{"ips":["`+place+`"]}`)

	_, charged = obfsTokens(t, limiter, place)
	require.False(t, charged)

	refuseFrom(t, ec, h, secret.Key, tcpFrom(place, 52002))

	tokens, charged := obfsTokens(t, limiter, place)
	require.True(t, charged, "the banned attempt was charged")
	assert.InDelta(t, float64(ec.policy.HandshakesPerIP)*handshakeBurstFactor-1, tokens, 0,
		"one token, out of a full bucket")
	assert.Zero(t, stats.misses.Load(), "a banned frame matched; it is not a miss")
	assert.EqualValues(t, 2, stats.trials.Load())
	assert.EqualValues(t, 1, stats.denied.Load())
}

// A banned place gets no hinted verification. The ban forgets the hint, so the
// banned hello is scanned, and a scan keeps its charge to the handshake budget;
// the banned hello writes no hint of its own. And a hint the ban could not
// forget -- one written by a stream admitted a moment before the ban, after it
// -- is skipped all the same: a banned place is never verified against the
// secret it is banned from on the strength of a hint. The skip is of that
// secret at that place and nothing wider: the place's hint for another secret,
// and the secret's hint at another place, are tried first as before.
func TestABannedPlaceIsScannedNotHinted(t *testing.T) {
	t.Parallel()

	const (
		place = "203.0.113.30"
		other = "203.0.113.31"
		cost  = 2 * 12 // two candidates, the short hello
	)

	ec := fakeTLSDoor()
	alice, bob := ec.secret(t), ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	recall := func() []string { return h.proxy.hints.recall(net.ParseIP(place)) }

	connectFrom(t, h, ec, tcpFrom(place, 53001), "alice", alice.Key)
	require.Equal(t, []string{"alice"}, recall())
	require.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 53002), "alice", alice.Key), "the control: the place is hinted")

	mustBan(t, h.proxy, "alice", `{"ips":["`+place+`"]}`)
	require.Nil(t, recall())

	global0, address0 := budgetLevels(t, h, place)

	assert.Equal(t, doorTally{verifications: 1, scanned: 1}, refusedFrom(t, h, tcpFrom(place, 53003), alice.Key),
		"scanned, and matched: alice is the first candidate")
	assert.Nil(t, recall(), "a banned hello writes no hint")

	global1, address1 := budgetLevels(t, h, place)
	assert.InDelta(t, global0-cost, global1, 1e-9, "the scan keeps its charge")
	assert.InDelta(t, address0-cost, address1, 1e-9)

	h.proxy.hints.remember(net.ParseIP(place), "alice")

	assert.Equal(t, doorTally{verifications: 1, scanned: 1}, refusedFrom(t, h, tcpFrom(place, 53004), alice.Key),
		"a hint written after the ban is not tried")
	assert.Equal(t, 2, h.events.frontings())

	connectFrom(t, h, ec, tcpFrom(place, 53005), "bob", bob.Key)
	require.Equal(t, []string{"bob", "alice"}, recall())
	assert.Equal(t, doorTally{verifications: 1, hinted: 1}, connectFrom(t, h, ec, tcpFrom(place, 53006), "bob", bob.Key),
		"bob's hint at the banned place is tried first, alice's beside it is not")

	connectFrom(t, h, ec, tcpFrom(other, 53007), "alice", alice.Key)
	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(other, 53008), "alice", alice.Key), "alice's hint at another place")
}
