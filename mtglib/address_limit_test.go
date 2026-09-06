package mtglib

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit an address limit counts. IPv4 is the address; IPv6 is its /64,
// because hosts rotate the low bits and one phone must not count as many
// devices; a v4-mapped v6 address is the v4 address it wraps.
func TestAddressKeyNormalisation(t *testing.T) {
	t.Parallel()

	key := func(text string) addressKey {
		t.Helper()

		k, ok := addressKeyOf(net.ParseIP(text))
		require.True(t, ok, text)

		return k
	}

	assert.Equal(t, addressKey("198.51.100.7"), key("198.51.100.7"))
	assert.Equal(t, key("198.51.100.7"), key("::ffff:198.51.100.7"),
		"a v4-mapped address is the v4 address")
	assert.NotEqual(t, key("198.51.100.7"), key("198.51.100.8"))

	assert.Equal(t, addressKey("2001:db8:1:2::/64"), key("2001:db8:1:2::1"))
	assert.Equal(t, key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff:ffff:ffff:ffff"),
		"two addresses in one /64 are one place")
	assert.NotEqual(t, key("2001:db8:1:2::1"), key("2001:db8:1:3::1"),
		"two /64s are two places")

	_, ok := addressKeyOf(nil)
	assert.False(t, ok, "no address is not a key")

	_, ok = addressKeyOf(net.IP{})
	assert.False(t, ok)
}

// The ledger's arithmetic, with the clock injected so expiry is exact.
func TestAddressLedger(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	a, b, c := addressKey("198.51.100.1"), addressKey("198.51.100.2"), addressKey("198.51.100.3")

	t.Run("a place counts once however many connections it holds", func(t *testing.T) {
		t.Parallel()

		l := newAddressLedger()

		require.True(t, l.admit(a, 1, now))
		require.True(t, l.admit(a, 1, now), "a second socket from the same place is the same device")
		require.False(t, l.admit(b, 1, now), "a second place is one too many")
		assert.Equal(t, 1, l.counted(now))

		l.release(a)
		require.False(t, l.admit(b, 1, now), "one connection from a is still a")

		l.release(a)
		require.True(t, l.admit(b, 1, now), "with a gone, the slot is free")
		assert.False(t, l.idle(now))

		l.release(b)
		assert.True(t, l.idle(now))
	})

	t.Run("reported addresses count until they expire", func(t *testing.T) {
		t.Parallel()

		l := newAddressLedger()
		l.setExternal([]netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")},
			now.Add(time.Minute))

		assert.Equal(t, 2, l.counted(now))
		require.False(t, l.admit(c, 2, now), "two places elsewhere fill a limit of two")
		require.True(t, l.admit(a, 2, now), "a place already reported is not a new one")
		assert.Equal(t, 2, l.counted(now), "a is one place, reported and live")

		later := now.Add(2 * time.Minute)
		assert.Equal(t, 1, l.counted(later), "expired reports stop counting; a is still live")
		require.True(t, l.admit(c, 2, later))

		external, expires := l.externalAddresses(later)
		assert.Nil(t, external)
		assert.True(t, expires.IsZero())
	})

	t.Run("a report replaces the previous one whole", func(t *testing.T) {
		t.Parallel()

		l := newAddressLedger()
		l.setExternal([]netip.Addr{netip.MustParseAddr("198.51.100.1")}, now.Add(time.Minute))
		l.setExternal([]netip.Addr{netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("2001:db8::1")},
			now.Add(2*time.Minute))

		external, expires := l.externalAddresses(now)
		assert.Equal(t, []string{"198.51.100.2", "2001:db8::1"}, external, "sorted, as reported")
		assert.Equal(t, now.Add(2*time.Minute), expires)
		assert.Equal(t, 2, l.counted(now))

		l.setExternal(nil, now)
		assert.True(t, l.idle(now))
	})

	t.Run("no limit still counts, so a limit set later starts from the truth", func(t *testing.T) {
		t.Parallel()

		l := newAddressLedger()

		require.True(t, l.admit(a, 0, now))
		require.True(t, l.admit(b, 0, now))
		assert.Equal(t, 2, l.counted(now))
		require.False(t, l.admit(c, 2, now))
	})
}

// A report is validated as the API receives it.
func TestParseExternalAddresses(t *testing.T) {
	t.Parallel()

	addrs, ttl, err := ParseExternalAddresses([]string{"198.51.100.7", "2001:db8::1"}, "")
	require.NoError(t, err)
	assert.Len(t, addrs, 2)
	assert.Equal(t, DefaultExternalAddressTTL, ttl, "no ttl is the default ttl")

	_, ttl, err = ParseExternalAddresses(nil, "90s")
	require.NoError(t, err)
	assert.Equal(t, 90*time.Second, ttl)

	for name, in := range map[string]struct {
		ips []string
		ttl string
	}{
		"not an address":     {[]string{"example.com"}, ""},
		"a prefix":           {[]string{"198.51.100.0/24"}, ""},
		"a zone":             {[]string{"fe80::1%eth0"}, ""},
		"ttl of zero":        {nil, "0s"},
		"negative ttl":       {nil, "-1s"},
		"ttl too long":       {nil, "2h"},
		"ttl not a duration": {nil, "soon"},
		"too many": {func() []string {
			out := make([]string, MaxExternalAddresses+1)
			for i := range out {
				out[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}).String()
			}

			return out
		}(), ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := ParseExternalAddresses(in.ips, in.ttl)
			require.ErrorIs(t, err, ErrExternalAddresses)
		})
	}
}

// tcpFrom is a client address for dialProxyFrom, one distinct port per call
// so two connections from one place are two sockets.
func tcpFrom(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// refuseFrom opens this door from addr and requires that the proxy refuses the
// connection rather than relaying it. The bound is what tells the two apart:
// a relayed stream never returns by itself.
func refuseFrom(t *testing.T, ec govEntryCase, h *entryHarness, key [SecretKeyLength]byte, addr net.Addr) {
	t.Helper()

	client, done := dialProxyFrom(t, h, ec.policy, addr)
	ec.openEntry(t, client, key)

	require.True(t, govAwait(done, govDenyBudget),
		"a connection from one address too many must be refused, not relayed")
}

// The limit holds on every door: a user at their limit is refused from a new
// address, admitted again from one they already hold, and gets the slot back
// the moment the old place lets go of it.
func TestIPLimitAcrossEntries(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret},
				map[string]SecretLimits{"alice": {IPLimit: 1}})

			// Two sockets from one place: the phone's second connection.
			first, firstDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.7", 50001))
			firstUp := connectThrough(t, ec, h, first, "alice", secret.Key)

			second, secondDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.7", 50002))
			secondUp := connectThrough(t, ec, h, second, "alice", secret.Key)

			// A second place.
			refuseFrom(t, ec, h, secret.Key, tcpFrom("203.0.113.9", 50003))

			// The refusal is counted, named, and leaves the connection count
			// where it found it: a refused connection was never admitted.
			stats := statsFor(t, h.proxy)
			assert.Equal(t, 1, stats.Users["alice"].IPLimit)
			assert.Equal(t, 1, stats.Users["alice"].ActiveIPs, "one place, two sockets")
			assert.EqualValues(t, 1, stats.Users["alice"].IPLimitRefused)
			assert.EqualValues(t, 2, stats.Users["alice"].Connections,
				"a refusal must not move the connection count")
			assert.Equal(t, 1, h.events.count(func(evt Event) bool {
				limited, ok := evt.(EventIPLimited)

				return ok && limited.SecretName == "alice"
			}), "the refusal must name the matched secret")

			// The count is never gated on tracking; the addresses are.
			assert.Nil(t, stats.Users["alice"].ConnectedIPs)

			// Releasing one socket releases nothing: the place still holds one.
			endStream(first, firstUp, firstDone)
			refuseFrom(t, ec, h, secret.Key, tcpFrom("203.0.113.9", 50004))

			// Releasing the last one frees the slot at once.
			endStream(second, secondUp, secondDone)

			third, thirdDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50005))
			thirdUp := connectThrough(t, ec, h, third, "alice", secret.Key)
			defer endStream(third, thirdUp, thirdDone)

			stats = statsFor(t, h.proxy)
			assert.Equal(t, 1, stats.Users["alice"].ActiveIPs)
			assert.EqualValues(t, 2, stats.Users["alice"].IPLimitRefused)
		})
	}
}

// The check and the registration are one critical section. Eight new places
// arriving together against a limit of one must produce exactly one admitted
// stream, and a count-then-register would let several through.
func TestIPLimitAdmitsExactlyOneUnderContention(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	ec := govEntryCases()[1] // dd: no server flight to sequence, so the arrivals really are concurrent
	h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": {IPLimit: 1}})

	const arrivals = 8

	var (
		wg    sync.WaitGroup
		dones = make([]<-chan struct{}, arrivals)
		start = make(chan struct{})
	)

	for i := range arrivals {
		client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113."+string(rune('1'+i)), 51000+i))
		dones[i] = done

		wg.Go(func() {
			<-start
			ec.openEntry(t, client, secret.Key)
		})
	}

	close(start)
	wg.Wait()

	// Every refusal returns promptly; the one admitted stream does not return
	// at all, because it is relaying. Count the returns within the budget.
	refused := 0

	deadline := time.After(govDenyBudget)

	for _, done := range dones {
		select {
		case <-done:
			refused++
		case <-deadline:
		}
	}

	require.Equal(t, arrivals-1, refused, "all but one arrival must be refused")

	h.proxy.liveMu.Lock()
	live := len(h.proxy.liveConns["alice"])
	h.proxy.liveMu.Unlock()

	assert.Equal(t, 1, live, "exactly one stream may hold the single slot")
	assert.EqualValues(t, arrivals-1, h.proxy.stats.users["alice"].ipLimitRefused.Load())
}

// Addresses a panel reports from elsewhere fill the user's slots here, so a
// user on their VPN from two places is refused a third through this proxy,
// and admitted from one of the two; and when the report lapses, so does its
// claim.
func TestIPLimitCountsReportedAddresses(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	ec := govEntryCases()[1]
	h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": {IPLimit: 2}})

	const reportTTL = 400 * time.Millisecond

	require.NoError(t, h.proxy.SetExternalAddresses("alice",
		[]netip.Addr{netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")}, reportTTL))

	stats := statsFor(t, h.proxy)
	assert.Equal(t, 2, stats.Users["alice"].ActiveIPs, "two places elsewhere count here")
	assert.Nil(t, stats.Users["alice"].ExternalIPs, "addresses are gated on tracking; the count is not")

	// A third place is refused...
	refuseFrom(t, ec, h, secret.Key, tcpFrom("203.0.113.9", 52001))

	// ...and a reported place is admitted, because it is not a new one.
	same, sameDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.7", 52002))
	sameUp := connectThrough(t, ec, h, same, "alice", secret.Key)
	defer endStream(same, sameUp, sameDone)

	assert.Equal(t, 2, statsFor(t, h.proxy).Users["alice"].ActiveIPs,
		"a place both reported and live is one place")

	// Once the report lapses, only the live place counts and the slot is free.
	time.Sleep(reportTTL + 200*time.Millisecond)

	third, thirdDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 52003))
	thirdUp := connectThrough(t, ec, h, third, "alice", secret.Key)
	defer endStream(third, thirdUp, thirdDone)

	assert.Equal(t, 2, statsFor(t, h.proxy).Users["alice"].ActiveIPs)

	require.ErrorIs(t, h.proxy.SetExternalAddresses("nobody", nil, time.Minute), ErrSecretNotFound)
}

// A limit with no address to count against fails closed: the only way a TCP
// listener yields none is a PROXY header declaring a non-TCP source, and
// admitting that uncounted would make the header the way around the limit.
// Without a limit the same connection is admitted, uncounted.
func TestIPLimitFailsClosedWithoutAnAddress(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	ec := govEntryCases()[1]
	noAddress := &net.UnixAddr{Name: "@nowhere", Net: "unix"}

	t.Run("limited", func(t *testing.T) {
		t.Parallel()

		h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": {IPLimit: 1}})

		refuseFrom(t, ec, h, secret.Key, noAddress)
		assert.EqualValues(t, 1, h.proxy.stats.users["alice"].ipLimitRefused.Load())
	})

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()

		h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

		client, done := dialProxyFrom(t, h, ec.policy, noAddress)
		upstream := connectThrough(t, ec, h, client, "alice", secret.Key)
		defer endStream(client, upstream, done)

		assert.Zero(t, statsFor(t, h.proxy).Users["alice"].ActiveIPs, "nothing to count, nothing counted")
	})
}

// A limit lowered on a running proxy binds the next admission and leaves the
// connections already open alone, like the quota and unlike a disable.
func TestIPLimitFollowsASecretSwapWithoutDroppingStreams(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	ec := govEntryCases()[1]
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

	first, firstDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.1", 53001))
	firstUp := connectThrough(t, ec, h, first, "alice", secret.Key)

	second, secondDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.2", 53002))
	secondUp := connectThrough(t, ec, h, second, "alice", secret.Key)

	require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": secret},
		Limits:  map[string]SecretLimits{"alice": {IPLimit: 1}},
	}))

	h.proxy.liveMu.Lock()
	live := len(h.proxy.liveConns["alice"])
	h.proxy.liveMu.Unlock()
	require.Equal(t, 2, live, "a lowered limit never closes what is already open")

	stats := statsFor(t, h.proxy)
	assert.Equal(t, 1, stats.Users["alice"].IPLimit)
	assert.Equal(t, 2, stats.Users["alice"].ActiveIPs, "over the new limit, and reported as such")

	refuseFrom(t, ec, h, secret.Key, tcpFrom("198.51.100.3", 53003))

	endStream(first, firstUp, firstDone)
	endStream(second, secondUp, secondDone)

	third, thirdDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.3", 53004))
	thirdUp := connectThrough(t, ec, h, third, "alice", secret.Key)
	defer endStream(third, thirdUp, thirdDone)
}

// The limit is set, read back and cleared through the secrets API with the
// same field on both sides, and the report routes validate, gate and 404 as
// the rest of the API does.
func TestIPLimitThroughTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	decode := func(t *testing.T, body []byte) map[string]any {
		t.Helper()

		out := map[string]any{}
		require.NoError(t, json.Unmarshal(body, &out))

		return out
	}

	body := `{"secrets":{"alice":{"secret":"` + alice.Hex() + `","ip_limit":2}}}`
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets", body).Code)

	assert.Equal(t, 2, p.secrets.Load().limits[0].IPLimit)
	assert.Equal(t, float64(2), decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes())["ip_limit"])

	users, _ := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())["users"].(map[string]any)
	user, _ := users["alice"].(map[string]any)
	assert.Equal(t, float64(2), user["ip_limit"])
	assert.NotContains(t, user, "active_ips", "nobody is anywhere yet")
	assert.NotContains(t, user, "ip_limit_refused")

	// A negative limit is refused and the running limit is untouched.
	rec := doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","ip_limit":-1}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "ip_limit")
	assert.Equal(t, 2, p.secrets.Load().limits[0].IPLimit)

	// Reports: counted at once, addresses withheld until tracking is on.
	rec = doAPI(t, p, "", http.MethodPut, "/secrets/alice/external-ips",
		`{"ips":["198.51.100.7","2001:db8::1"],"ttl":"90s"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	report := decode(t, rec.Body.Bytes())
	assert.Equal(t, "alice", report["name"])
	assert.Equal(t, float64(2), report["ip_limit"])
	assert.Equal(t, float64(2), report["active_ips"])
	assert.NotContains(t, report, "external_ips")
	assert.NotContains(t, report, "external_expires_at")

	p.trackClientIPs = true

	report = decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice/external-ips", "").Body.Bytes())
	assert.Equal(t, []any{"198.51.100.7", "2001:db8::1"}, report["external_ips"])
	assert.Contains(t, report, "external_expires_at")

	one := decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes())
	assert.Equal(t, float64(2), one["active_ips"])
	assert.Equal(t, []any{"198.51.100.7", "2001:db8::1"}, one["external_ips"])

	users, _ = statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())["users"].(map[string]any)
	user, _ = users["alice"].(map[string]any)
	assert.Equal(t, float64(2), user["active_ips"])
	assert.Equal(t, []any{"198.51.100.7", "2001:db8::1"}, user["external_ips"])

	// Validation is the parser's, and a bad report changes nothing.
	for _, bad := range []string{
		`{"ips":["example.com"]}`,
		`{"ips":["198.51.100.7"],"ttl":"2h"}`,
		`{"ips":["198.51.100.7"],"ttl":"0s"}`,
		`not json`,
	} {
		rec := doAPI(t, p, "", http.MethodPut, "/secrets/alice/external-ips", bad)
		assert.Equal(t, http.StatusBadRequest, rec.Code, bad)
	}

	report = decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice/external-ips", "").Body.Bytes())
	assert.Equal(t, float64(2), report["active_ips"])

	// An unknown user is 404 on every verb.
	assert.Equal(t, http.StatusNotFound, doAPI(t, p, "", http.MethodGet, "/secrets/bob/external-ips", "").Code)
	assert.Equal(t, http.StatusNotFound,
		doAPI(t, p, "", http.MethodPut, "/secrets/bob/external-ips", `{"ips":["198.51.100.7"]}`).Code)
	assert.Equal(t, http.StatusNotFound, doAPI(t, p, "", http.MethodDelete, "/secrets/bob/external-ips", "").Code)

	// Clearing the report empties the count.
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodDelete, "/secrets/alice/external-ips", "").Code)

	report = decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice/external-ips", "").Body.Bytes())
	assert.NotContains(t, report, "active_ips")
	assert.NotContains(t, report, "external_ips")

	// Omitted is unlimited, read back as absent.
	require.Equal(t, http.StatusOK,
		doAPI(t, p, "", http.MethodPut, "/secrets", `{"secrets":{"alice":{"secret":"`+alice.Hex()+`"}}}`).Code)
	assert.Zero(t, p.secrets.Load().limits[0].IPLimit)

	cleared := decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes())
	assert.NotContains(t, cleared, "ip_limit")

	report = decode(t, doAPI(t, p, "", http.MethodGet, "/secrets/alice/external-ips", "").Body.Bytes())
	assert.NotContains(t, report, "ip_limit")
}

// A reload from the file carries the limit the same way as the API, through
// the same swap.
func TestIPLimitThroughAReload(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newReloadTestProxy(map[string]Secret{"alice": alice})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{
			Secrets: map[string]Secret{"alice": alice},
			Limits:  map[string]SecretLimits{"alice": {IPLimit: 3}},
		}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	assert.Equal(t, 3, p.secrets.Load().limits[0].IPLimit)

	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{Secrets: map[string]Secret{"alice": alice}}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	assert.Zero(t, p.secrets.Load().limits[0].IPLimit)
}
