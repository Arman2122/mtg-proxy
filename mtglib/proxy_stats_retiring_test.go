package mtglib

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The read-only view of an overlap (spec §5.3, tests A7-A9 and D31): four
// scalars inside the secret's own object on GET /stats and GET /secrets/{name},
// absent for a name with no unexpired previous key, and never a key under users.
// The panel bills every key under users as a client and decodes the body without
// complaint about an unknown field, so what these tests hold fixed is the SHAPE:
// where the fields may appear, and that nothing else moves.

// viewRig is alice (on K1, about to be rotated to K2 with K1 and an older K0
// retiring), bob (rotated once) and carol (never rotated) on a hand-built proxy
// with a rotation clock the test moves. The proxy is built unrotated, so a test
// can register the streams that were live before the rotation; rotate then
// swaps the rotated file in.
type viewRig struct {
	p      *Proxy
	clock  *steppedClock
	k0     Secret // an older key of alice's, retiring until aliceLate
	k1     Secret // alice's key before the rotation, retiring until aliceEarly
	k2     Secret // alice's key after it
	bobOld Secret
	bobNew Secret
	carol  Secret
}

// The untils of the rig's three overlaps, relative to rotationNow where the
// rig's clock starts.
var (
	aliceEarly = rotationAt(time.Hour)
	aliceLate  = rotationAt(3 * time.Hour)
	bobUntil   = rotationAt(2 * time.Hour)
)

func newViewRig(t *testing.T) *viewRig {
	t.Helper()

	r := &viewRig{
		k0:     GenerateSecret("alice.example.com"),
		k1:     GenerateSecret("alice.example.com"),
		k2:     GenerateSecret("alice.example.com"),
		bobOld: GenerateSecret("bob.example.com"),
		bobNew: GenerateSecret("bob.example.com"),
		carol:  GenerateSecret("carol.example.com"),
	}

	r.p = newAPITestProxy(map[string]Secret{"alice": r.k1, "bob": r.bobOld, "carol": r.carol})
	r.clock = rotationClockAt(r.p, rotationNow)

	return r
}

// rotate swaps the rotated file in -- alice on K2 with K0 and K1 retiring, bob
// on his new key with his old one retiring, carol as she was -- and returns the
// set it built.
func (r *viewRig) rotate(t *testing.T) *secretSet {
	t.Helper()

	return rotateTo(t, r.p, map[string]Secret{"alice": r.k2, "bob": r.bobNew, "carol": r.carol},
		retire("alice", r.k0, aliceLate), retire("alice", r.k1, aliceEarly), retire("bob", r.bobOld, bobUntil))
}

// secrets is every key the rig knows, for the leak check.
func (r *viewRig) secrets() []Secret {
	return []Secret{r.k0, r.k1, r.k2, r.bobOld, r.bobNew, r.carol}
}

// retiringSecrets is the keys that are, or were, only ever retiring: a body that
// legitimately carries primaries is checked against these alone.
func (r *viewRig) retiringSecrets() []Secret {
	return []Secret{r.k0, r.k1, r.bobOld}
}

// bareStream is a stream with no socket and no handshake, closed with the test.
func bareStream(t testing.TB) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &streamContext{ctx: ctx, ctxCancel: cancel, logger: testLogger()}
}

// admit attributes a stream of name on secret's key as a door that matched it
// in the set in force does, and runs admission on it, which registers it and
// stamps what admission stamps. It requires that the stream was admitted.
func (r *viewRig) admit(t *testing.T, name string, secret Secret) *streamContext {
	t.Helper()

	sc := bareStream(t)
	attributeOnKey(t, r.p, r.p.secrets.Load(), sc, name, secret.Key)
	require.True(t, r.p.admit(sc), "a stream of %s on one of its keys is admitted", name)

	return sc
}

// retiringFields is the retiring_* keys of a decoded object: all of them, and
// only them, so that a test pins both which appear and that none else does.
func retiringFields(object map[string]any) map[string]any {
	out := map[string]any{}

	for key, value := range object {
		if strings.HasPrefix(key, "retiring_") {
			out[key] = value
		}
	}

	return out
}

// secretObject reads GET /secrets/{name}: the decoded object and the body.
func secretObject(t *testing.T, p *Proxy, name string) (map[string]any, string) {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, "/secrets/"+name, "")
	require.Equal(t, http.StatusOK, rec.Code)

	object := map[string]any{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &object))

	return object, rec.Body.String()
}

// assertRetiring requires that the retiring_* fields name carries are exactly
// want, on all three places that carry them: its object in GET /stats, GET
// /secrets/{name} and its entry in GET /secrets. Times are the strings the wire
// carries; counts are float64, as an untyped decode makes them.
func assertRetiring(t *testing.T, p *Proxy, name string, want map[string]any) {
	t.Helper()

	assert.Equal(t, want, retiringFields(statsUser(t, p, name)), "GET /stats, users.%s", name)

	object, _ := secretObject(t, p, name)
	assert.Equal(t, want, retiringFields(object), "GET /secrets/%s", name)

	rec := doAPI(t, p, "", http.MethodGet, "/secrets", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var list struct {
		Secrets []map[string]any `json:"secrets"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))

	found := false

	for _, entry := range list.Secrets {
		if entry["name"] == name {
			found = true

			assert.Equal(t, want, retiringFields(entry), "GET /secrets, the entry of %s", name)
		}
	}

	assert.True(t, found, "GET /secrets lists %s", name)
}

// assertSameInstant requires that two optional times are both absent or both the
// same instant.
func assertSameInstant(t *testing.T, want, got *time.Time, what string) {
	t.Helper()

	if want == nil || got == nil {
		assert.Equal(t, want == nil, got == nil, "%s is absent on both or on neither", what)

		return
	}

	assert.True(t, want.Equal(*got), "%s is the same instant on both", what)
}

// assertSurfacesAgree requires that GET /stats and GET /secrets say the same
// four things about name: they are built by different code over the same state.
func assertSurfacesAgree(t *testing.T, p *Proxy, name string) {
	t.Helper()

	stats, info := statsFor(t, p).Users[name], secretInfoFor(t, p, name)

	assert.Equal(t, stats.RetiringKeys, info.RetiringKeys)
	assert.Equal(t, stats.RetiringConnections, info.RetiringConnections)
	assertSameInstant(t, stats.RetiringUntil, info.RetiringUntil, "retiring_until")
	assertSameInstant(t, stats.RetiringLastSeen, info.RetiringLastSeen, "retiring_last_seen")
}

// overlap is the fields of a name with keys unexpired retiring keys that last
// until until, and no stream and no admission under any of them.
func overlap(keys int, until time.Time) map[string]any {
	return map[string]any{"retiring_keys": float64(keys), "retiring_until": changeUntil(until)}
}

// withConnections is want with retiring_connections n.
func withConnections(want map[string]any, n int) map[string]any {
	out := maps.Clone(want)
	out["retiring_connections"] = float64(n)

	return out
}

// A7. The four fields appear on a name that has an unexpired previous key, and
// nowhere else; nothing new is a key under users; the shape of a deployment that
// never rotated, and of a name that never was, is the one it always was. The
// byte-for-byte guard is TestStatsOmitemptyShapeUnchanged, which this does not
// touch; this is the half that exercises a rotation.
func TestRetiringFieldsAppearOnlyWhenRelevant(t *testing.T) {
	t.Parallel()

	none := map[string]any{}

	// What a user's object has always held when nothing is configured for it.
	plainUser := []string{"connections", "bytes_in", "bytes_out", "last_seen", "quota_used"}

	t.Run("a deployment that never rotated carries none of them", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)

		for _, name := range []string{"alice", "bob", "carol"} {
			assertRetiring(t, r.p, name, none)
		}

		assert.ElementsMatch(t, plainUser, slices.Collect(maps.Keys(statsUser(t, r.p, "alice"))))
	})

	t.Run("a rotated name reports its overlap and the others report nothing", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		fresh := statsRaw(t, doAPI(t, r.p, "", http.MethodGet, "/stats", "").Body.Bytes())

		r.rotate(t)

		// alice has two previous keys; the field is the LATER until, the moment
		// every old link of hers stops working, not the earlier one the set sorts
		// its sweep by.
		assertRetiring(t, r.p, "alice", overlap(2, aliceLate))
		assertRetiring(t, r.p, "bob", overlap(1, bobUntil))
		assertRetiring(t, r.p, "carol", none)

		raw := statsRaw(t, doAPI(t, r.p, "", http.MethodGet, "/stats", "").Body.Bytes())
		users, _ := raw["users"].(map[string]any)

		assert.ElementsMatch(t, []string{"alice", "bob", "carol"}, slices.Collect(maps.Keys(users)),
			"nothing new is a key under users")
		assert.ElementsMatch(t, slices.Collect(maps.Keys(fresh)), slices.Collect(maps.Keys(raw)),
			"nothing new is a key of the response either")

		carol, _ := users["carol"].(map[string]any)
		assert.ElementsMatch(t, plainUser, slices.Collect(maps.Keys(carol)),
			"a name that was never rotated has the object it always had")
	})

	t.Run("an overlap that ended on the clock alone is gone from the next read", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		r.rotate(t)

		// Past alice's earlier until and not her later: one key left, the later
		// until still reported. No swap and no sweep has run: the entries are
		// still in the set, and the view judges them by the clock.
		r.clock.set(rotationAt(90 * time.Minute))
		require.Equal(t, 3, heldRetiring(r.p), "the sweep has not run")

		assertRetiring(t, r.p, "alice", overlap(1, aliceLate))
		assertRetiring(t, r.p, "bob", overlap(1, bobUntil))

		// An until is the first instant the key is refused.
		r.clock.set(bobUntil)
		assertRetiring(t, r.p, "bob", none)
		assertRetiring(t, r.p, "alice", overlap(1, aliceLate))

		r.clock.set(rotationAt(4 * time.Hour))
		require.Equal(t, 3, heldRetiring(r.p), "the sweep has not run")

		for _, name := range []string{"alice", "bob", "carol"} {
			assertRetiring(t, r.p, name, none)
		}

		// And once the sweep has ended them for good, still none.
		r.p.expireRetiring()
		require.Zero(t, heldRetiring(r.p))

		for _, name := range []string{"alice", "bob", "carol"} {
			assertRetiring(t, r.p, name, none)
		}
	})

	t.Run("the rotation clock decides, not the wall clock", func(t *testing.T) {
		t.Parallel()

		t.Run("an overlap the wall clock has long outlived is shown while the rotation clock is inside it", func(t *testing.T) {
			t.Parallel()

			base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			alice, old := GenerateSecret("alice.example.com"), GenerateSecret("alice.example.com")

			p := newAPITestProxy(map[string]Secret{"alice": old})
			rotationClockAt(p, base)
			rotateTo(t, p, map[string]Secret{"alice": alice}, retire("alice", old, base.Add(time.Hour)))

			assertRetiring(t, p, "alice", overlap(1, base.Add(time.Hour)))
		})

		t.Run("an overlap the wall clock has not reached is hidden once the rotation clock has", func(t *testing.T) {
			t.Parallel()

			base := time.Now().UTC().AddDate(10, 0, 0).Truncate(time.Second)
			alice, old := GenerateSecret("alice.example.com"), GenerateSecret("alice.example.com")

			p := newAPITestProxy(map[string]Secret{"alice": old})
			clock := rotationClockAt(p, base)
			rotateTo(t, p, map[string]Secret{"alice": alice}, retire("alice", old, base.Add(time.Hour)))

			assertRetiring(t, p, "alice", overlap(1, base.Add(time.Hour)))

			clock.set(base.Add(2 * time.Hour))
			assertRetiring(t, p, "alice", none)
		})
	})

	t.Run("the view is laid over users that exist and never adds one", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		r.rotate(t)

		// Every swap pre-registers every name, so a rotated name always has a
		// bucket in practice. The overlay's rule is about the shape: a name in
		// the set whose counters are not in the response is not made a user by
		// having an overlap, because every key under users is billed as a client.
		r.p.stats = NewProxyStats()
		r.p.stats.PreRegister("bob")

		raw := statsRaw(t, doAPI(t, r.p, "", http.MethodGet, "/stats", "").Body.Bytes())
		users, _ := raw["users"].(map[string]any)

		assert.Equal(t, []string{"bob"}, slices.Collect(maps.Keys(users)), "alice has overlap and no bucket: not a user")

		bob, _ := users["bob"].(map[string]any)
		assert.Equal(t, overlap(1, bobUntil), retiringFields(bob), "a user that is there still gets its view")

		// GET /secrets/{name} lists the set's names, not the counters', and says
		// the same.
		object, _ := secretObject(t, r.p, "alice")
		assert.Equal(t, overlap(2, aliceLate), retiringFields(object))
	})

	t.Run("a time is written in UTC whatever zone the entry was given in", func(t *testing.T) {
		t.Parallel()

		zone := time.FixedZone("east", 5*60*60+30*60)
		until := aliceEarly.In(zone)
		alice, old := GenerateSecret("alice.example.com"), GenerateSecret("alice.example.com")

		p := newAPITestProxy(map[string]Secret{"alice": old})
		rotationClockAt(p, rotationNow)
		rotateTo(t, p, map[string]Secret{"alice": alice}, retire("alice", old, until))

		stamp, _ := statsUser(t, p, "alice")["retiring_until"].(string)
		assert.Equal(t, changeUntil(aliceEarly), stamp)
		assert.True(t, strings.HasSuffix(stamp, "Z"), "UTC, not an offset: %s", stamp)

		object, _ := secretObject(t, p, "alice")
		stamp, _ = object["retiring_until"].(string)
		assert.True(t, strings.HasSuffix(stamp, "Z"), "UTC, not an offset: %s", stamp)
	})

	t.Run("no key material is in any of the bodies", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		r.rotate(t)
		r.admit(t, "alice", r.k1)
		r.admit(t, "alice", r.k0)
		r.admit(t, "bob", r.bobOld)

		alice := statsUser(t, r.p, "alice")
		require.Contains(t, alice, "retiring_last_seen", "the body checked below carries every one of the four")
		require.Contains(t, alice, "retiring_connections")

		stats := doAPI(t, r.p, "", http.MethodGet, "/stats", "").Body.String()
		assert.Empty(t, leaks(stats, r.secrets()), "GET /stats carries no value of any key")

		// The detail and the list legitimately carry a primary's value: it is
		// what the panel hands out. What they must not carry is a previous key's.
		for _, name := range []string{"alice", "bob", "carol"} {
			_, body := secretObject(t, r.p, name)
			assert.Empty(t, leaks(body, r.retiringSecrets()), "GET /secrets/%s carries no previous key", name)
		}

		list := doAPI(t, r.p, "", http.MethodGet, "/secrets", "").Body.String()
		assert.Empty(t, leaks(list, r.retiringSecrets()), "GET /secrets carries no previous key")
	})
}

// A8. retiring_connections is computed from the key a stream matched at the time
// of the read, not from how it was admitted. Right after a rotation every
// old-link stream was admitted as the primary, because it was one: a flag set at
// admission would read 0 exactly when the operator is watching the number fall.
func TestRetiringConnectionsCountsLiveOldLinkStreams(t *testing.T) {
	t.Parallel()

	none := map[string]any{}

	r := newViewRig(t)

	const n = 3

	olds := make([]*streamContext, 0, n)
	for range n {
		olds = append(olds, registerOnKey(t, r.p, "alice", r.k1.Key))
	}

	registerOnKey(t, r.p, "bob", r.bobOld.Key)
	registerOnKey(t, r.p, "bob", r.bobOld.Key)
	registerOnKey(t, r.p, "carol", r.carol.Key)

	assertRetiring(t, r.p, "alice", none)

	r.rotate(t)

	for _, sc := range olds {
		require.True(t, sc.retiringUntil.IsZero(), "every old-link stream was admitted as the primary")
	}

	// N right after the rotation, with no stream admitted under a retiring key.
	assertRetiring(t, r.p, "alice", withConnections(overlap(2, aliceLate), n))
	assertRetiring(t, r.p, "bob", withConnections(overlap(1, bobUntil), 2))
	assertRetiring(t, r.p, "carol", none)
	assertSurfacesAgree(t, r.p, "alice")

	// A stream on the new key is not an old link.
	registerOnKey(t, r.p, "alice", r.k2.Key)
	assertRetiring(t, r.p, "alice", withConnections(overlap(2, aliceLate), n))

	// Streams admitted after the rotation under either previous key are.
	viaK0 := registerOnKey(t, r.p, "alice", r.k0.Key)
	require.False(t, viaK0.retiringUntil.IsZero())
	assertRetiring(t, r.p, "alice", withConnections(overlap(2, aliceLate), n+1))

	registerOnKey(t, r.p, "alice", r.k1.Key)
	assertRetiring(t, r.p, "alice", withConnections(overlap(2, aliceLate), n+2))
	assertSurfacesAgree(t, r.p, "alice")

	// The number falls as the old links close, which is what it is for.
	r.p.unregisterConn(olds[0])
	r.p.unregisterConn(viaK0)
	assertRetiring(t, r.p, "alice", withConnections(overlap(2, aliceLate), n))

	// A name with no unexpired previous key reports no connections, whatever
	// its streams hold: the clock has passed every until and no sweep has run,
	// so the old-link streams are still live, and still not reported.
	r.clock.set(rotationAt(4 * time.Hour))
	require.Equal(t, 3, heldRetiring(r.p), "the sweep has not run")

	for _, name := range []string{"alice", "bob", "carol"} {
		assertRetiring(t, r.p, name, none)
	}
}

const (
	// viewLockHold is how long the lock test waits to see that retiringViews has
	// NOT returned while the registry lock is held. A wait that is too short can
	// only make a missing lock go unnoticed, never a present one fail.
	viewLockHold = 200 * time.Millisecond

	// viewLockBound is how long it waits for retiringViews to return once the lock
	// is let go. Generous, and only ever spent when the code under test is wrong.
	viewLockBound = 5 * time.Second
)

// retiringViews takes liveMu to walk the streams of the names that have an
// overlap, because admission and release write that registry under it. This is
// the deterministic proof: with the registry lock held here, the walk cannot
// return, and it returns once the lock is let go. A walk without the lock
// returns at once and fails the first wait.
func TestRetiringConnectionsWaitForTheRegistryLock(t *testing.T) {
	t.Parallel()

	r := newViewRig(t)
	set := r.rotate(t)

	r.p.liveMu.Lock()

	held := true
	defer func() {
		if held {
			r.p.liveMu.Unlock()
		}
	}()

	done := make(chan map[string]retiringView, 1)

	go func() { done <- r.p.retiringViews(set, rotationNow) }()

	select {
	case <-done:
		t.Fatal("retiringViews returned while the registry lock was held: it walks the streams without it")
	case <-time.After(viewLockHold):
	}

	r.p.liveMu.Unlock()

	held = false

	select {
	case views := <-done:
		assert.Equal(t, 2, views["alice"].keys, "and once the lock is let go it answers")
	case <-time.After(viewLockBound):
		t.Fatal("retiringViews did not return after the registry lock was let go")
	}
}

// The same lock, proven by a race instead of by waiting: registration and
// release churn against repeated walks. A walk without the lock is a map read
// against a map write. This proves the lock ONLY under -race, where the detector
// reports the two accesses; without it the runtime's own concurrent-map check
// may or may not trip, so TestRetiringConnectionsWaitForTheRegistryLock above is
// the one that holds on any run.
func TestRetiringConnectionsAreCountedUnderTheRegistryLock(t *testing.T) {
	t.Parallel()

	r := newViewRig(t)
	set := r.rotate(t)

	const (
		pool   = 64
		rounds = 2000
		reads  = 400
	)

	streams := make([]*streamContext, pool)
	for i := range streams {
		streams[i] = bareStream(t)
		attributeOnKey(t, r.p, set, streams[i], "alice", r.k1.Key)
	}

	var (
		refused atomic.Int64
		wg      sync.WaitGroup
	)

	wg.Go(func() {
		for i := range rounds {
			sc := streams[i%pool]

			if r.p.tryRegisterConn(sc) != DenyNone {
				refused.Add(1)

				continue
			}

			r.p.unregisterConn(sc)
		}
	})

	most := 0

	for range reads {
		views := r.p.retiringViews(set, rotationNow)
		most = max(most, views["alice"].connections)
	}

	wg.Wait()

	assert.Zero(t, refused.Load(), "every registration of an old link inside its overlap is admitted")
	assert.LessOrEqual(t, most, pool)
}

// D31. retiring_last_seen is the last admission made under a previous key: an
// admission as the primary does not move it, a refused admission does not move
// it, and it is reported only while the name still has a previous key to report
// it with.
func TestRetiringLastSeenFollowsRetiringAdmissions(t *testing.T) {
	t.Parallel()

	none := map[string]any{}

	r := newViewRig(t)
	r.rotate(t)

	stamp := func(name string) int64 { return r.p.stats.users[name].retiringLastSeen.Load() }

	// Nobody has come in on an old link.
	assertRetiring(t, r.p, "alice", overlap(2, aliceLate))

	// A stream on the name's primary is not an old link.
	r.admit(t, "alice", r.k2)
	r.admit(t, "bob", r.bobNew)
	assert.Zero(t, stamp("alice"), "an admission as the primary stamps nothing")
	assert.Zero(t, stamp("bob"))
	assertRetiring(t, r.p, "alice", overlap(2, aliceLate))

	// A stream on a previous key is.
	before := time.Now()
	r.admit(t, "alice", r.k1)
	after := time.Now()

	object := statsUser(t, r.p, "alice")
	text, _ := object["retiring_last_seen"].(string)
	require.NotEmpty(t, text, "an admission under a previous key stamps it")

	seen, err := time.Parse(time.RFC3339Nano, text)
	require.NoError(t, err)

	assert.False(t, seen.Before(before) || seen.After(after), "it is when the admission happened: %s", text)
	assert.True(t, strings.HasSuffix(text, "Z"), "UTC, not an offset: %s", text)
	assertSurfacesAgree(t, r.p, "alice")

	// The wire text ends in Z on any host whose local zone is UTC, whatever the
	// code did, so the zone is pinned on the Go value as well: the one location
	// time.UTC, which time.Local is not even when it has no offset.
	views := r.p.retiringViews(r.p.secrets.Load(), r.p.rotation.Now())
	assert.Same(t, time.UTC, views["alice"].lastSeen.Location(), "the stamp is in UTC on every host")
	assert.Same(t, time.UTC, views["alice"].until.Location(), "and so is the until")

	info := secretInfoFor(t, r.p, "alice")
	require.NotNil(t, info.RetiringLastSeen)
	require.NotNil(t, info.RetiringUntil)
	assert.Same(t, time.UTC, info.RetiringLastSeen.Location(), "GET /secrets says it in UTC")
	assert.Same(t, time.UTC, info.RetiringUntil.Location())

	// It is alice's: bob, whose old key nobody used, has none.
	assertRetiring(t, r.p, "bob", overlap(1, bobUntil))
	assert.Zero(t, stamp("bob"))

	// A later admission under another previous key moves it on, never back.
	first := stamp("alice")
	r.admit(t, "alice", r.k0)
	assert.GreaterOrEqual(t, stamp("alice"), first)

	// A refused admission is not an admission: bob's old key expires between the
	// door and registration, which refuses it.
	late := bareStream(t)
	attributeOnKey(t, r.p, r.p.secrets.Load(), late, "bob", r.bobOld.Key)
	r.clock.set(rotationAt(4 * time.Hour))

	require.False(t, r.p.admit(late), "an old key past its until is refused at registration")
	assert.Zero(t, stamp("bob"), "a refusal stamps nothing")

	// Both overlaps are over, with no sweep: alice's stamp is still there, and is
	// not reported, because a name with no previous key has no last seen of one.
	require.Equal(t, 3, heldRetiring(r.p), "the sweep has not run")
	assert.NotZero(t, stamp("alice"), "the stamp itself is kept")
	assertRetiring(t, r.p, "alice", none)
	assertRetiring(t, r.p, "bob", none)
}

// stampOf is the raw retiring_last_seen stamp of name: what was recorded, not
// what is reported. 0 is never.
func (r *viewRig) stampOf(name string) int64 {
	return r.p.stats.users[name].retiringLastSeen.Load()
}

// admitAndRelease admits a stream of name on secret's key, so that admission
// stamps what it stamps, and lets the stream go again: the stamp is what a test
// wants, not a live stream counted as an old link.
func (r *viewRig) admitAndRelease(t *testing.T, name string, secret Secret) {
	t.Helper()

	r.p.release(r.admit(t, name, secret))
}

// hasLastSeen says whether name's object in GET /stats carries
// retiring_last_seen.
func hasLastSeen(t *testing.T, p *Proxy, name string) bool {
	t.Helper()

	_, has := statsUser(t, p, name)["retiring_last_seen"]

	return has
}

// D31, revision 4. retiring_last_seen answers "has anyone used THIS old link
// lately", so it is cleared when a name gets its first unexpired retiring entry
// in a new set -- it had none in the set being replaced. A second rotation never
// shows the previous overlap's last admission, which would read as "the old link
// has been quiet for nine days" about a key that was the primary a minute ago and
// invite an early --end-overlap. Reported "absent" means nobody has come in on
// the old link since this overlap began, which is also what the first rotation
// says.
func TestASecondRotationDoesNotShowTheFirstOverlapsLastSeen(t *testing.T) {
	t.Parallel()

	for _, variant := range []struct {
		name string
		// between ends the first overlap, or puts the name outside the set, before
		// the second rotation.
		between func(*testing.T, *viewRig)
	}{
		{"after the sweep ended the first overlap", func(t *testing.T, r *viewRig) {
			r.clock.set(rotationAt(4 * time.Hour))
			r.p.expireRetiring()
			require.Zero(t, heldRetiring(r.p), "the sweep ended the overlaps")
		}},
		{"on a swap after the until that never saw the sweep", func(t *testing.T, r *viewRig) {
			r.clock.set(rotationAt(4 * time.Hour))
			require.Equal(t, 3, heldRetiring(r.p), "the sweep has not run: the set still holds the entries")
		}},
		{"for a name that left the set and came back", func(t *testing.T, r *viewRig) {
			require.NoError(t, r.p.ReplaceSecrets(SecretConfig{Secrets: map[string]Secret{"bob": r.bobNew, "carol": r.carol}}))
			require.Zero(t, heldRetiring(r.p))
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			t.Parallel()

			r := newViewRig(t)
			r.rotate(t)

			r.admitAndRelease(t, "alice", r.k1)
			require.NotZero(t, r.stampOf("alice"))
			require.True(t, hasLastSeen(t, r.p, "alice"), "the first overlap reports it")

			variant.between(t, r)

			// alice is rotated again: K3 is the primary and K2, until now the primary,
			// retires. K2 has not been used since it stopped being the primary.
			k3, until := GenerateSecret("alice.example.com"), rotationAt(24*time.Hour)
			rotateTo(t, r.p, map[string]Secret{"alice": k3, "bob": r.bobNew, "carol": r.carol},
				retire("alice", r.k2, until))

			assertRetiring(t, r.p, "alice", overlap(1, until))
			assert.Zero(t, r.stampOf("alice"), "the stamp was cleared, not merely hidden")

			// And the new old link's first admission is reported.
			r.admit(t, "alice", r.k2)
			assert.NotZero(t, r.stampOf("alice"))
			assert.True(t, hasLastSeen(t, r.p, "alice"))
			assertSurfacesAgree(t, r.p, "alice")
		})
	}
}

// An admission through the new set's entry that arrives right after the swap
// stored the set is not wiped: the reset runs between the build and the Swap, not
// after it. afterSecretStoreHook runs in exactly that window, so a reset placed
// after the Swap wipes what the hook's stream stamped. A package seam, so this
// test is not parallel.
func TestAnAdmissionRightAfterTheSwapIsNotWiped(t *testing.T) {
	r := newViewRig(t)

	admitted := false

	installAfterSecretStoreHook(t, func(*secretSet) {
		if admitted {
			return
		}

		admitted = true

		r.admit(t, "alice", r.k1)
	})

	r.rotate(t)

	require.True(t, admitted, "the stream was admitted in the window after the new set was stored")
	assert.NotZero(t, r.stampOf("alice"), "its stamp survives the swap")
	assert.True(t, hasLastSeen(t, r.p, "alice"))
	assertSurfacesAgree(t, r.p, "alice")
}

// A swap that leaves the name's overlap in force does not reset it: an unrelated
// one (another secret's ad tag), and another rotation of the same name while its
// first overlap is still running, where the earlier admission is still about a
// working old link.
func TestASwapInsideALiveOverlapKeepsTheLastSeen(t *testing.T) {
	t.Parallel()

	t.Run("an unrelated swap", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		r.rotate(t)
		r.admitAndRelease(t, "alice", r.k1)

		stamp := r.stampOf("alice")
		require.NotZero(t, stamp)

		cfg := r.p.secrets.Load().toConfig()
		cfg.SecretAdTags = map[string][AdTagLength]byte{"carol": {1, 2, 3}}
		require.NoError(t, r.p.ReplaceSecrets(cfg))

		assert.Equal(t, stamp, r.stampOf("alice"), "an unrelated swap does not reset it")
		assert.True(t, hasLastSeen(t, r.p, "alice"))
	})

	t.Run("another rotation of the name inside its overlap", func(t *testing.T) {
		t.Parallel()

		r := newViewRig(t)
		r.rotate(t)
		r.admitAndRelease(t, "alice", r.k1)

		stamp := r.stampOf("alice")
		require.NotZero(t, stamp)

		k3 := GenerateSecret("alice.example.com")
		cfg := r.p.secrets.Load().toConfig()
		cfg.Secrets["alice"] = k3
		cfg.Retiring = append(cfg.Retiring, retire("alice", r.k2, rotationAt(5*time.Hour)))
		require.NoError(t, r.p.ReplaceSecrets(cfg))

		assert.Len(t, r.p.secrets.Load().retiring, 4, "alice now has three previous keys, bob one")
		assert.Equal(t, stamp, r.stampOf("alice"), "the name already had a previous key: no reset")
		assert.True(t, hasLastSeen(t, r.p, "alice"))
	})
}

// The reset is for the names that got their first entry, and only those: a name
// whose overlap ended and who was not rotated again keeps its stamp (unreported,
// since it has no previous key), and another name's reset does not touch it.
func TestTheResetTouchesOnlyTheNameThatGotItsFirstEntry(t *testing.T) {
	t.Parallel()

	r := newViewRig(t)
	carolNew, carolThird := GenerateSecret("carol.example.com"), GenerateSecret("carol.example.com")

	rotateTo(t, r.p, map[string]Secret{"alice": r.k2, "bob": r.bobNew, "carol": carolNew},
		retire("alice", r.k1, aliceEarly), retire("bob", r.bobOld, bobUntil), retire("carol", r.carol, bobUntil))

	r.admitAndRelease(t, "alice", r.k1)
	r.admitAndRelease(t, "bob", r.bobOld)
	r.admitAndRelease(t, "carol", r.carol)

	alice, bob := r.stampOf("alice"), r.stampOf("bob")
	require.NotZero(t, alice)
	require.NotZero(t, bob)
	require.NotZero(t, r.stampOf("carol"))

	r.clock.set(rotationAt(4 * time.Hour))
	r.p.expireRetiring()
	require.Zero(t, heldRetiring(r.p), "every overlap is over")

	// Only carol is rotated again.
	rotateTo(t, r.p, map[string]Secret{"alice": r.k2, "bob": r.bobNew, "carol": carolThird},
		retire("carol", carolNew, rotationAt(5*time.Hour)))

	assert.Zero(t, r.stampOf("carol"), "carol got a first entry in this set")
	assert.Equal(t, alice, r.stampOf("alice"), "alice is not in this rotation")
	assert.Equal(t, bob, r.stampOf("bob"), "nor is bob")
}

// Nothing about an overlap costs anything when there is none: the three
// read-backs do not read the rotation clock for a set with no retiring entry,
// and with some they read it once for the whole response, not once per secret.
func TestStatsReadTheRotationClockOnlyForAnOverlap(t *testing.T) {
	t.Parallel()

	r := newViewRig(t)

	var reads atomic.Int64

	r.p.rotation = NewRotationClock(func() time.Time {
		reads.Add(1)

		return rotationNow
	}, nil)

	for _, target := range []string{"/stats", "/secrets", "/secrets/alice"} {
		require.Equal(t, http.StatusOK, doAPI(t, r.p, "", http.MethodGet, target, "").Code)
	}

	assert.Zero(t, reads.Load(), "no retiring entry, no clock read")
	assert.Nil(t, r.p.retiringViews(r.p.secrets.Load(), rotationNow), "no retiring entry, no view")
	assert.Nil(t, r.p.retiringViews(nil, rotationNow), "no set, no view")

	r.rotate(t)
	reads.Store(0)

	require.Equal(t, http.StatusOK, doAPI(t, r.p, "", http.MethodGet, "/stats", "").Code)
	assert.EqualValues(t, 1, reads.Load(), "GET /stats reads the clock once")

	require.Equal(t, http.StatusOK, doAPI(t, r.p, "", http.MethodGet, "/secrets", "").Code)
	assert.EqualValues(t, 2, reads.Load(), "GET /secrets reads it once for all three secrets")
}

// A9. The capability is advertised, in its place in the sorted list: between
// secret-read and secrets-api. The four pinned lists in TestStatsFeatures say
// the same in full; this holds the neighbours and the order independently of
// them, so that a list edited to match a misplaced entry still fails.
func TestTheRotationFeatureIsAdvertisedInOrder(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "secret-rotation", FeatureSecretRotation)

	at := slices.Index(supportedFeatures, FeatureSecretRotation)
	require.NotEqual(t, -1, at, "the build advertises it")
	require.Positive(t, at)
	require.Less(t, at, len(supportedFeatures)-1)

	assert.Equal(t, FeatureSecretRead, supportedFeatures[at-1])
	assert.Equal(t, FeatureSecretsAPI, supportedFeatures[at+1])
	assert.True(t, slices.IsSorted(supportedFeatures), "the list is sorted so /stats is byte-stable")

	p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

	var resp StatsResponse

	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes(), &resp))
	assert.Contains(t, resp.Features, FeatureSecretRotation)
}
