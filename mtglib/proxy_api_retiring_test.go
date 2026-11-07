package mtglib

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The management API with retiring keys (spec §5.1, tests A1-A6, D17 and D18):
// the API cannot express an overlap, so no call may end one it did not mean to,
// and none may make one. A PUT keeps the overlaps of the names it keeps, a
// removal takes a name's overlaps with it, a POST of another name leaves them
// alone, and a reload takes the file's. The tests hold no key in an assertion
// that can fail: sets are compared by counts, names and untils, and keys by
// accepts or by ==, which print nothing.

// apiRotation is alice and bob, each re-keyed with an overlap still running, and
// carol, who never was, on a hand-built proxy with a rotation clock the test
// moves and a log it reads. The clock stands well before both untils.
type apiRotation struct {
	p          *Proxy
	clock      *steppedClock
	log        *rotationLog
	aliceOld   Secret    // alice's key before the rotation: K1
	aliceNew   Secret    // alice's key after it: K2
	bobOld     Secret    // bob's key before the rotation
	bobNew     Secret    // bob's key after it
	carol      Secret    // carol's one key
	aliceUntil time.Time // when K1's overlap ends
	bobUntil   time.Time // when bob's old key's overlap ends
}

func newAPIRotation(t *testing.T) *apiRotation {
	t.Helper()

	a := &apiRotation{
		aliceOld:   GenerateSecret("alice.example.com"),
		aliceNew:   GenerateSecret("alice.example.com"),
		bobOld:     GenerateSecret("bob.example.com"),
		bobNew:     GenerateSecret("bob.example.com"),
		carol:      GenerateSecret("carol.example.com"),
		log:        &rotationLog{},
		aliceUntil: rotationAt(time.Hour),
		bobUntil:   rotationAt(2 * time.Hour),
	}

	a.p = newAPITestProxy(map[string]Secret{"alice": a.aliceOld, "bob": a.bobOld, "carol": a.carol})
	a.p.logger = rotationLogger{log: a.log}
	a.clock = rotationClockAt(a.p, rotationNow)

	cfg := a.rotated()
	rotateTo(t, a.p, cfg.Secrets, cfg.Retiring...)

	return a
}

// rotated is the config after both rotations: alice and bob on their new keys
// with the old ones retiring until their untils, carol as she was.
func (a *apiRotation) rotated() SecretConfig {
	return SecretConfig{
		Secrets:  map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": a.carol},
		Retiring: []RetiringSecret{retire("alice", a.aliceOld, a.aliceUntil), retire("bob", a.bobOld, a.bobUntil)},
	}
}

// secrets is every key the fixture knows, for the leak check.
func (a *apiRotation) secrets() []Secret {
	return []Secret{a.aliceOld, a.aliceNew, a.bobOld, a.bobNew, a.carol}
}

// stream registers a stream of name holding secret's key.
func (a *apiRotation) stream(t *testing.T, name string, secret Secret) *streamContext {
	t.Helper()

	return registerOnKey(t, a.p, name, secret.Key)
}

// accepts says whether the set in force accepts secret's key for name at the
// rotation clock's instant.
func (a *apiRotation) accepts(name string, secret Secret) bool {
	return a.p.secrets.Load().accepts(name, secret.Key[:], a.clock.now())
}

// entries is the retiring entries the set in force holds, as "name until", in
// the set's order, and nil when it holds none. Never a key.
func (a *apiRotation) entries() []string {
	set := a.p.secrets.Load()

	var out []string

	for r := range set.retiring {
		entry := &set.retiring[r]
		out = append(out, set.names[entry.nameIdx]+" until "+changeUntil(entry.until))
	}

	return out
}

// untilOf is how entries writes an until.
func untilOf(name string, until time.Time) string {
	return name + " until " + changeUntil(until)
}

// primaryIs says whether name's primary key in the set in force is secret's.
func (a *apiRotation) primaryIs(name string, secret Secret) bool {
	set := a.p.secrets.Load()

	i, ok := set.indexOf(name)

	return ok && set.secrets[i].Key == secret.Key
}

// call makes one API request on the proxy, with no token, so that
// authentication can never be why a route answers as it does.
func (a *apiRotation) call(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var raw string

	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)

		raw = string(encoded)
	}

	return doAPI(t, a.p, "", method, target, raw)
}

// put is PUT /secrets with the given secrets, as the panel makes it: no
// retiring entry, no limit. It requires the answer every PUT has always given.
func (a *apiRotation) put(t *testing.T, secrets map[string]Secret) {
	t.Helper()

	entries := make(map[string]map[string]string, len(secrets))
	for name, secret := range secrets {
		entries[name] = map[string]string{"secret": secret.Hex()}
	}

	rec := a.call(t, http.MethodPut, "/secrets", map[string]any{"secrets": entries})

	require.Equal(t, http.StatusOK, rec.Code, "a PUT answers 200, as it always did")
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String(), "and its body is unchanged")
}

// post is POST /secrets for one name.
func (a *apiRotation) post(t *testing.T, name string, secret Secret) {
	t.Helper()

	rec := a.call(t, http.MethodPost, "/secrets", map[string]string{"name": name, "secret": secret.Hex()})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

const (
	// keepMergeBound is how long a test waits for a goroutine the merge's seam
	// depends on. Generous, and only ever spent when the code under test is wrong.
	keepMergeBound = 5 * time.Second

	// keepMergeHold is how long a goroutine that took reloadMu in the seam holds
	// it before it swaps.
	keepMergeHold = 50 * time.Millisecond
)

// installBeforeKeepMergeLockHook replaces the seam the PUT's keep-merge calls
// before it takes reloadMu, and puts it back. The seam is a package variable, so
// a test that uses it is not parallel.
func installBeforeKeepMergeLockHook(t *testing.T, hook func()) {
	t.Helper()

	previous := beforeKeepMergeLockHook
	beforeKeepMergeLockHook = hook

	t.Cleanup(func() { beforeKeepMergeLockHook = previous })
}

// A1. A PUT keeps the entries of the names it keeps, and drops those of the
// names it removes. The panel's PUT states no overlap, and cannot: reading its
// silence as "none" would end every overlap the file granted, and the next
// restart would grant it again.
//
// A name the PUT removes takes its entries with it before the build sees them.
// The build would drop them anyway, as dangling, and the set would come out the
// same, so what tells a merge that filters by name from one that does not is the
// drop line: the build is handed nothing it has to drop.
//
// The library's ReplaceSecrets is another matter: a nil Retiring is none there,
// as in every swap, and only the HTTP PUT keeps.
func TestPutSecretsKeepsTheEntriesOfTheNamesItKeeps(t *testing.T) {
	t.Parallel()

	t.Run("a name it keeps keeps its entry, a name it removes loses its own", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		aliceOld, aliceNew := a.stream(t, "alice", a.aliceOld), a.stream(t, "alice", a.aliceNew)
		bobOld, bobNew := a.stream(t, "bob", a.bobOld), a.stream(t, "bob", a.bobNew)
		carol := a.stream(t, "carol", a.carol)

		a.put(t, map[string]Secret{"alice": a.aliceNew, "carol": a.carol})

		assert.Equal(t, []string{untilOf("alice", a.aliceUntil)}, a.entries())
		assert.True(t, a.accepts("alice", a.aliceOld), "alice's old key is still accepted")
		assert.False(t, a.accepts("bob", a.bobOld), "bob is gone, and so is his old key")
		assert.False(t, a.accepts("bob", a.bobNew))

		for name, sc := range map[string]*streamContext{"alice's K1 stream": aliceOld, "alice's K2 stream": aliceNew, "carol's stream": carol} {
			assert.NoError(t, sc.Err(), "%s is not touched: its secret is kept, and so are its keys", name)
		}

		for name, sc := range map[string]*streamContext{"bob's old key stream": bobOld, "bob's new key stream": bobNew} {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "%s: the name is removed", name)
		}

		assert.Empty(t, ignoredLines(t, a.log), "the build is handed no entry of a removed name to drop")
		assert.Empty(t, leaks(a.log.text(), a.secrets()))
	})

	t.Run("every name it keeps keeps its entry, in the set's order", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)

		a.put(t, map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": a.carol})

		assert.Equal(t, []string{untilOf("alice", a.aliceUntil), untilOf("bob", a.bobUntil)}, a.entries())
		assert.True(t, a.accepts("alice", a.aliceOld))
		assert.True(t, a.accepts("bob", a.bobOld))
		assert.NoError(t, aliceOld.Err())
		assert.NoError(t, bobOld.Err())

		assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil)}, changeLines(a.log),
			"a PUT that changes nothing about rotation writes nothing about it")
		assert.Empty(t, ignoredLines(t, a.log))
		assert.Empty(t, leaks(a.log.text(), a.secrets()))
	})

	t.Run("the library's ReplaceSecrets with a nil Retiring clears them", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)
		aliceNew := a.stream(t, "alice", a.aliceNew)

		cfg := a.rotated()
		cfg.Retiring = nil

		require.NoError(t, a.p.ReplaceSecrets(cfg))

		assert.Empty(t, a.entries(), "nil is none, wherever a SecretConfig is consumed")
		assert.False(t, a.accepts("alice", a.aliceOld))
		assert.False(t, a.accepts("bob", a.bobOld))
		assert.ErrorIs(t, aliceOld.Err(), context.Canceled, "the overlap ended: its stream is closed")
		assert.ErrorIs(t, bobOld.Err(), context.Canceled)
		assert.NoError(t, aliceNew.Err())
		assert.Empty(t, leaks(a.log.text(), a.secrets()))
	})
}

// A2, the revert. POST /secrets re-keying a name back onto its retiring key makes
// that key the primary on purpose (a PUT can too: see the test below). The entry
// is dropped (the primary wins, rule 6), the streams on the key stay open under
// their now-primary key, and the streams on the key it took away close. Another
// name's entry is not touched.
func TestPostingTheRetiringKeyBackMakesItPrimary(t *testing.T) {
	t.Parallel()

	a := newAPIRotation(t)

	k1 := a.stream(t, "alice", a.aliceOld)
	k2s := []*streamContext{a.stream(t, "alice", a.aliceNew), a.stream(t, "alice", a.aliceNew)}
	bobOld := a.stream(t, "bob", a.bobOld)

	a.post(t, "alice", a.aliceOld)

	assert.True(t, a.primaryIs("alice", a.aliceOld), "K1 is the primary again")
	assert.False(t, a.accepts("alice", a.aliceNew), "and K2, which it took away, is not accepted")
	assert.Equal(t, []string{untilOf("bob", a.bobUntil)}, a.entries(), "alice's entry is dropped, bob's is not")

	assert.NoError(t, k1.Err(), "K1's stream stays open: its key is the primary now")

	for i, sc := range k2s {
		assert.ErrorIs(t, sc.Err(), context.Canceled, "K2 stream %d closes", i)
	}

	assert.NoError(t, bobOld.Err())
	assert.True(t, a.accepts("bob", a.bobOld))

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), returnedLine("alice", len(k2s))},
		changeLines(a.log))
	assert.Empty(t, leaks(a.log.text(), a.secrets()))
}

// A2, the other ways to make a retiring key a primary. The POST revert is not the
// only one: a PUT whose body names the retiring key as the name's primary does the
// same, and a PUT or a POST that gives ANOTHER name the key makes it that name's
// primary instead. Both are the primary winning (rules 6 and 5), and neither is
// silent: the build says so, at Info for the name's own key and at Warning for
// another name's, and the change log says what the swap did to the streams.
func TestTheRetiringKeyNamedByAPutOrAPostBecomesAPrimary(t *testing.T) {
	t.Parallel()

	t.Run("a PUT that names it as the name's own primary", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		k1 := a.stream(t, "alice", a.aliceOld)
		k2s := []*streamContext{a.stream(t, "alice", a.aliceNew), a.stream(t, "alice", a.aliceNew)}
		bobOld := a.stream(t, "bob", a.bobOld)

		a.put(t, map[string]Secret{"alice": a.aliceOld, "bob": a.bobNew, "carol": a.carol})

		assert.True(t, a.primaryIs("alice", a.aliceOld), "K1 is the primary")
		assert.False(t, a.accepts("alice", a.aliceNew), "and K2, which the PUT took away, is not accepted")
		assert.Equal(t, []string{untilOf("bob", a.bobUntil)}, a.entries(), "alice's entry is dropped, bob's is not")

		assert.NoError(t, k1.Err(), "K1's stream stays open: its key is the primary now")

		for i, sc := range k2s {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "K2 stream %d closes", i)
		}

		assert.NoError(t, bobOld.Err())

		assert.Equal(t, []string{"info|alice|same_as_primary"}, ignoredLines(t, a.log), "the primary wins: rule 6")
		assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), returnedLine("alice", len(k2s))},
			changeLines(a.log))
		assert.Empty(t, leaks(a.log.text(), a.secrets()))
	})

	for _, tc := range []struct {
		name  string
		apply func(t *testing.T, a *apiRotation)
	}{
		{"a PUT that gives it to another name", func(t *testing.T, a *apiRotation) {
			t.Helper()

			a.put(t, map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": a.aliceOld})
		}},
		{"a POST that gives it to another name", func(t *testing.T, a *apiRotation) {
			t.Helper()

			a.post(t, "carol", a.aliceOld)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := newAPIRotation(t)

			k1, k2 := a.stream(t, "alice", a.aliceOld), a.stream(t, "alice", a.aliceNew)
			carolOld := a.stream(t, "carol", a.carol)
			bobOld := a.stream(t, "bob", a.bobOld)

			tc.apply(t, a)

			assert.True(t, a.primaryIs("carol", a.aliceOld), "the key is carol's primary now")
			assert.True(t, a.accepts("carol", a.aliceOld))
			assert.False(t, a.accepts("alice", a.aliceOld), "and alice no longer accepts it: it is another name's key")
			assert.True(t, a.accepts("alice", a.aliceNew), "alice's primary is untouched")
			assert.Equal(t, []string{untilOf("bob", a.bobUntil)}, a.entries(), "alice's entry is dropped, bob's is not")

			assert.ErrorIs(t, k1.Err(), context.Canceled, "alice's stream on the key closes: she no longer holds it")
			assert.NoError(t, k2.Err())
			assert.ErrorIs(t, carolOld.Err(), context.Canceled, "carol was re-keyed")
			assert.NoError(t, bobOld.Err())

			assert.Equal(t, []string{"warning|alice|key_of_other_secret"}, ignoredLines(t, a.log),
				"a key on another name is a mistake worth a Warning: rule 5")
			assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), removedLine("alice", 1)},
				changeLines(a.log))
			assert.Empty(t, leaks(a.log.text(), a.secrets()))
		})
	}
}

// A3. DELETE /secrets/{name} takes the name's entries with it, and a name added
// again under the same name does not get them back. The drop line is checked for
// the reason A1's is: an entry left in the config handed to the swap would be
// dropped as dangling and the set would come out the same.
func TestDeletingASecretDropsItsEntries(t *testing.T) {
	t.Parallel()

	a := newAPIRotation(t)

	aliceOld := a.stream(t, "alice", a.aliceOld)
	bobOld, bobNew := a.stream(t, "bob", a.bobOld), a.stream(t, "bob", a.bobNew)

	rec := a.call(t, http.MethodDelete, "/secrets/bob", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, []string{untilOf("alice", a.aliceUntil)}, a.entries())
	assert.False(t, a.accepts("bob", a.bobOld))
	assert.ErrorIs(t, bobOld.Err(), context.Canceled)
	assert.ErrorIs(t, bobNew.Err(), context.Canceled)
	assert.NoError(t, aliceOld.Err(), "alice's overlap is not bob's")
	assert.Empty(t, ignoredLines(t, a.log), "the swap is handed no entry of the deleted name")

	a.post(t, "bob", a.bobNew)

	assert.Equal(t, []string{untilOf("alice", a.aliceUntil)}, a.entries(), "adding bob again does not bring his entry back")
	assert.False(t, a.accepts("bob", a.bobOld))
	assert.True(t, a.accepts("bob", a.bobNew))

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), removedLine("bob", 2)}, changeLines(a.log))
	assert.Empty(t, leaks(a.log.text(), a.secrets()))
}

// A4. A POST for another name, new or existing, and a POST of the rotated name's
// own primary (limits and tags change that way) keep every entry: toConfig
// carries them, and nothing about rotation is written, since nothing about it
// changed.
func TestPostingAnotherNameKeepsEveryEntry(t *testing.T) {
	t.Parallel()

	a := newAPIRotation(t)

	aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)
	carol := a.stream(t, "carol", a.carol)

	want := a.entries()
	require.Len(t, want, 2)

	a.post(t, "dave", GenerateSecret("dave.example.com"))
	assert.Equal(t, want, a.entries(), "a new name")

	a.post(t, "carol", GenerateSecret("carol.example.com"))
	assert.Equal(t, want, a.entries(), "another name re-keyed")
	assert.ErrorIs(t, carol.Err(), context.Canceled, "carol's re-key is a re-key: her stream closes")

	a.post(t, "alice", a.aliceNew)
	assert.Equal(t, want, a.entries(), "the rotated name's own primary again")

	assert.True(t, a.accepts("alice", a.aliceOld))
	assert.True(t, a.accepts("bob", a.bobOld))
	assert.NoError(t, aliceOld.Err())
	assert.NoError(t, bobOld.Err())

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil)}, changeLines(a.log))
	assert.Empty(t, ignoredLines(t, a.log))
	assert.Empty(t, leaks(a.log.text(), a.secrets()))
}

// A4, the re-key half. A POST that gives a rotated name a fresh primary -- neither
// its own nor any of its retiring keys -- is a re-key like the panel's: the key it
// takes away closes at once, and the name keeps its overlap. Ending it would be
// the kill the next reload revives, which D17 exists to prevent. The taken-away
// primary does not become an entry, and the build is handed nothing to drop.
func TestPostingAFreshKeyForARotatedNameKeepsItsOverlap(t *testing.T) {
	t.Parallel()

	a := newAPIRotation(t)

	k1 := a.stream(t, "alice", a.aliceOld)
	k2s := []*streamContext{a.stream(t, "alice", a.aliceNew), a.stream(t, "alice", a.aliceNew)}
	bobOld := a.stream(t, "bob", a.bobOld)

	want := a.entries()
	require.Len(t, want, 2)

	k3 := GenerateSecret("alice.example.com")

	a.post(t, "alice", k3)

	assert.True(t, a.primaryIs("alice", k3), "K3 is the primary")
	assert.False(t, a.accepts("alice", a.aliceNew), "K2, which it took away, is not accepted")
	assert.True(t, a.accepts("alice", a.aliceOld), "K1's overlap runs on")
	assert.Equal(t, want, a.entries(), "no entry is added for K2 and none is lost")

	assert.NoError(t, k1.Err(), "K1's stream stays open")

	for i, sc := range k2s {
		assert.ErrorIs(t, sc.Err(), context.Canceled, "K2 stream %d closes: a re-key is immediate", i)
	}

	assert.NoError(t, bobOld.Err())

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil)}, changeLines(a.log),
		"nothing about rotation changed, so nothing about it is written")
	assert.Empty(t, ignoredLines(t, a.log))
	assert.Empty(t, leaks(a.log.text(), append(a.secrets(), k3)))
}

// A5. A PUT cannot re-add an entry a reload removed. The merge reads the set in
// force under reloadMu, after the seam: a reload that ends alice's overlap while
// its until is still ahead -- rotate-secret --end-overlap, then a reload -- runs
// in the seam, and the PUT, whose body was read before it, must not bring the key
// back. The expiry sweep cannot play this part: the build's rule 2 would drop an
// expired entry whatever the merge handed it.
//
// Bob's entry is the other half: the same reload kept it, so the PUT keeps it.
// Without it a merge that keeps nothing would pass.
func TestAPutCannotReAddAnEntryAReloadRemoved(t *testing.T) { //nolint: paralleltest // swaps a package variable
	a := newAPIRotation(t)

	aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)

	// The file after the operator ended alice's overlap: bob's block stays.
	file := a.rotated()
	file.Retiring = []RetiringSecret{retire("bob", a.bobOld, a.bobUntil)}

	a.p.reloader = func() (SecretConfig, error) { return file, nil }

	fired := 0

	installBeforeKeepMergeLockHook(t, func() {
		fired++

		require.True(t, a.accepts("alice", a.aliceOld), "before the reload, the set in force holds alice's old key")
		require.True(t, a.clock.now().Before(a.aliceUntil), "and its until is still ahead")

		// On its own goroutine, with a bound: were the seam ever to run under
		// reloadMu, the reload would wait for the very lock the PUT holds, and the
		// test must fail by name rather than hang the package until its timeout.
		reloaded := make(chan error, 1)

		go func() { reloaded <- a.p.ReloadSecrets() }()

		select {
		case err := <-reloaded:
			require.NoError(t, err)
		case <-time.After(keepMergeBound):
			t.Fatalf("the reload in the seam did not finish within %v: the seam must run before the merge takes reloadMu", keepMergeBound)
		}

		require.False(t, a.accepts("alice", a.aliceOld), "the reload ended the overlap")
	})

	a.put(t, map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": a.carol})

	require.Equal(t, 1, fired, "the seam ran once, before the merge took reloadMu")

	assert.Equal(t, []string{untilOf("bob", a.bobUntil)}, a.entries(), "bob's entry survives; alice's is not re-added")
	assert.False(t, a.accepts("alice", a.aliceOld), "the PUT did not bring the old key back")
	assert.True(t, a.accepts("bob", a.bobOld))
	assert.ErrorIs(t, aliceOld.Err(), context.Canceled, "alice's old key stream was closed by the reload")
	assert.NoError(t, bobOld.Err())

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), removedLine("alice", 1)}, changeLines(a.log),
		"the PUT writes nothing about rotation: no alice line after the reload's")
	assert.Empty(t, ignoredLines(t, a.log))
	assert.Empty(t, leaks(a.log.text(), a.secrets()))
}

// A5, the other half: the merge reads the set UNDER reloadMu, not merely after
// the seam. A5 above runs its reload to the end inside the seam, so a merge that
// read the set after the seam but before taking the lock would see the post-reload
// set and pass it. Here the seam hands reloadMu to another goroutine and returns
// at once: that goroutine holds the lock for a while and then swaps in the file
// that ends alice's overlap (until still ahead) and keeps bob's, as a reload
// does. The PUT, which has read nothing yet, blocks on the lock; a merge that had
// read before blocking would hand the swap alice's entry from the set as it was,
// and the PUT would bring the old key back. Read under the lock, it merges onto
// what the holder left.
//
// The holder's sleep only sets how often a merge that reads before the lock
// loses the race; a merge that reads under it cannot lose, whatever the sleep.
func TestAPutReadsTheSetUnderTheLock(t *testing.T) { //nolint: paralleltest // swaps a package variable
	a := newAPIRotation(t)

	aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)

	// The file after the operator ended alice's overlap: bob's block stays.
	ended := a.rotated()
	ended.Retiring = []RetiringSecret{retire("bob", a.bobOld, a.bobUntil)}

	var (
		fired   int
		locked  = make(chan struct{})
		swapped = make(chan error, 1)
	)

	installBeforeKeepMergeLockHook(t, func() {
		fired++

		require.True(t, a.accepts("alice", a.aliceOld), "before the swap, the set in force holds alice's old key")
		require.True(t, a.clock.now().Before(a.aliceUntil), "and its until is still ahead")

		// No require on this goroutine: only the test's own may fail the test.
		go func() {
			a.p.reloadMu.Lock()
			defer a.p.reloadMu.Unlock()

			close(locked)
			time.Sleep(keepMergeHold)

			swapped <- a.p.swapSecretConfigLocked(ended)
		}()

		// Bounded, like A5's: were the seam to run under reloadMu, the holder could
		// never take it.
		select {
		case <-locked:
		case <-time.After(keepMergeBound):
			t.Fatalf("reloadMu was not free within %v: the seam must run before the merge takes it", keepMergeBound)
		}
	})

	a.put(t, map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": a.carol})

	require.Equal(t, 1, fired, "the seam ran once")
	require.NoError(t, <-swapped, "the holder's swap was applied before the PUT's")

	assert.Equal(t, []string{untilOf("bob", a.bobUntil)}, a.entries(), "bob's entry survives; alice's is not re-added")
	assert.False(t, a.accepts("alice", a.aliceOld), "the PUT did not bring the old key back")
	assert.True(t, a.accepts("bob", a.bobOld))
	assert.ErrorIs(t, aliceOld.Err(), context.Canceled, "alice's old key stream was closed by the holder's swap")
	assert.NoError(t, bobOld.Err())

	assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), removedLine("alice", 1)}, changeLines(a.log),
		"the PUT writes nothing about rotation: no alice line after the holder's")
	assert.Empty(t, ignoredLines(t, a.log))
	assert.Empty(t, leaks(a.log.text(), a.secrets()))
}

// A6. POST /reload replaces the entries with the file's: it never merges, and a
// file with none means none.
func TestReloadReplacesTheEntriesWithTheFiles(t *testing.T) {
	t.Parallel()

	t.Run("the file's entries are the set's, whatever was in memory", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		third := GenerateSecret("alice.example.com")
		thirdUntil := rotationAt(3 * time.Hour)

		file := a.rotated()
		file.Retiring = []RetiringSecret{retire("alice", third, thirdUntil)}

		a.p.reloader = func() (SecretConfig, error) { return file, nil }

		aliceOld, bobOld := a.stream(t, "alice", a.aliceOld), a.stream(t, "bob", a.bobOld)
		aliceNew := a.stream(t, "alice", a.aliceNew)

		rec := a.call(t, http.MethodPost, "/reload", nil)
		require.Equal(t, http.StatusOK, rec.Code)

		assert.Equal(t, []string{untilOf("alice", thirdUntil)}, a.entries())
		assert.True(t, a.accepts("alice", third), "the file's entry is held")
		assert.False(t, a.accepts("alice", a.aliceOld), "the one in memory is not")
		assert.False(t, a.accepts("bob", a.bobOld))
		assert.ErrorIs(t, aliceOld.Err(), context.Canceled)
		assert.ErrorIs(t, bobOld.Err(), context.Canceled)
		assert.NoError(t, aliceNew.Err())
		assert.Empty(t, leaks(a.log.text(), append(a.secrets(), third)))
	})

	t.Run("a file with no entries means none", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		file := a.rotated()
		file.Retiring = nil

		a.p.reloader = func() (SecretConfig, error) { return file, nil }

		aliceOld, aliceNew := a.stream(t, "alice", a.aliceOld), a.stream(t, "alice", a.aliceNew)

		rec := a.call(t, http.MethodPost, "/reload", nil)
		require.Equal(t, http.StatusOK, rec.Code)

		assert.Empty(t, a.entries())
		assert.ErrorIs(t, aliceOld.Err(), context.Canceled)
		assert.NoError(t, aliceNew.Err())
		assert.Equal(t, []string{addedLine("alice", a.aliceUntil), addedLine("bob", a.bobUntil), removedLine("alice", 1), removedLine("bob", 0)},
			changeLines(a.log))
	})
}

// A panel re-key is immediate. The panel's PUT states a new key for a name and
// nothing else: the old primary's streams close at once, and the old primary is
// not kept as a retiring entry -- an overlap is something the file grants. With
// an overlap already in force the name's entry survives the PUT, and the key the
// PUT took away does not join it.
func TestAPanelRekeyIsStillImmediate(t *testing.T) {
	t.Parallel()

	t.Run("no overlap in force", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		// carol has no entry: re-key her.
		carolOld := a.stream(t, "carol", a.carol)
		carolNext := GenerateSecret("carol.example.com")

		a.put(t, map[string]Secret{"alice": a.aliceNew, "bob": a.bobNew, "carol": carolNext})

		assert.ErrorIs(t, carolOld.Err(), context.Canceled, "the old key's stream is closed at once")
		assert.False(t, a.accepts("carol", a.carol), "and the old key is not accepted")
		assert.True(t, a.accepts("carol", carolNext))
		assert.Equal(t, []string{untilOf("alice", a.aliceUntil), untilOf("bob", a.bobUntil)}, a.entries(),
			"no entry is created for carol; the other names keep theirs")
	})

	t.Run("the only secret, no entry anywhere", func(t *testing.T) {
		t.Parallel()

		old, next := GenerateSecret("alice.example.com"), GenerateSecret("alice.example.com")

		p := newAPITestProxy(map[string]Secret{"alice": old})
		rotationClockAt(p, rotationNow)

		stream := registerOnKey(t, p, "alice", old.Key)

		body := `{"secrets":{"alice":{"secret":"` + next.Hex() + `"}}}`
		rec := doAPI(t, p, "", http.MethodPut, "/secrets", body)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

		assert.ErrorIs(t, stream.Err(), context.Canceled)
		assert.Zero(t, heldRetiring(p), "the old key is not an entry")
		assert.True(t, p.secrets.Load().retiringNext.IsZero())
		assert.False(t, p.secrets.Load().accepts("alice", old.Key[:], rotationNow))
	})

	t.Run("an overlap in force", func(t *testing.T) {
		t.Parallel()

		a := newAPIRotation(t)

		k1 := a.stream(t, "alice", a.aliceOld)
		k2s := []*streamContext{a.stream(t, "alice", a.aliceNew), a.stream(t, "alice", a.aliceNew)}

		k3 := GenerateSecret("alice.example.com")

		a.put(t, map[string]Secret{"alice": k3, "bob": a.bobNew, "carol": a.carol})

		assert.True(t, a.primaryIs("alice", k3), "the PUT's key is the primary")
		assert.False(t, a.accepts("alice", a.aliceNew), "K2, the primary it took away, is not accepted")

		for i, sc := range k2s {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "K2 stream %d is closed at once", i)
		}

		assert.True(t, a.accepts("alice", a.aliceOld), "K1's entry survives the PUT")
		assert.NoError(t, k1.Err())
		assert.Equal(t, []string{untilOf("alice", a.aliceUntil), untilOf("bob", a.bobUntil)}, a.entries(),
			"two entries still: K2 did not become a third")
		assert.Empty(t, ignoredLines(t, a.log))
		assert.Empty(t, leaks(a.log.text(), append(a.secrets(), k3)))
	})
}

// D18. There is no rotate route: a route that set a new primary the file does not
// hold would make the leaked key the primary again at the next reload. The
// request answers 404, not 405, so no method of any route answers on that path,
// and it changes nothing. The call carries no token, so authentication cannot be
// the reason it fails.
func TestThereIsNoRotateRoute(t *testing.T) {
	t.Parallel()

	a := newAPIRotation(t)

	before := a.p.secrets.Load()

	for _, body := range []any{nil, map[string]string{"secret": GenerateSecret("alice.example.com").Hex()}} {
		rec := a.call(t, http.MethodPost, "/secrets/alice/rotate", body)

		assert.Equal(t, http.StatusNotFound, rec.Code, "POST /secrets/alice/rotate is not a route")
	}

	assert.True(t, a.p.secrets.Load() == before, "and it swapped nothing")
}
