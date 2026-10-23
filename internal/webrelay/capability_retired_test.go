package webrelay

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// Task 11. The relay recognises the capability of a retired key, so that a
// holder of the old WEB link is answered by the same local 404 as any
// authentic-but-unusable capability -- and is never handed to the cover site,
// which for cover-upstream is a third party's access log.
//
// Nothing here prints a capability or a secret: a Capability's key bytes and a
// Secret's String() (its value) are credentials, so every assertion compares
// booleans, counts and the three outcomes below.

// The three key families of these tests. A family's i-th secret has the family
// tag, then i as a 16-bit number, so two secrets never share a key unless a
// test copies one, and none is all zero.
const (
	liveFamily     byte = 0x11
	retiredFamily  byte = 0x22
	strangerFamily byte = 0x33
	freshFamily    byte = 0x44
)

func indexedSecret(family byte, index int) mtglib.Secret {
	secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
	secret.Key[0] = family
	secret.Key[1] = byte(index >> 8)
	secret.Key[2] = byte(index)

	return secret
}

func indexedSecrets(family byte, count int) []mtglib.Secret {
	secrets := make([]mtglib.Secret, 0, count)

	for i := range count {
		secrets = append(secrets, indexedSecret(family, i))
	}

	return secrets
}

// asEE is the same key spelled the way a panel mints it, as an ee secret.
func asEE(secret mtglib.Secret) mtglib.Secret {
	return mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com", Key: secret.Key}
}

// retiringBlockFor is the [[retiring-secret]] block of a key: its ee value, in
// hex, and the instant it stops being accepted.
func retiringBlockFor(secret mtglib.Secret, until string) string {
	return fmt.Sprintf("[[retiring-secret]]\nname = %q\nsecret = %q\nuntil = %q\n\n", "alice", asEE(secret).Hex(), until)
}

// W5: with 4,096 live and 4,096 retired capabilities the recognition scan
// visits all 8,192 whichever one matches, or none does.
//
// What this proves: every capability of both lists is visited, and there is no
// break. The count is taken inside ctEqual, the helper that also makes the
// compare, so a scan that stops at a match, or that skips the compare once
// something matched, reports fewer than 8,192 and fails here.
//
// What it cannot prove: any count the function under test reports about itself
// can be made to lie (an early return of len(live)+len(retired) passes), and
// this test does not claim otherwise. That is for review, and for a timing
// measurement if the scan's timing ever matters.
//
// A value that does not even parse is refused before the scan and depends only
// on the prober's own input.
func TestTheScanVisitsEveryCapabilityOfBothLists(t *testing.T) {
	t.Parallel()

	live := indexedSecrets(liveFamily, MaxProfiles)
	retired := indexedSecrets(retiredFamily, MaxProfiles)

	registry, err := NewRegistryWithRetired(originHost, live, retired)
	require.NoError(t, err)
	require.Equal(t, MaxProfiles, registry.Len(), "the retired list must not count as profiles")
	// len, not require.Len: a failure of Len would print every capability.
	require.Equal(t, MaxProfiles, len(registry.retired), "the whole retired list is held")

	const bound = 2 * MaxProfiles

	for name, probe := range map[string]struct {
		secret mtglib.Secret
		found  bool
	}{
		"the first live":     {live[0], true},
		"a middle live":      {live[MaxProfiles/2], true},
		"the last live":      {live[MaxProfiles-1], true},
		"the first retired":  {retired[0], true},
		"a middle retired":   {retired[MaxProfiles/2], true},
		"the last retired":   {retired[MaxProfiles-1], true},
		"neither list":       {indexedSecret(strangerFamily, 0), false},
		"the live neighbour": {indexedSecret(liveFamily, MaxProfiles), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			found, compares := registry.authentic(webCapability(t, probe.secret))

			require.Equal(t, probe.found, found, "recognition")
			require.Equal(t, bound, compares, "the scan must visit every live and every retired capability")
			require.Equal(t, probe.found, registry.IsAuthentic(webCapability(t, probe.secret)))
		})
	}

	found, compares := registry.authentic("not-a-capability")
	require.False(t, found)
	require.Zero(t, compares, "a value that does not parse is refused before the scan")
}

// The scan allocates the same however long the retired list is: the compare
// counter lives on the stack, and a retired capability costs a compare, not an
// allocation. Not parallel: AllocsPerRun cannot run in a parallel test.
func TestTheScanAllocatesNothingPerCapability(t *testing.T) {
	live := indexedSecrets(liveFamily, 4)

	none, err := NewRegistryWithRetired(originHost, live, nil)
	require.NoError(t, err)

	many, err := NewRegistryWithRetired(originHost, live, indexedSecrets(retiredFamily, MaxProfiles))
	require.NoError(t, err)

	for name, probe := range map[string]string{
		"a live capability":    webCapability(t, live[3]),
		"a retired capability": webCapability(t, indexedSecret(retiredFamily, MaxProfiles-1)),
		"an unknown one":       webCapability(t, indexedSecret(strangerFamily, 0)),
	} {
		without := testing.AllocsPerRun(20, func() { none.IsAuthentic(probe) })
		with := testing.AllocsPerRun(20, func() { many.IsAuthentic(probe) })

		require.InDelta(t, without, with, 0, "%s: a 4096-long retired list changed the allocations of one scan", name)
	}
}

// The cap keeps the LATEST grants. A long-lived file can hold thousands of
// expired blocks that nobody pruned (an expired block is inert, not deleted) and
// a rotation writes its block after them, so a cap that kept the first values in
// file order would leave the newest retirements out -- and the holders of those
// just-retired links, the ones most likely to present them, would be forwarded
// to the cover site. RetiringValues orders by until, latest first, so the
// registry's cut keeps the grants that expire last.
//
// The file here is real: 4,500 old blocks, then ten fresh ones, loaded through
// the config and the registry, and each fresh link derived on its own.
func TestTheNewestRetirementsSurviveTheCap(t *testing.T) {
	t.Parallel()

	const (
		stale = 4500
		fresh = 10
	)

	var file strings.Builder

	file.WriteString("bind-to = \"0.0.0.0:3128\"\n\n")

	for i := range stale {
		file.WriteString(retiringBlockFor(indexedSecret(retiredFamily, i), "2000-01-01T00:00:00Z"))
	}

	for i := range fresh {
		file.WriteString(retiringBlockFor(indexedSecret(freshFamily, i), "2999-01-01T00:00:00Z"))
	}

	file.WriteString("[secrets]\nalice = \"" + asEE(indexedSecret(liveFamily, 0)).Hex() + "\"\n")

	conf, err := config.Parse([]byte(file.String()))
	require.NoError(t, err)

	values := conf.RetiringValues()
	require.Equal(t, stale+fresh, len(values), "every block that passes rule 1 gives its value")

	registry, err := NewRegistryWithRetired(originHost, indexedSecrets(liveFamily, 1), values)
	require.NoError(t, err)
	require.Equal(t, MaxProfiles, len(registry.retired), "the cap was reached")

	for i := range fresh {
		found, _ := registry.authentic(webCapability(t, indexedSecret(freshFamily, i)))
		require.True(t, found, "fresh retirement %d was left out by the cap", i)
	}
}

// W4: a retired capability equal to a live one is dropped, and the live one
// serves. Dropped is observable only through the scan, because the two answer
// alike, so the compare count says how many capabilities the registry holds.
func TestACollidingRetiredCapabilityKeepsTheLiveOne(t *testing.T) {
	t.Parallel()

	live := indexedSecrets(liveFamily, 2)
	other := indexedSecret(retiredFamily, 0)

	// The live key again as a retired value, in two spellings (dd and the ee a
	// panel mints), and the second live one: all collide, and only `other` is a
	// retired capability of its own.
	registry, err := NewRegistryWithRetired(originHost, live, []mtglib.Secret{live[0], asEE(live[0]), other, live[1]})
	require.NoError(t, err)

	found, compares := registry.authentic(webCapability(t, other))
	require.True(t, found)
	require.Equal(t, len(live)+1, compares, "a colliding retired capability was kept beside the live one")

	for i, secret := range live {
		index, ok := registry.Lookup(webCapability(t, secret))
		require.True(t, ok, "the live capability stopped resolving")
		require.Equal(t, i, index, "the live capability resolves to another profile")
	}
}

// The relay must not refuse to start, or to reload, over a retired list: it is
// read from a file that can hold duplicates (a rule-5 or rule-7 file), more
// than 4,096 values, a value equal to a live one, and a value that cannot be
// derived. None of them is the operator's relay being unusable, so the list is
// trimmed in silence. Only the live list keeps the registry's errors.
func TestAnInertRetiredListNeverRefusesTheRelay(t *testing.T) {
	t.Parallel()

	live := indexedSecrets(liveFamily, 1)
	first := indexedSecret(retiredFamily, 0)
	second := indexedSecret(retiredFamily, 1)
	distinct := indexedSecrets(retiredFamily, MaxProfiles+1)

	for name, probe := range map[string]struct {
		retired []mtglib.Secret
		kept    int
	}{
		"none":                           {nil, 0},
		"an empty list":                  {[]mtglib.Secret{}, 0},
		"duplicates":                     {[]mtglib.Secret{first, first, second, first}, 2},
		"a duplicate in another form":    {[]mtglib.Secret{first, asEE(first)}, 1},
		"4097 values":                    {distinct, MaxProfiles},
		"4097 values with a duplicate":   {append(indexedSecrets(retiredFamily, MaxProfiles), first), MaxProfiles},
		"a duplicate and 4096 more":      {append([]mtglib.Secret{first}, distinct...), MaxProfiles},
		"a value equal to a live one":    {[]mtglib.Secret{live[0], first}, 1},
		"a live value in another form":   {[]mtglib.Secret{asEE(live[0]), first}, 1},
		"nothing but live values":        {[]mtglib.Secret{live[0], asEE(live[0])}, 0},
		"a value that cannot be derived": {[]mtglib.Secret{{Mode: mtglib.SecretModeDD}, first}, 1},
		"an ee value":                    {[]mtglib.Secret{asEE(first)}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistryWithRetired(originHost, live, probe.retired)
			require.NoError(t, err, "a retired list refused the registry")
			require.Equal(t, len(live), registry.Len())

			found, compares := registry.authentic(webCapability(t, live[0]))
			require.True(t, found)
			require.Equal(t, len(live)+probe.kept, compares, "the retired list kept the wrong number of capabilities")
		})
	}

	// The cap keeps the first 4,096 in the list's order and leaves the rest out.
	registry, err := NewRegistryWithRetired(originHost, live, distinct)
	require.NoError(t, err)

	found, _ := registry.authentic(webCapability(t, distinct[MaxProfiles-1]))
	require.True(t, found, "the 4096th retired value is held")

	found, _ = registry.authentic(webCapability(t, distinct[MaxProfiles]))
	require.False(t, found, "the 4097th retired value is left out")
}

// Only the live list keeps NewRegistry's errors, and a retired list changes
// none of them.
func TestOnlyTheLiveListKeepsTheRegistrysErrors(t *testing.T) {
	t.Parallel()

	retired := indexedSecrets(retiredFamily, 3)

	_, err := NewRegistryWithRetired(originHost, nil, retired)
	require.ErrorIs(t, err, ErrNoProfiles, "retired capabilities are not profiles")

	_, err = NewRegistryWithRetired(originHost, indexedSecrets(liveFamily, MaxProfiles+1), retired)
	require.ErrorIs(t, err, ErrTooManyProfiles)

	live := indexedSecrets(liveFamily, 2)
	_, err = NewRegistryWithRetired(originHost, []mtglib.Secret{live[0], live[0]}, retired)
	require.ErrorIs(t, err, ErrCapabilityCollision)

	_, err = NewRegistryWithRetired(originHost, []mtglib.Secret{live[0], {Mode: mtglib.SecretModeDD}}, retired)
	require.ErrorIs(t, err, ErrInvalidSecret)

	_, err = NewRegistryWithRetired("localhost", live, retired)
	require.ErrorIs(t, err, ErrInvalidHost)
}

// NewRegistry is NewRegistryWithRetired with nothing retired, and a registry
// with a retired list still answers Len and Lookup for the live list alone.
func TestARetiredListIsNeverAProfile(t *testing.T) {
	t.Parallel()

	live := indexedSecrets(liveFamily, 3)
	retired := indexedSecrets(retiredFamily, 2)

	plain, err := NewRegistry(originHost, live)
	require.NoError(t, err)
	require.Zero(t, len(plain.retired), "NewRegistry holds no retired list")

	found, compares := plain.authentic(webCapability(t, live[2]))
	require.True(t, found)
	require.Equal(t, len(live), compares)

	registry, err := NewRegistryWithRetired(originHost, live, retired)
	require.NoError(t, err)
	require.Equal(t, len(live), registry.Len())

	for _, secret := range retired {
		capability := webCapability(t, secret)

		_, ok := registry.Lookup(capability)
		require.False(t, ok, "a retired capability resolved to a profile")
		require.True(t, registry.IsAuthentic(capability), "a retired capability is recognised")
	}
}

// What the client receives, which is how the three tiers are told apart.
const (
	servedBridge  = "the bridge"
	localNotFound = "a local 404"
	servedCover   = "the cover site"
)

// coverTap is a cover site that counts the requests that reach it.
type coverTap struct {
	hits atomic.Int64
}

func (c *coverTap) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.hits.Add(1)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, coverMarker)
}

// retiredOrigin is an origin over live profiles with a retired list and a cover
// site that counts what reaches it.
func retiredOrigin(t *testing.T, live, retired []mtglib.Secret) (*Origin, *coverTap, *Counters) {
	t.Helper()

	signer, err := NewSigner(bytes.Repeat([]byte{7}, TokenKeySize))
	require.NoError(t, err)

	tap := &coverTap{}
	counters := NewCounters(time.Now())

	origin, err := NewOrigin(OriginOptions{
		Host:     originHost,
		Secrets:  live,
		Retired:  retired,
		Signer:   signer,
		Cover:    tap,
		Backend:  newPipeBackend(),
		Counters: counters,
	})
	require.NoError(t, err)

	return origin, tap, counters
}

// outcome sends a request and says which of the three things answered it.
func outcome(t *testing.T, origin *Origin, request *http.Request) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	origin.ServeHTTP(recorder, request)

	body := recorder.Body.String()

	switch {
	case recorder.Code == http.StatusOK && strings.Contains(body, "TPROXY_BOOT"):
		return servedBridge
	case recorder.Code == http.StatusOK && body == coverMarker:
		return servedCover
	case recorder.Code == http.StatusNotFound && recorder.Header().Get("Cache-Control") == "no-store" &&
		body == "404 page not found\n":
		return localNotFound
	default:
		t.Fatalf("an answer none of the three tiers gives: status %d", recorder.Code)

		return ""
	}
}

func getBridge(t *testing.T, origin *Origin, capability string) string {
	t.Helper()

	return outcome(t, origin, httptest.NewRequest(http.MethodGet, "/?bridge="+capability, nil))
}

// W1: a retired capability, however it arrives, gets the local 404 and never
// reaches the cover site. Expired or not is the config's judgement, not the
// relay's (it has no clock): the end-to-end half of "expired" is in the CLI
// package's tests, which load a real file.
func TestARetiredCapabilityIsAnsweredLocallyNeverByTheCoverSite(t *testing.T) {
	t.Parallel()

	live := indexedSecret(liveFamily, 0)
	retiredDD := indexedSecret(retiredFamily, 0)
	retiredEE := asEE(indexedSecret(retiredFamily, 1))

	origin, tap, counters := retiredOrigin(t, []mtglib.Secret{asEE(live)}, []mtglib.Secret{retiredDD, retiredEE})

	requests := 0

	for name, secret := range map[string]mtglib.Secret{"a dd value": retiredDD, "an ee value": retiredEE} {
		capability := webCapability(t, secret)

		raw, err := base64.RawURLEncoding.DecodeString(capability)
		require.NoError(t, err)

		for shape, request := range map[string]*http.Request{
			"exact":                 httptest.NewRequest(http.MethodGet, "/?bridge="+capability, nil),
			"percent-encoded":       httptest.NewRequest(http.MethodGet, "/?bridge=%"+hexOf(capability[0])+capability[1:], nil),
			"on the wrong path":     httptest.NewRequest(http.MethodGet, "/somewhere?bridge="+capability, nil),
			"with the wrong method": httptest.NewRequest(http.MethodPost, "/?bridge="+capability, nil),
			"under another name":    httptest.NewRequest(http.MethodGet, "/?b="+capability, nil),
			"with an extra field":   httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"&x=1", nil),
			"duplicated":            httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"&bridge="+capability, nil),
			"padded":                httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"%3D", nil),
			"padded standard": httptest.NewRequest(http.MethodGet,
				"/?bridge="+escape(base64.StdEncoding.EncodeToString(raw)), nil),
		} {
			require.Equal(t, localNotFound, outcome(t, origin, request), "%s, %s", name, shape)

			requests++
		}

		header := httptest.NewRequest(http.MethodGet, "/some/page", nil)
		header.Header.Set("X-Something", "prefix "+capability)
		require.Equal(t, localNotFound, outcome(t, origin, header), "%s, in a header", name)

		requests++
	}

	require.Zero(t, tap.hits.Load(), "a retired capability reached the cover site")
	require.Equal(t, int64(requests), counters.Snapshot(time.Now(), 0, 0).Refused.NotFound)
	require.Zero(t, counters.Snapshot(time.Now(), 0, 0).Refused.CoverServed)

	// The controls: the recognition is not a blanket 404. A live capability is
	// served, and a capability nobody holds is the website.
	require.Equal(t, servedBridge, getBridge(t, origin, webCapability(t, live)))
	require.Equal(t, servedCover, getBridge(t, origin, webCapability(t, indexedSecret(strangerFamily, 0))))
	require.EqualValues(t, 1, tap.hits.Load())
}

// W2: a retired capability never serves the bridge, in the exact shape that
// serves a live one. Lookup is live-only; an index into the profiles for a key
// that is no longer one would hand the old holder a session.
func TestARetiredCapabilityNeverServesTheBridge(t *testing.T) {
	t.Parallel()

	live := indexedSecret(liveFamily, 0)
	retired := indexedSecret(retiredFamily, 0)

	origin, _, _ := retiredOrigin(t, []mtglib.Secret{live}, []mtglib.Secret{retired})

	require.Equal(t, localNotFound, getBridge(t, origin, webCapability(t, retired)))
	require.Equal(t, servedBridge, getBridge(t, origin, webCapability(t, live)))
	require.Equal(t, 1, origin.Profiles(), "a retired capability is not a profile")
}

// The swap is whole. A rotation moves a key from the live list to the retired
// one in one write, and the relay must change over in one step: between the
// two the old link would otherwise fall to the cover site.
func TestSetSecretsWithRetiredSwapsTheRetiredListWhole(t *testing.T) {
	t.Parallel()

	oldKey := indexedSecret(retiredFamily, 0)
	newKey := indexedSecret(liveFamily, 0)
	other := indexedSecret(strangerFamily, 0)

	origin, tap, _ := retiredOrigin(t, []mtglib.Secret{oldKey}, nil)

	oldCapability := webCapability(t, oldKey)
	newCapability := webCapability(t, newKey)

	require.Equal(t, servedBridge, getBridge(t, origin, oldCapability), "the old key serves before the rotation")
	require.Equal(t, servedCover, getBridge(t, origin, newCapability))
	require.EqualValues(t, 1, tap.hits.Load())

	// The rotation: the new key is the profile, the old one is retired, in one
	// swap.
	require.NoError(t, origin.SetSecretsWithRetired([]mtglib.Secret{newKey}, []mtglib.Secret{oldKey}))
	require.Equal(t, 1, origin.Profiles())
	require.Equal(t, servedBridge, getBridge(t, origin, newCapability))
	require.Equal(t, localNotFound, getBridge(t, origin, oldCapability), "the old link must not reach the cover site")
	require.EqualValues(t, 1, tap.hits.Load(), "the cover site was reached during the rotation")

	// A set that cannot be served is refused whole: the previous profiles and
	// the previous retired list both stay.
	require.Error(t, origin.SetSecretsWithRetired(nil, []mtglib.Secret{other}))
	require.Equal(t, localNotFound, getBridge(t, origin, oldCapability), "a refused swap dropped the retired list")
	require.Equal(t, servedCover, getBridge(t, origin, webCapability(t, other)), "a refused swap took in its retired list")

	// An empty retired list ends the recognition (a --prune): the old link is
	// an unknown capability again.
	require.NoError(t, origin.SetSecretsWithRetired([]mtglib.Secret{newKey}, nil))
	require.Equal(t, servedCover, getBridge(t, origin, oldCapability))

	// SetSecrets is the nil form of the same call.
	require.NoError(t, origin.SetSecretsWithRetired([]mtglib.Secret{newKey}, []mtglib.Secret{oldKey}))
	require.Equal(t, localNotFound, getBridge(t, origin, oldCapability))
	require.NoError(t, origin.SetSecrets([]mtglib.Secret{newKey}))
	require.Equal(t, servedCover, getBridge(t, origin, oldCapability))
}
