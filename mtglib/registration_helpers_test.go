package mtglib

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// attributeFromSet gives a hand-built stream what attribute gives a real one,
// as far as the registration re-check reads it: the key its secret had in the
// set stored now, and that set as the one it matched against. Registration
// refuses a stream whose key the set no longer accepts, so a helper that builds
// a stream by hand must attribute it as a door would, from the set the proxy
// holds when the stream is built.
//
// With no set stored it leaves both nil, as a door never could: there is
// nothing to match against. The re-check then compares two nil sets and is
// skipped, so a probe that never stores a set registers as it always did.
func attributeFromSet(t testing.TB, p *Proxy, sc *streamContext) {
	t.Helper()

	set := p.secrets.Load()
	if set == nil {
		return
	}

	i, found := slices.BinarySearch(set.names, sc.secretName)
	if !found {
		t.Fatalf("the stored secret set has no secret named %q", sc.secretName)
	}

	sc.matchedSecretKey = set.secrets[i].Key[:]
	sc.attrSet = set
}

// registerFakeStream registers a stream of name that has no socket and no
// handshake, attributed from the set the proxy holds now, and requires that it
// registered: a test that reads such a stream's fate after a reload is only
// about something if the stream was in the registry to begin with.
func registerFakeStream(t testing.TB, p *Proxy, name string) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	sc := &streamContext{ctx: ctx, ctxCancel: cancel, secretName: name}

	attributeFromSet(t, p, sc)

	// A fake stream has no client socket, so it registers uncounted: the
	// address ledger is exercised by the entry tests, not by these.
	require.Equal(t, DenyNone, p.tryRegisterConn(sc), "the fake stream of %s must register", name)

	return sc
}

// installAfterAttributeHook replaces the seam ServeConn calls between a
// successful entry and admission, and puts it back. The seam is a package
// variable, so a test that uses it is not parallel. The hook runs on the
// stream's own goroutine: it must not call require, and a test reads what it
// recorded only once that goroutine has finished.
func installAfterAttributeHook(t *testing.T, hook func(*streamContext)) {
	t.Helper()

	previous := afterAttributeHook
	afterAttributeHook = hook

	t.Cleanup(func() { afterAttributeHook = previous })
}

// installBeforeRegisterLockHook replaces the seam tryRegisterConn calls just
// before it takes liveMu, and puts it back. The seam is a package variable, so
// a test that uses it is not parallel.
func installBeforeRegisterLockHook(t *testing.T, hook func(*streamContext)) {
	t.Helper()

	previous := beforeRegisterLockHook
	beforeRegisterLockHook = hook

	t.Cleanup(func() { beforeRegisterLockHook = previous })
}
