package cli

import (
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C16. The doctor reads the [[retiring-secret]] table as run --check does, at
// the wall clock: a problem or a warning in it fails the verdict, as an unknown
// key does, and expired entries alone do not -- they are counted, with the way
// to remove them. Its output names entries, never their keys.
func TestDoctorFailsOnARetiringLineButNotOnExpiredEntries(t *testing.T) {
	t.Parallel()

	const ours = "203.0.113.7"

	cover, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Cleanup, not defer: the subtests are parallel and outlive this function.
	t.Cleanup(func() { cover.Close() }) //nolint: errcheck

	_, port, err := net.SplitHostPort(cover.Addr().String())
	require.NoError(t, err)

	dc := startFakeDC(t)
	resolver := fakeResolver{doctorSecretHost: {ours}}

	// Everything TestDoctorDiagnose calls healthy, plus the blocks. A failing
	// verdict here can come from the retiring check alone.
	healthy := func(blocks ...string) string {
		extra := "[domain-fronting]\nhost = \"127.0.0.1\"\nport = " + port + "\n\n"
		for _, block := range blocks {
			extra += block
		}

		return doctorConfig(extra)
	}

	old := mtglib.GenerateSecret("old.example.com")
	older := mtglib.GenerateSecret("old.example.com")

	diagnoseOver := func(t *testing.T, raw string) (bool, string) {
		t.Helper()

		d, out := newDoctor(t, raw, time.Second, nil)
		ntw := &doctorNetwork{dial: toFakeDC(dc), publicIP: map[string]string{"tcp4": ours}}

		ok, err := d.diagnose(ntw, resolver)
		require.NoError(t, err)
		assert.Contains(t, out.String(), "Retiring secrets")
		require.Empty(t, retiringLeaks(out.String(), old, older), "the doctor printed a key")

		return ok, out.String()
	}

	const tail = "; the entry is ignored and its key is not accepted"

	t.Run("a problem fails the verdict", func(t *testing.T) {
		t.Parallel()

		ok, out := diagnoseOver(t, healthy(retiringBlock("default", old, "tomorrow")))

		assert.False(t, ok, "a retiring problem must fail the doctor's verdict")
		assert.Contains(t, out, `⚠️  retiring-secret #1 (name "default"): until is not an RFC 3339 date-time with an offset, `+
			`such as 2026-10-09T09:30:00Z`+tail)
	})

	t.Run("a warning fails the verdict", func(t *testing.T) {
		t.Parallel()

		ok, out := diagnoseOver(t, healthy(retiringBlock("default", old, rfc3339(time.Now().Add(800*time.Hour)))))

		assert.False(t, ok, "an over-long until must fail the doctor's verdict")
		assert.Contains(t, out, `retiring-secret #1 (name "default"): until is more than 720h away`)
	})

	t.Run("expired entries alone do not", func(t *testing.T) {
		t.Parallel()

		ok, out := diagnoseOver(t, healthy(
			retiringBlock("default", old, "2020-01-01T00:00:00Z"),
			retiringBlock("default", older, "2020-06-01T00:00:00+03:00")))

		assert.True(t, ok, "expired entries must not fail the doctor's verdict")
		assert.Contains(t, out, "✅ No retiring-secret entry has a problem")
		assert.Contains(t, out, "2 retiring-secret entries are past their until and ignored; rotate-secret --prune removes them")
		assert.NotContains(t, out, "⚠️")
	})

	t.Run("an unexpired entry passes", func(t *testing.T) {
		t.Parallel()

		ok, out := diagnoseOver(t, healthy(retiringBlock("default", old, rfc3339(time.Now().Add(24*time.Hour)))))

		assert.True(t, ok)
		assert.Contains(t, out, "✅ No retiring-secret entry has a problem")
		assert.NotContains(t, out, "--prune", "no expired entry, no hint")
	})

	t.Run("the check itself", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, healthy(
			retiringBlock("carol", old, rfc3339(time.Now().Add(24*time.Hour))),
			retiringBlock("default", older, "2020-01-01T00:00:00Z")), time.Second, nil)

		assert.False(t, d.checkRetiringSecrets())
		assert.Contains(t, out.String(), `⚠️  retiring-secret #1 (name "carol"): name is not a configured secret`+tail)
		assert.Contains(t, out.String(), "1 retiring-secret entry is past its until and ignored; rotate-secret --prune removes it")
		assert.NotContains(t, out.String(), "✅")
		require.Empty(t, retiringLeaks(out.String(), old, older), "the doctor printed a key")
	})
}
