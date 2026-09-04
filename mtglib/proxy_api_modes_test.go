package mtglib

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustSecretMode is GenerateSecretMode for a test that has no interest in the
// error arm.
func mustSecretMode(t *testing.T, mode SecretMode) Secret {
	t.Helper()

	secret, err := GenerateSecretMode(mode, "")
	require.NoError(t, err)

	return secret
}

// modeTestProxy builds an API test proxy whose listener union is modes. That
// union is the only input to the unserved predicate, so a test sets it directly
// instead of standing up real sockets.
func modeTestProxy(secrets map[string]Secret, modes ModeSet) *Proxy {
	p := newAPITestProxy(secrets)
	p.listenerModes = modes

	return p
}

// getSecretInfos decodes GET /secrets into a name-keyed map.
func getSecretInfos(t *testing.T, p *Proxy) map[string]SecretInfo {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, "/secrets", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Secrets []SecretInfo `json:"secrets"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	out := make(map[string]SecretInfo, len(resp.Secrets))
	for _, info := range resp.Secrets {
		out[info.Name] = info
	}

	return out
}

// secretsRaw decodes GET /secrets loosely, so the test sees the wire shape -
// field names and JSON types - rather than whatever SecretInfo accepts today.
func secretsRaw(t *testing.T, p *Proxy) map[string]map[string]any {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, "/secrets", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw struct {
		Secrets []map[string]any `json:"secrets"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	out := make(map[string]map[string]any, len(raw.Secrets))
	for _, entry := range raw.Secrets {
		name, _ := entry["name"].(string)
		out[name] = entry
	}

	return out
}

func TestSecretsAPIReportsMode(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   mustSecretMode(t, SecretModeDD),
		"carol": mustSecretMode(t, SecretModePlain),
	}

	t.Run("every wire form names itself", func(t *testing.T) {
		t.Parallel()

		infos := getSecretInfos(t, modeTestProxy(secrets, ModeSetOf(SecretModeDD, SecretModePlain)))

		assert.Equal(t, "ee", infos["alice"].Mode)
		assert.Equal(t, "dd", infos["bob"].Mode)
		assert.Equal(t, "plain", infos["carol"].Mode)
	})

	t.Run("the secret string of each form round-trips", func(t *testing.T) {
		t.Parallel()

		infos := getSecretInfos(t, modeTestProxy(secrets, 0))

		for name, secret := range secrets {
			parsed, err := ParseSecret(infos[name].Secret)
			require.NoError(t, err)
			assert.Equal(t, secret, parsed)
		}
	})

	t.Run("mode is always present, never omitted", func(t *testing.T) {
		t.Parallel()

		raw := secretsRaw(t, modeTestProxy(secrets, 0))

		for _, name := range []string{"alice", "bob", "carol"} {
			require.Contains(t, raw[name], "mode")
			assert.IsType(t, "", raw[name]["mode"])
		}
	})
}

// TestSecretsAPIUnserved pins the predicate to tag-set CONTAINMENT, which is
// what mtglib.NewProxy's startup warning uses. "Is there any obfuscated
// listener" would pass every row here except the one that matters: a dd-only
// listener honours padded-intermediate alone, and a plain client is free to pick
// abridged or intermediate, so it is not served.
func TestSecretsAPIUnserved(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   mustSecretMode(t, SecretModeDD),
		"carol": mustSecretMode(t, SecretModePlain),
	}

	for _, tc := range []struct {
		name  string
		modes ModeSet
		want  map[string]bool
	}{
		{
			name:  "no listener leaves both hostless forms without a door",
			modes: 0,
			want:  map[string]bool{"alice": false, "bob": true, "carol": true},
		},
		{
			name:  "a dd-only listener does not cover a plain secret",
			modes: ModeSetOf(SecretModeDD),
			want:  map[string]bool{"alice": false, "bob": false, "carol": true},
		},
		{
			name:  "a plain listener covers a dd secret too",
			modes: ModeSetOf(SecretModePlain),
			want:  map[string]bool{"alice": false, "bob": false, "carol": false},
		},
		{
			name:  "both accepted serves both",
			modes: ModeSetOf(SecretModeDD, SecretModePlain),
			want:  map[string]bool{"alice": false, "bob": false, "carol": false},
		},
		{
			name:  "an ee-only listener union never marks the ee secret unserved",
			modes: ModeSetOf(SecretModeFakeTLS),
			want:  map[string]bool{"alice": false, "bob": true, "carol": true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := modeTestProxy(secrets, tc.modes)
			infos := getSecretInfos(t, p)
			raw := secretsRaw(t, p)

			for name, want := range tc.want {
				assert.Equal(t, want, infos[name].Unserved, "secret %q", name)

				// False is the overwhelmingly common case and must not add a
				// key to the panel's view of the response.
				if want {
					assert.Equal(t, true, raw[name]["unserved"], "secret %q", name)
				} else {
					assert.NotContains(t, raw[name], "unserved", "secret %q", name)
				}
			}
		})
	}
}

// TestSecretsAPIPutBodyFrozen sends the exact body the management panel builds
// today (map of name -> {secret, ad_tag, quota, expires}, quota as a bare byte
// count with a "B" suffix and expires as RFC3339) and requires the same 200 and
// the same response bytes. decodeJSON sets DisallowUnknownFields, so a new
// request field would 400 this body on an older binary - which is why the mode
// rides inside the secret string and this request shape never changes.
func TestSecretsAPIPutBodyFrozen(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := modeTestProxy(map[string]Secret{"alice": alice}, ModeSetOf(SecretModeDD, SecretModePlain))

	body := `{"secrets":{"alice":{"secret":"` + alice.Hex() +
		`","ad_tag":"0123456789abcdef0123456789abcdef","quota":"1000B",` +
		`"expires":"2030-01-01T00:00:00Z"}}}`

	rec := doAPI(t, p, "", http.MethodPut, "/secrets", body)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "{\"status\":\"ok\"}\n", rec.Body.String())

	infos := getSecretInfos(t, p)
	require.Contains(t, infos, "alice")

	// The secret string the panel gets back is byte-identical to what it stored.
	assert.Equal(t, alice.Base64(), infos["alice"].Secret)
	assert.Equal(t, "alice.example.com", infos["alice"].Host)
	assert.Equal(t, "ee", infos["alice"].Mode)
	assert.False(t, infos["alice"].Unserved)
	assert.Equal(t, "0123456789abcdef0123456789abcdef", infos["alice"].AdTag)
}

// TestSecretsResponseShapeUnchanged is the frozen-contract guard for GET
// /secrets: the fields that were there before this change keep their names and
// JSON types, and the two additions do not appear where they did not before.
func TestSecretsResponseShapeUnchanged(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	raw := secretsRaw(t, modeTestProxy(map[string]Secret{"alice": alice}, 0))
	require.Contains(t, raw, "alice")

	for field, want := range map[string]any{
		"name":   "",
		"secret": "",
		"host":   "",
		"mode":   "",
	} {
		require.Contains(t, raw["alice"], field)
		assert.IsType(t, want, raw["alice"][field], "secrets[alice].%s changed type", field)
	}

	assert.Equal(t, "alice", raw["alice"]["name"])
	assert.Equal(t, alice.Base64(), raw["alice"]["secret"])

	// Nothing was set, so every omitempty field must still be absent.
	for _, field := range []string{
		"ad_tag", "effective_ad_tag", "quota", "quota_used", "quota_remaining",
		"quota_reset", "expires_at", "disabled", "unserved",
	} {
		assert.NotContains(t, raw["alice"], field)
	}
}

// TestStatsListenerOverlayShape covers the two additive /stats blocks. The
// absence half is the contract: a deployment that never declared a [[listener]]
// must see a response identical to the one it saw before this change.
func TestStatsListenerOverlayShape(t *testing.T) {
	t.Parallel()

	statsMap := func(t *testing.T, p *Proxy) map[string]any {
		t.Helper()

		rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
		require.Equal(t, http.StatusOK, rec.Code)

		return statsRaw(t, rec.Body.Bytes())
	}

	t.Run("no listener means no listeners and no obfuscated block", func(t *testing.T) {
		t.Parallel()

		p := modeTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, 0)
		p.obfsStats.OnObfuscatedTrial()

		raw := statsMap(t, p)
		assert.NotContains(t, raw, "listeners")
		assert.NotContains(t, raw, "obfuscated")
	})

	t.Run("a configured listener reports what each socket accepts", func(t *testing.T) {
		t.Parallel()

		p := modeTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")},
			ModeSetOf(SecretModeDD, SecretModePlain))
		p.listeners = []ListenerJSON{
			{Bind: "0.0.0.0:443", Accept: []string{"ee"}, Public: true},
			{Bind: "127.0.0.1:2398", Accept: []string{"dd", "plain"}, Public: false},
		}

		raw := statsMap(t, p)

		listeners, ok := raw["listeners"].([]any)
		require.True(t, ok, "listeners must be a JSON array")
		require.Len(t, listeners, 2)

		first, _ := listeners[0].(map[string]any)
		assert.Equal(t, "0.0.0.0:443", first["bind"])
		assert.Equal(t, []any{"ee"}, first["accept"])
		assert.Equal(t, true, first["public"])

		second, _ := listeners[1].(map[string]any)
		assert.Equal(t, "127.0.0.1:2398", second["bind"])
		assert.Equal(t, []any{"dd", "plain"}, second["accept"])
		assert.Equal(t, false, second["public"])
	})

	t.Run("the obfuscated counters report what the entry recorded", func(t *testing.T) {
		t.Parallel()

		p := modeTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")},
			ModeSetOf(SecretModeDD))

		// Distinct counts per counter on purpose: with all of them at 1 any two
		// fields could be transposed in the mapping and this would still pass,
		// while an operator reading /stats would be told a probing attacker was
		// an over-quota user.
		bump := func(n int, f func()) {
			for range n {
				f()
			}
		}

		bump(1, p.obfsStats.OnObfuscatedTrial)
		bump(2, p.obfsStats.OnObfuscatedMiss)
		bump(3, p.obfsStats.OnObfuscatedDenied)
		bump(4, p.obfsStats.OnObfuscatedDrainStart)
		bump(5, p.obfsStats.OnObfuscatedRateLimited)

		obfuscated, ok := statsMap(t, p)["obfuscated"].(map[string]any)
		require.True(t, ok, "obfuscated must be a JSON object")

		assert.Equal(t, map[string]any{
			"trials":       float64(1),
			"misses":       float64(2),
			"denied":       float64(3),
			"draining":     float64(4),
			"rate_limited": float64(5),
		}, obfuscated)
	})
}

// TestStatsAdTagSkipped covers the per-user counter behind the abridged
// middle-proxy skip: it is omitted while zero, so an existing deployment's user
// object is unchanged, and appears as a number once a stream has been skipped.
func TestStatsAdTagSkipped(t *testing.T) {
	t.Parallel()

	userMap := func(t *testing.T, p *Proxy) map[string]any {
		t.Helper()

		rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
		require.Equal(t, http.StatusOK, rec.Code)

		users, _ := statsRaw(t, rec.Body.Bytes())["users"].(map[string]any)
		require.Contains(t, users, "alice")

		user, _ := users["alice"].(map[string]any)

		return user
	}

	t.Run("absent until something is actually skipped", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		assert.NotContains(t, userMap(t, p), "ad_tag_skipped")
	})

	t.Run("counts every skipped stream", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		p.stats.OnAdTagSkipped("alice")
		p.stats.OnAdTagSkipped("alice")

		user := userMap(t, p)
		require.Contains(t, user, "ad_tag_skipped")
		assert.Equal(t, float64(2), user["ad_tag_skipped"])
	})
}
