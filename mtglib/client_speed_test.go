package mtglib

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// client-speed, the per-address ceiling: how fast one address of a shared
// secret may move bytes, both directions together, whatever the others do. It
// is a bucket of its own on the address's entry, separate from fair share's,
// and the secret's rest entry -- every unkeyed peer, every address past a cap --
// never has one.

// The ceiling travels the API as client_speed, spelled as speed is and parsed by
// the same function, so it has speed's floor: PUT sets it and answers 200, it
// reads back as client_speed_limit in bytes a second, on GET /secrets/{name} and
// inside the user object on /stats; a POST that sends it keeps it and one that
// does not clears it, a mutation of another secret leaves it alone, and a value
// the parser refuses is a 400 that names the field, with the running ceiling
// untouched.
func TestClientSpeedThroughTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	userOf := func(t *testing.T) map[string]any {
		t.Helper()

		raw := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())

		users, ok := raw["users"].(map[string]any)
		require.True(t, ok)

		for name := range users {
			assert.Contains(t, []string{"alice", "bob"}, name, "nothing new is a key under users")
		}

		user, ok := users["alice"].(map[string]any)
		require.True(t, ok)

		return user
	}

	secretOf := func(t *testing.T) map[string]any {
		t.Helper()

		out := map[string]any{}
		require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &out))

		return out
	}

	assert.NotContains(t, userOf(t), "client_speed_limit", "absent while unset")
	assert.NotContains(t, secretOf(t), "client_speed_limit")

	rec := doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`","client_speed":"2mbit"}}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	assert.EqualValues(t, 250_000, p.secrets.Load().limits[0].ClientSpeedBytesPerSecond, "a ceiling alone is kept")
	assert.Equal(t, float64(250_000), secretOf(t)["client_speed_limit"], "read back in bytes a second")
	assert.Equal(t, float64(250_000), userOf(t)["client_speed_limit"])
	assert.NotContains(t, userOf(t), "speed_limit", "it is not the secret's own speed")

	// Another secret's mutation starts from a copy of the set, which keeps it.
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"bob","secret":"`+bob.Hex()+`"}`).Code)
	assert.Equal(t, float64(250_000), secretOf(t)["client_speed_limit"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":"1MB/s"}`).Code)
	assert.Equal(t, float64(1<<20), secretOf(t)["client_speed_limit"], "sent, it is kept")

	for name, value := range map[string]string{
		"below speed's floor": `"32kbit"`,
		"not a speed":         `"fast"`,
		"negative":            `"-1mbit"`,
		"zero":                `"0"`,
	} {
		rec := doAPI(t, p, "", http.MethodPost, "/secrets",
			`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":`+value+`}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Contains(t, rec.Body.String(), "client_speed", "%s: the refusal names the field", name)
		assert.Equal(t, float64(1<<20), secretOf(t)["client_speed_limit"],
			"%s: a refused request leaves the running ceiling alone", name)
	}

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":"64kbit"}`).Code, "the floor itself is accepted")
	assert.Equal(t, float64(MinSpeedBytesPerSecond), secretOf(t)["client_speed_limit"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","ip_limit":2}`).Code)
	assert.NotContains(t, secretOf(t), "client_speed_limit", "not sent, it is cleared")
	assert.NotContains(t, userOf(t), "client_speed_limit")
	assert.Equal(t, float64(2), secretOf(t)["ip_limit"])
}
