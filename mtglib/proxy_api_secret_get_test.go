package mtglib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /secrets/{name} is one entry of GET /secrets, by name. The route took
// DELETE and answered GET with 405, so a panel drawing one user's page had to
// fetch every user and pick one out. The contract is that the two views are
// the same object: whatever the collection would say about a user, the single
// route says, and nothing else.
func TestGetOneSecret(t *testing.T) {
	t.Parallel()

	t.Run("is the collection's entry for that name", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{
			"alice": GenerateSecret("alice.example.com"),
			"bob":   GenerateSecret("bob.example.com"),
		})

		single := doAPI(t, p, "", http.MethodGet, "/secrets/alice", "")
		require.Equal(t, http.StatusOK, single.Code)

		var one map[string]any
		require.NoError(t, json.Unmarshal(single.Body.Bytes(), &one))
		assert.Equal(t, "alice", one["name"])

		all := doAPI(t, p, "", http.MethodGet, "/secrets", "")
		require.Equal(t, http.StatusOK, all.Code)

		var collection struct {
			Secrets []map[string]any `json:"secrets"`
		}

		require.NoError(t, json.Unmarshal(all.Body.Bytes(), &collection))

		var fromCollection map[string]any

		for _, entry := range collection.Secrets {
			if entry["name"] == "alice" {
				fromCollection = entry
			}
		}

		require.NotNil(t, fromCollection, "the collection must list alice")
		assert.Equal(t, fromCollection, one,
			"the single view and the collection's entry must be the same object, field for field")
	})

	t.Run("carries the live counters", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		p.stats.OnConnect("alice")
		p.stats.UpdateLastSeen("alice")

		rec := doAPI(t, p, "", http.MethodGet, "/secrets/alice", "")
		require.Equal(t, http.StatusOK, rec.Code)

		var one map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &one))
		assert.Equal(t, float64(1), one["connections"])
		assert.NotEmpty(t, one["last_seen"])
	})

	t.Run("an unknown name is 404, like DELETE", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

		rec := doAPI(t, p, "", http.MethodGet, "/secrets/ghost", "")
		require.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "ghost")
	})

	t.Run("sits behind the bearer token like every other route", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

		// Built with a token, asked without one. doAPI cannot express this: it
		// sends whatever token it built the handler with.
		handler := p.buildAPIHandler("s3cr3t")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets/alice", nil))

		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
