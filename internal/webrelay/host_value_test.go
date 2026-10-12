package webrelay_test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Task 10's second review, N-A. The relay checks [web] host again when it starts
// (origin.go), and its refusal quotes the host. A secret value pasted there is
// not printed: three hosts the config's own check lets through and this one
// refuses -- a trailing dot, an empty label, a '+' -- and the same in uppercase
// hex, which the mapping lowercases before quoting.
func TestCanonicalHostNeverEchoesAValue(t *testing.T) {
	t.Parallel()

	value := mtglib.GenerateSecret("cover.example.com")

	raw, err := hex.DecodeString(value.Hex())
	require.NoError(t, err)

	b64url := base64.RawURLEncoding.EncodeToString(raw)

	for name, host := range map[string]string{
		"the value in hex, with a trailing dot":           value.Hex() + ".",
		"the value in hex, with an empty label after it":  value.Hex() + "..example.org",
		"the value in base64url after a '+'":              "a+" + b64url + ".example.org",
		"the value in uppercase hex, with a trailing dot": strings.ToUpper(value.Hex()) + ".",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := webrelay.CanonicalHost(host)
			require.Error(t, err)

			// Compared without printing either side: a failure must not print
			// the value it found.
			text := strings.ToLower(err.Error())
			require.False(t, strings.Contains(text, strings.ToLower(value.Hex())), "the refusal carries the value in hex")
			require.False(t, strings.Contains(text, hex.EncodeToString(value.Key[:])), "the refusal carries the key in hex")
			require.False(t, strings.Contains(err.Error(), b64url), "the refusal carries the value in base64url")

			require.ErrorIs(t, err, webrelay.ErrInvalidHost)
			assert.Contains(t, err.Error(), "<not shown: reads as a secret value>")
		})
	}

	// An ordinary refused host reads as before.
	_, err = webrelay.CanonicalHost("proxy.example.com.")
	assert.EqualError(t, err, webrelay.ErrInvalidHost.Error()+`: "proxy.example.com." has a trailing dot`)
}
