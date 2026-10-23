package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The configuration's rendering is built from the JSON of the struct, so an
// entry that is not a URL cannot come out of a parsed configuration; the
// redaction still has an answer for one, and it is the safe one: if it cannot
// tell the password from the rest, it shows none of it.
func TestRedactProxyPasswordsFailsClosed(t *testing.T) {
	t.Parallel()

	fields := map[string]any{
		"network": map[string]any{
			"proxies": []any{
				"socks5://user:pr0xyP4ssw0rd@10.0.0.2:1080",
				"://user:pr0xyP4ssw0rd@10.0.0.2:1080",
				42,
				"socks5://10.0.0.3:1080",
			},
		},
	}

	redactProxyPasswords(fields)

	assert.Equal(t, []any{
		"socks5://user:xxxxx@10.0.0.2:1080",
		redactedValue,
		redactedValue,
		"socks5://10.0.0.3:1080",
	}, fields["network"].(map[string]any)["proxies"])
}

// A rendering with no network table, or one without proxies, is left alone.
func TestRedactProxyPasswordsToleratesOtherShapes(t *testing.T) {
	t.Parallel()

	for _, fields := range []map[string]any{
		{},
		{"network": nil},
		{"network": map[string]any{}},
		{"network": map[string]any{"proxies": nil}},
		{"network": map[string]any{"proxies": "not a list"}},
	} {
		assert.NotPanics(t, func() { redactProxyPasswords(fields) })
	}
}
