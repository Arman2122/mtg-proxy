package config_test

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenerConfigTOML is the shape the panel emits once the WEB backend toggle is
// on: the [[listener]] block goes after [throttle] and before the trailing
// key-value tables, with [secrets] last. The tables AFTER the block matter as
// much as the block itself -- see TestOldBinaryIgnoresListenerBlock.
const listenerConfigTOML = `
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
concurrency = 8192

[throttle]
max-connections = 8

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
public = false

[secret-ad-tags]
alice = "0123456789abcdef0123456789abcdef"

[secrets]
alice = "eeAAAA"
bob = "eeBBBB"
`

// oldTOMLConfig is internal/config's tomlConfig as it stood BEFORE [[listener]]
// existed: no Listeners field of any kind.
type oldTOMLConfig struct {
	Secret      string `toml:"secret"`
	BindTo      any    `toml:"bind-to"`
	Concurrency uint   `toml:"concurrency"`
	Throttle    struct {
		MaxConnections uint `toml:"max-connections"`
	} `toml:"throttle"`
	SecretAdTags map[string]string `toml:"secret-ad-tags"`
	Secrets      map[string]string `toml:"secrets"`
}

// TestOldBinaryIgnoresListenerBlock pins the fact the entire cross-repo rollout
// rests on: internal/config/parse.go calls toml.Unmarshal WITHOUT
// DisallowUnknownFields, so a config carrying [[listener]] loads cleanly on an
// mtg-proxy binary that predates the feature -- it simply serves ee on bind-to
// as before. That is what lets the panel emit the block unconditionally, with no
// capability probe and no ordering constraint against the binary rollout.
//
// The [secrets] assertion is the sharp end. [[listener]] is an array of TABLES,
// so the danger is not that an old binary rejects it but that it skips the block
// and loses the tables written after it -- which would leave the inbound with
// zero secrets and fail Validate. If this test ever fails, emitting [[listener]]
// takes every inbound offline on any binary not upgraded first.
func TestOldBinaryIgnoresListenerBlock(t *testing.T) {
	t.Parallel()

	var old oldTOMLConfig

	require.NoError(t, toml.Unmarshal([]byte(listenerConfigTOML), &old))

	// Keys before the block.
	assert.Equal(t, "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t", old.Secret)
	assert.Equal(t, "0.0.0.0:3128", old.BindTo)
	assert.EqualValues(t, 8192, old.Concurrency)
	assert.EqualValues(t, 8, old.Throttle.MaxConnections)

	// Tables after the block: skipping the unknown array of tables must not
	// swallow what follows it.
	assert.Equal(t, map[string]string{"alice": "0123456789abcdef0123456789abcdef"}, old.SecretAdTags)
	assert.Equal(t, map[string]string{"alice": "eeAAAA", "bob": "eeBBBB"}, old.Secrets)
}

// TestStrictDecodeWouldReject is the discriminating half of the test above: the
// same document and the same struct DO fail once unknown fields are disallowed.
// Without this, a decoder that silently accepted anything would pass the leniency
// assertion for the wrong reason.
func TestStrictDecodeWouldReject(t *testing.T) {
	t.Parallel()

	var old oldTOMLConfig

	decoder := toml.NewDecoder(bytes.NewReader([]byte(listenerConfigTOML)))
	decoder.DisallowUnknownFields()

	assert.Error(t, decoder.Decode(&old))
}
