package config_test

import (
	"encoding/json"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeSecretMode(t *testing.T) {
	t.Parallel()

	var m config.TypeSecretMode

	require.NoError(t, m.Set("dd"))
	assert.Equal(t, mtglib.SecretModeDD, m.Get())
	assert.Equal(t, "dd", m.String())

	require.NoError(t, m.Set("plain"))
	assert.Equal(t, mtglib.SecretModePlain, m.Get())

	require.NoError(t, m.Set("EE"))
	assert.Equal(t, mtglib.SecretModeFakeTLS, m.Get())

	require.NoError(t, m.Set("faketls"))
	assert.Equal(t, mtglib.SecretModeFakeTLS, m.Get())

	assert.Error(t, m.Set("eee"))
	assert.Error(t, m.Set(""))
}

func TestTypeSecretModeZero(t *testing.T) {
	t.Parallel()

	// The zero value is a real mode, not an "unset" sentinel: accept is a
	// required key, so nothing may lean on distinguishing the two.
	var zero config.TypeSecretMode
	assert.Equal(t, mtglib.SecretModeFakeTLS, zero.Get())
	assert.Equal(t, "ee", zero.String())
}

func TestTypeSecretModeJSON(t *testing.T) {
	t.Parallel()

	var holder struct {
		V []config.TypeSecretMode `json:"v"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"v":["dd","plain"]}`), &holder))
	require.Len(t, holder.V, 2)
	assert.Equal(t, mtglib.SecretModeDD, holder.V[0].Get())
	assert.Equal(t, mtglib.SecretModePlain, holder.V[1].Get())

	assert.Error(t, json.Unmarshal([]byte(`{"v":["eee"]}`), &holder))
}

func TestTypeSecretModeMarshal(t *testing.T) {
	t.Parallel()

	holder := struct {
		V config.TypeSecretMode `json:"v"`
	}{V: config.TypeSecretMode{Value: mtglib.SecretModePlain}}

	data, err := json.Marshal(holder)
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":"plain"}`, string(data))
}
