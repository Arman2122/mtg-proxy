package config_test

import (
	"encoding/json"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeUnknownSecretAction(t *testing.T) {
	t.Parallel()

	var a config.TypeUnknownSecretAction

	require.NoError(t, a.Set("close"))
	assert.Equal(t, "close", a.Value)

	require.NoError(t, a.Set("drain"))
	assert.Equal(t, "drain", a.Value)

	require.NoError(t, a.Set("DRAIN"))
	assert.Equal(t, "drain", a.Value)

	assert.Error(t, a.Set("reset"))
	assert.Error(t, a.Set(""))
}

func TestTypeUnknownSecretActionGetDefault(t *testing.T) {
	t.Parallel()

	var zero config.TypeUnknownSecretAction
	assert.Equal(t, "close", zero.Get(config.TypeUnknownSecretActionClose))

	zero.Value = config.TypeUnknownSecretActionDrain
	assert.Equal(t, "drain", zero.Get(config.TypeUnknownSecretActionClose))
}

func TestTypeUnknownSecretActionJSON(t *testing.T) {
	t.Parallel()

	var holder struct {
		V config.TypeUnknownSecretAction `json:"v"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"v":"drain"}`), &holder))
	assert.Equal(t, "drain", holder.V.Value)

	assert.Error(t, json.Unmarshal([]byte(`{"v":"reset"}`), &holder))

	data, err := json.Marshal(holder)
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":"drain"}`, string(data))
}
