package config_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type typeDoppelShapingTestStruct struct {
	Value config.TypeDoppelShaping `json:"value"`
}

func TestTypeDoppelShaping(t *testing.T) {
	t.Parallel()

	for _, v := range []string{
		config.TypeDoppelShapingRecord,
		config.TypeDoppelShapingBurst,
		strings.ToUpper(config.TypeDoppelShapingBurst),
	} {
		data, err := json.Marshal(map[string]string{"value": v})
		require.NoError(t, err)

		var got typeDoppelShapingTestStruct

		require.NoError(t, json.Unmarshal(data, &got), v)
		assert.Equal(t, strings.ToLower(v), got.Value.Get(""))
	}

	for _, v := range []string{"pace", "bursty", "record "} {
		data, err := json.Marshal(map[string]string{"value": v})
		require.NoError(t, err)

		err = json.Unmarshal(data, &typeDoppelShapingTestStruct{})
		require.Error(t, err, v)
		assert.ErrorContains(t, err, `"record"`, "the error must name the values that work")
		assert.ErrorContains(t, err, `"burst"`, "the error must name the values that work")
	}

	assert.Equal(t, config.TypeDoppelShapingRecord, config.TypeDoppelShaping{}.Get(config.TypeDoppelShapingRecord),
		"unset means the default")
}

func TestDoppelShapingReachesConfig(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(`secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[defense.doppelganger]
shaping = "burst"
`))
	require.NoError(t, err)
	assert.Equal(t, config.TypeDoppelShapingBurst, conf.Defense.Doppelganger.Shaping.Get(config.TypeDoppelShapingRecord))
	assert.Empty(t, conf.UnknownKeys, "shaping is a known key")

	conf, err = config.Parse([]byte(`secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
`))
	require.NoError(t, err)
	assert.Equal(t, config.TypeDoppelShapingRecord, conf.Defense.Doppelganger.Shaping.Get(config.TypeDoppelShapingRecord),
		"a config that never mentions shaping keeps today's behaviour")
}
