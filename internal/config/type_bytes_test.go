package config_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/alecthomas/units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type typeBytesTestStruct struct {
	Value config.TypeBytes `json:"value"`
}

type TypeBytesTestSuite struct {
	suite.Suite
}

func (suite *TypeBytesTestSuite) TestUnmarshalFail() {
	testData := []string{
		"1m",
		"1",
		"-1kb",
		"-1kib",
	}

	for _, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal(data, &typeBytesTestStruct{}))
		})
	}
}

func (suite *TypeBytesTestSuite) TestUnmarshalOk() {
	testData := map[string]uint{
		"1b":   1,
		"1kb":  1024,
		"1kib": 1024,
		"2mb":  2 * 1024 * 1024,
		"2mib": 2 * 1024 * 1024,
	}

	for k, v := range testData {
		value := v

		data, err := json.Marshal(map[string]string{
			"value": k,
		})
		suite.NoError(err)

		suite.T().Run(k, func(t *testing.T) {
			testStruct := &typeBytesTestStruct{}

			assert.NoError(t, json.Unmarshal(data, testStruct))
			assert.EqualValues(t, value, testStruct.Value.Get(0))
		})
	}
}

func (suite *TypeBytesTestSuite) TestMarshalOk() {
	value := typeBytesTestStruct{}
	suite.NoError(value.Value.Set("1kib"))

	data, err := json.Marshal(value)
	suite.NoError(err)
	suite.JSONEq(`{"value": "1kib"}`, string(data))
}

func (suite *TypeBytesTestSuite) TestGet() {
	value := config.TypeBytes{}
	suite.EqualValues(1000, value.Get(1000))

	suite.NoError(value.Set("1mib"))
	suite.EqualValues(1048576, value.Get(1000))
}

// A byte count must survive Get at its parsed width. `uint` is 32 bits on the
// linux/386, linux/arm and windows/386 targets we ship binaries for, so a Get
// that narrowed turned 5GiB into 1GiB with no error at all.
func TestGetIsNotNarrowed(t *testing.T) {
	t.Parallel()

	for _, v := range []struct {
		text string
		want int64
	}{
		{"4gib", 4 << 30},
		{"5gib", 5 << 30},
		{"10gib", 10 << 30},
		{"1tib", 1 << 40},
	} {
		t.Run(v.text, func(t *testing.T) {
			t.Parallel()

			value := config.TypeBytes{}
			require.NoError(t, value.Set(v.text))
			assert.Equal(t, v.want, value.Get(0))
		})
	}
}

// The end-to-end path the finding is about: a per-secret quota above 4 GiB
// reaching mtglib.SecretLimits intact.
func TestQuotaAbove4GiBReachesSecretLimits(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("alice.example.com").Hex()
	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
quota = "5GiB"

[secrets]
alice = "%s"
`, secret)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	limits := conf.GetSecretLimits()
	require.Len(t, limits, 1)
	assert.Equal(t, int64(5<<30), limits["alice"].QuotaBytes)
}

// GetUint is the only narrowing left. It must refuse rather than wrap: an
// operator who wrote 5GiB must never silently get 1GiB.
func TestGetUint(t *testing.T) {
	t.Parallel()

	t.Run("zero yields default", func(t *testing.T) {
		t.Parallel()

		value, err := config.TypeBytes{}.GetUint(1024)
		require.NoError(t, err)
		assert.EqualValues(t, 1024, value)
	})

	t.Run("fitting value passes through", func(t *testing.T) {
		t.Parallel()

		parsed := config.TypeBytes{}
		require.NoError(t, parsed.Set("1mib"))

		value, err := parsed.GetUint(1024)
		require.NoError(t, err)
		assert.EqualValues(t, 1048576, value)
	})

	t.Run("MaxInt still fits", func(t *testing.T) {
		t.Parallel()

		value, err := config.TypeBytes{Value: units.Base2Bytes(math.MaxInt)}.GetUint(1024)
		require.NoError(t, err)
		assert.EqualValues(t, uint(math.MaxInt), value)
	})

	// Set rejects negatives, but nothing stops a zero-value struct being
	// filled in directly, and a negative must not become a huge uint.
	t.Run("negative is refused", func(t *testing.T) {
		t.Parallel()

		_, err := config.TypeBytes{Value: -1}.GetUint(1024)
		require.Error(t, err)
	})

	// Only reachable where int is narrower than the parsed int64, i.e. the
	// 32-bit builds. Run the package with GOARCH=386 to exercise it.
	t.Run("above MaxInt is refused, not wrapped", func(t *testing.T) {
		t.Parallel()

		if strconv.IntSize >= 64 {
			t.Skip("int is 64 bits here; no byte count can exceed it")
		}

		parsed := config.TypeBytes{}
		require.NoError(t, parsed.Set("5gib"))

		_, err := parsed.GetUint(1024)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not fit")
	})
}

func TestTypeBytes(t *testing.T) {
	t.Parallel()
	suite.Run(t, &TypeBytesTestSuite{})
}
