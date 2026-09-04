package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/alecthomas/units"
)

var typeBytesStringCleaner = strings.NewReplacer(" ", "", "\t", "", "IB", "iB")

type TypeBytes struct {
	Value units.Base2Bytes
}

func (t *TypeBytes) Set(value string) error {
	normalizedValue := typeBytesStringCleaner.Replace(strings.ToUpper(value))

	parsedValue, err := units.ParseBase2Bytes(normalizedValue)
	if err != nil {
		return fmt.Errorf("incorrect bytes value (%v): %w", value, err)
	}

	if parsedValue < 0 {
		return fmt.Errorf("bytes should be positive (%s)", value)
	}

	t.Value = parsedValue

	return nil
}

// Get keeps the parsed int64 width. uint is 32 bits on the 386/arm builds we
// ship, and narrowing here wrapped a per-secret quota above 4 GiB silently.
func (t TypeBytes) Get(defaultValue int64) int64 {
	if t.Value == 0 {
		return defaultValue
	}

	return int64(t.Value)
}

// GetUint serves the two machine-word consumers (bloom filter size,
// TCP_NOTSENT_LOWAT). It refuses what does not fit rather than wrapping or
// clamping it, bounded by MaxInt so their int cast is safe on 32-bit too.
func (t TypeBytes) GetUint(defaultValue uint) (uint, error) {
	if t.Value == 0 {
		return defaultValue, nil
	}

	value := int64(t.Value)
	if value < 0 || value > math.MaxInt {
		return 0, fmt.Errorf("bytes value %s does not fit into a %d-bit int (max %d bytes)",
			t.Value, strconv.IntSize, int64(math.MaxInt))
	}

	return uint(value), nil
}

func (t *TypeBytes) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeBytes) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeBytes) String() string {
	if t.Value == 0 {
		return ""
	}

	return strings.ToLower(t.Value.String())
}
