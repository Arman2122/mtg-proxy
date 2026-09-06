package config

import (
	"fmt"
	"strconv"
)

// TypeIPLimit is a per-user address limit as the config file spells it: a
// bare non-negative integer, the number of distinct addresses the user may
// hold connections from at once. Zero, or the key left out, is unlimited.
type TypeIPLimit struct {
	Value int
}

func (t *TypeIPLimit) Set(value string) error {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fmt.Errorf("ip-limit is not an integer (%s): %w", value, err)
	}

	if parsed < 0 {
		return fmt.Errorf("ip-limit must not be negative (%s)", value)
	}

	t.Value = int(parsed)

	return nil
}

// Get returns the limit, or the default when none is set.
func (t TypeIPLimit) Get(defaultValue int) int {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeIPLimit) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeIPLimit) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeIPLimit) String() string {
	return strconv.Itoa(t.Value)
}
