package config

import (
	"fmt"
	"strconv"
)

// TypeClientConns is a per-address connection cap as the config file spells
// it: a bare non-negative integer, the number of live connections one address
// may hold to the secret at once. Zero, or the key left out, is unlimited. A
// type of its own rather than TypeIPLimit, whose messages name ip-limit: an
// operator told "ip-limit must not be negative" about a client-conns line
// would look in the wrong place.
type TypeClientConns struct {
	Value int
}

func (t *TypeClientConns) Set(value string) error {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return fmt.Errorf("client-conns is not an integer (%s): %w", value, err)
	}

	if parsed < 0 {
		return fmt.Errorf("client-conns must not be negative (%s)", value)
	}

	t.Value = int(parsed)

	return nil
}

// Get returns the cap, or the default when none is set.
func (t TypeClientConns) Get(defaultValue int) int {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeClientConns) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeClientConns) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeClientConns) String() string {
	return strconv.Itoa(t.Value)
}
