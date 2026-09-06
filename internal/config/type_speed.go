package config

import (
	"strconv"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

// TypeSpeed is a per-user speed limit as the config file spells it: "5mbit",
// "500kbit", "1MB/s". It parses through the same function the management API
// uses, so a spelling the file accepts is one the API accepts and the two can
// never drift. The value is bytes per second; zero is unlimited.
type TypeSpeed struct {
	Value int64
}

func (t *TypeSpeed) Set(value string) error {
	parsed, err := mtglib.ParseSpeed(value)
	if err != nil {
		return err //nolint: wrapcheck // the parser's message names the value and the rule
	}

	t.Value = parsed

	return nil
}

// Get returns the limit in bytes per second, or the default when none is set.
func (t TypeSpeed) Get(defaultValue int64) int64 {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeSpeed) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeSpeed) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// String renders the limit in a form Set accepts back, so the value survives
// the config's own round trip. Empty is unlimited.
func (t TypeSpeed) String() string {
	if t.Value == 0 {
		return ""
	}

	return strconv.FormatInt(t.Value, 10) + "B/s"
}
