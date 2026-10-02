package config

import (
	"fmt"
	"strings"
)

const (
	// TypeDoppelShapingRecord waits a drawn delay before every TLS record the
	// doppelganger writes. It is the default.
	TypeDoppelShapingRecord = "record"

	// TypeDoppelShapingBurst waits one drawn delay when a connection wakes
	// from idle and then sends records back to back.
	TypeDoppelShapingBurst = "burst"
)

type TypeDoppelShaping struct {
	Value string
}

func (t *TypeDoppelShaping) Set(value string) error {
	value = strings.ToLower(value)

	switch value {
	case TypeDoppelShapingRecord, TypeDoppelShapingBurst:
		t.Value = value

		return nil
	default:
		return fmt.Errorf("unsupported doppelganger shaping %q: use %q or %q",
			value, TypeDoppelShapingRecord, TypeDoppelShapingBurst)
	}
}

func (t TypeDoppelShaping) Get(defaultValue string) string {
	if t.Value == "" {
		return defaultValue
	}

	return t.Value
}

func (t *TypeDoppelShaping) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeDoppelShaping) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeDoppelShaping) String() string {
	return t.Value
}
