package config

import (
	"fmt"
	"strings"
)

const (
	// TypeUnknownSecretActionClose closes a refused connection immediately.
	TypeUnknownSecretActionClose = "close"

	// TypeUnknownSecretActionDrain reads and discards from a refused connection
	// under a bounded budget before closing it.
	TypeUnknownSecretActionDrain = "drain"
)

// TypeUnknownSecretAction is the disposal of a connection no secret matches.
// The value is validated at parse time so that a misspelled policy cannot leave
// a public listener answering probes in a way the operator did not choose.
type TypeUnknownSecretAction struct {
	Value string
}

func (t *TypeUnknownSecretAction) Set(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))

	switch value {
	case TypeUnknownSecretActionClose, TypeUnknownSecretActionDrain:
		t.Value = value

		return nil
	default:
		return fmt.Errorf("unsupported on-unknown-secret action %q (expected %q or %q)",
			value, TypeUnknownSecretActionClose, TypeUnknownSecretActionDrain)
	}
}

func (t TypeUnknownSecretAction) Get(defaultValue string) string {
	if t.Value == "" {
		return defaultValue
	}

	return t.Value
}

func (t *TypeUnknownSecretAction) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeUnknownSecretAction) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeUnknownSecretAction) String() string {
	return t.Value
}
