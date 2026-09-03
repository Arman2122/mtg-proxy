package config

import (
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// TypeSecretMode is one entry of a [[listener]] accept list: "dd", "ee" or
// "plain". Parsing it here turns a typo like accept = ["eee"] into a config
// error naming the value, instead of a socket that silently honours nothing.
type TypeSecretMode struct {
	Value mtglib.SecretMode
}

func (t *TypeSecretMode) Set(value string) error {
	mode, err := mtglib.ParseSecretMode(value)
	if err != nil {
		return err
	}

	t.Value = mode

	return nil
}

// Get returns the parsed mode. There is no default: SecretMode's zero value is
// a real mode ("ee"), so an unset one cannot be told from an explicit one, and
// accept is a required key anyway.
func (t TypeSecretMode) Get() mtglib.SecretMode {
	return t.Value
}

func (t *TypeSecretMode) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeSecretMode) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeSecretMode) String() string {
	return t.Value.String()
}
