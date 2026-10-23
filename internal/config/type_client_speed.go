package config

import (
	"fmt"
)

// TypeClientSpeed is a per-address speed ceiling as the config file spells it:
// a speed, exactly as TypeSpeed reads one -- the same parser, so the same units
// and the same 64kbit/s floor, and the API's client_speed agrees with it. A type
// of its own only for the message: the config decoder does not say which key a
// value it refused came from, and an operator told "speed is below the minimum"
// about a client-speed line would look at the wrong one.
type TypeClientSpeed struct {
	TypeSpeed
}

func (t *TypeClientSpeed) Set(value string) error {
	if err := t.TypeSpeed.Set(value); err != nil {
		return fmt.Errorf("client-speed: %w", err)
	}

	return nil
}

func (t *TypeClientSpeed) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}
