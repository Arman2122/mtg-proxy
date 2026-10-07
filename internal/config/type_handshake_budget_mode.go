package config

import "fmt"

const (
	// TypeHandshakeBudgetModeEnforce charges the scan of a hello that no hint
	// matched against the CPU budget. A scan the budget can pay for within
	// 150 ms waits for it and runs; one it cannot pay for is fronted to the
	// cover site at once, never closed. It is the default.
	TypeHandshakeBudgetModeEnforce = "enforce"

	// TypeHandshakeBudgetModeObserve keeps the same accounting but never waits
	// and never refuses: it counts what enforce would have refused, and scans
	// anyway. It is the canary.
	TypeHandshakeBudgetModeObserve = "observe"

	// TypeHandshakeBudgetModeOff has no budget and no scan cap.
	TypeHandshakeBudgetModeOff = "off"
)

// TypeHandshakeBudgetMode is [defense.handshake-budget] mode: exactly one of the
// three lower-case words. Unlike its neighbour TypeDoppelShaping it does not fold
// case: mtglib.ProxyOpts accepts any case, for an embedder, but a config file
// that says "OBSERVE" is a typo this binary reports rather than guesses at.
type TypeHandshakeBudgetMode struct {
	Value string
}

func (t *TypeHandshakeBudgetMode) Set(value string) error {
	switch value {
	case TypeHandshakeBudgetModeEnforce, TypeHandshakeBudgetModeObserve, TypeHandshakeBudgetModeOff:
		t.Value = value

		return nil
	default:
		return fmt.Errorf("unsupported [defense.handshake-budget] mode %q: use %q, %q or %q",
			value, TypeHandshakeBudgetModeEnforce, TypeHandshakeBudgetModeObserve, TypeHandshakeBudgetModeOff)
	}
}

func (t TypeHandshakeBudgetMode) Get(defaultValue string) string {
	if t.Value == "" {
		return defaultValue
	}

	return t.Value
}

func (t *TypeHandshakeBudgetMode) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeHandshakeBudgetMode) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeHandshakeBudgetMode) String() string {
	return t.Value
}
