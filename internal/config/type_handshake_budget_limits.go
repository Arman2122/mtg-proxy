package config

import (
	"fmt"
	"strconv"
)

const (
	// handshakeBudgetMaxPerIPMillis is the most scan CPU a client address may be
	// given, in milliseconds a second: all of one core.
	handshakeBudgetMaxPerIPMillis = 1000

	// handshakeBudgetMaxCPUPercent is the most of the cores the whole process may
	// spend scanning.
	handshakeBudgetMaxCPUPercent = 100
)

// TypeHandshakeBudgetPerIP is [defense.handshake-budget] per-ip-ms: the scan CPU
// one client address may spend per second, in milliseconds, 0 to 1000.
//
// 0 is a value, not an absence: it turns the per-address bucket off. Config holds
// this type behind a pointer so that an explicit 0 survives and "not set" (50)
// stays distinct from it.
type TypeHandshakeBudgetPerIP struct {
	Value uint
}

func (t *TypeHandshakeBudgetPerIP) Set(value string) error {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("[defense.handshake-budget] per-ip-ms is not a whole number of milliseconds (%s): %w",
			value, err)
	}

	if parsed < 0 || parsed > handshakeBudgetMaxPerIPMillis {
		return fmt.Errorf("[defense.handshake-budget] per-ip-ms should be 0 to %d (%s)",
			handshakeBudgetMaxPerIPMillis, value)
	}

	t.Value = uint(parsed)

	return nil
}

func (t *TypeHandshakeBudgetPerIP) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeHandshakeBudgetPerIP) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeHandshakeBudgetPerIP) String() string {
	return strconv.FormatUint(uint64(t.Value), 10)
}

// TypeHandshakeBudgetCPU is [defense.handshake-budget] cpu-percent: the share of
// the cores the whole process may spend scanning, 1 to 100.
//
// Unlike per-ip-ms there is no zero that means anything, so 0 is both "not set"
// (25) and, written in the file, an error. The TOML mirror holds it behind a
// pointer so the file's 0 reaches Set instead of being dropped as an empty value.
type TypeHandshakeBudgetCPU struct {
	Value uint
}

func (t *TypeHandshakeBudgetCPU) Set(value string) error {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("[defense.handshake-budget] cpu-percent is not a whole number (%s): %w", value, err)
	}

	if parsed < 1 || parsed > handshakeBudgetMaxCPUPercent {
		return fmt.Errorf("[defense.handshake-budget] cpu-percent should be 1 to %d (%s)",
			handshakeBudgetMaxCPUPercent, value)
	}

	t.Value = uint(parsed)

	return nil
}

func (t TypeHandshakeBudgetCPU) Get(defaultValue uint) uint {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeHandshakeBudgetCPU) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeHandshakeBudgetCPU) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeHandshakeBudgetCPU) String() string {
	return strconv.FormatUint(uint64(t.Value), 10)
}
