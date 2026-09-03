package mtglib

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// SecretMode is the wire form a secret is PRESENTED in. It is not an access
// control: the same Key derives the same ciphers in all three modes, so which
// mode a connection actually uses is decided by the listener it arrived on
// (ListenerPolicy) plus the transport tag it decrypts to. Mode never gates
// admission -- see doFakeTLSHandshake, which selects HMAC candidates by
// Hosted(), and doObfuscatedEntry, which trial-decrypts against every key.
type SecretMode uint8

const (
	SecretModeFakeTLS SecretMode = iota // "ee" + key + hostname; the ZERO VALUE
	SecretModeDD                        // "dd" + key; obfuscated2, no TLS
	SecretModePlain                     // bare 16-byte key; obfuscated2, no TLS
)

const (
	secretModeNameFakeTLS = "ee"
	secretModeNameDD      = "dd"
	secretModeNamePlain   = "plain"
)

// String is to support fmt.Stringer interface.
func (m SecretMode) String() string {
	switch m {
	case SecretModeFakeTLS:
		return secretModeNameFakeTLS
	case SecretModeDD:
		return secretModeNameDD
	case SecretModePlain:
		return secretModeNamePlain
	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

// ParseSecretMode resolves a mode name. "faketls" is accepted as a synonym of
// "ee" because that is what the mode does; "ee" is what the link says.
func ParseSecretMode(s string) (SecretMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case secretModeNameFakeTLS, "faketls":
		return SecretModeFakeTLS, nil
	case secretModeNameDD:
		return SecretModeDD, nil
	case secretModeNamePlain:
		return SecretModePlain, nil
	default:
		return SecretModeFakeTLS, fmt.Errorf(
			"unknown secret mode %q (expected one of \"dd\", \"ee\", \"plain\")", s)
	}
}

// MarshalText is to support text.Marshaller interface.
func (m SecretMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// UnmarshalText is to support text.Unmarshaller interface.
func (m *SecretMode) UnmarshalText(b []byte) error {
	parsed, err := ParseSecretMode(string(b))
	if err != nil {
		return err
	}

	*m = parsed

	return nil
}

// ModeSet is a bitset of SecretMode.
type ModeSet uint8

// ModeSetOf builds a set out of the given modes.
func ModeSetOf(modes ...SecretMode) ModeSet {
	var set ModeSet

	for _, mode := range modes {
		set |= 1 << mode
	}

	return set
}

// ParseModeSet resolves a list of mode names into a set.
func ParseModeSet(names []string) (ModeSet, error) {
	var set ModeSet

	for _, name := range names {
		mode, err := ParseSecretMode(name)
		if err != nil {
			return 0, err
		}

		set |= 1 << mode
	}

	return set, nil
}

// Has reports whether the given mode belongs to this set.
func (m ModeSet) Has(mode SecretMode) bool { return m&(1<<mode) != 0 }

// Empty reports whether this set honours nothing at all.
func (m ModeSet) Empty() bool { return m == 0 }

// Strings returns the sorted names of the modes in this set.
func (m ModeSet) Strings() []string {
	names := make([]string, 0, 3) //nolint: mnd // dd, ee, plain

	for _, mode := range []SecretMode{SecretModeFakeTLS, SecretModeDD, SecretModePlain} {
		if m.Has(mode) {
			names = append(names, mode.String())
		}
	}

	sort.Strings(names)

	return names
}

// String is to support fmt.Stringer interface.
func (m ModeSet) String() string {
	return strings.Join(m.Strings(), ",")
}

// Tags is the set of obfuscated2 connection-type tags this mode set honours at
// frame offset 56.
//
// dd is padded-intermediate and nothing else -- that is what the mode means.
// plain is ALL THREE, because a bare 16-byte secret places no constraint on the
// client's transport: tdlib sends 0xeeeeeeee for it, tdesktop and Telegram-iOS
// send 0xefefefef, and any of them may pick padded-intermediate. Honouring a
// subset silently breaks part of the client population.
func (m ModeSet) Tags() obfuscation.TagSet {
	var t obfuscation.TagSet

	if m.Has(SecretModeDD) {
		t = t.With(obfuscation.TagPaddedIntermediate)
	}

	if m.Has(SecretModePlain) {
		t = t.With(obfuscation.TagPaddedIntermediate).
			With(obfuscation.TagIntermediate).
			With(obfuscation.TagAbridged)
	}

	return t
}
