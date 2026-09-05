package mtglib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
)

const (
	secretFakeTLSFirstByte byte = 0xee
	secretDDFirstByte      byte = 0xdd
)

var secretEmptyKey [SecretKeyLength]byte

// Secret is a data structure that presents a secret.
//
// Telegram secret is not a simple string like
// "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d".
// Actually, this is a serialized datastructure of 3 parts: a mode prefix, a key
// and a host.
//
//	ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d
//	|-|-------------------------------|-------------------------------------------
//	p key                             hostname
//
// There are 3 wire forms, and the length discriminates between them before the
// first byte does:
//
//	16 bytes                  - "plain": a bare key, obfuscated2, no TLS.
//	17 bytes starting 0xdd    - "dd": obfuscated2 with padded-intermediate framing.
//	0xee + 16 bytes + a host  - "ee": faketls plus protection from statistical
//	                            attacks on a length. This is what mtg generates
//	                            and what every modern client should be given.
//
// After the prefix we have 16 bytes of the key. This is a random generated
// secret data of the proxy and this data is used to derive authentication
// schemas. These secrets are mixed into hmacs and sha256 checksums which are
// used to build AEAD ciphers for obfuscated2 protocol and ensure faketls
// handshake. The key is identical in all 3 forms: the prefix tells the CLIENT
// how to connect, it does not change the cryptography.
//
// Host is a domain fronting hostname in latin1 (ASCII) encoding. This hostname
// should be used for SNI in faketls and MTG verifies it. Also, this is when
// mtg gets about a domain fronting hostname. Only the 'ee' form carries it.
//
// Secrets can be serialized into 2 forms: hex and base64. If you decode both
// forms into bytes, you'll get the same byte array. Telegram clients nowadays
// accept all forms.
type Secret struct {
	// Key is a set of bytes used for traffic authentication.
	Key [SecretKeyLength]byte

	// Host is a domain fronting hostname. Required by, and meaningful only to,
	// SecretModeFakeTLS: dd and plain never send SNI and never front.
	Host string

	// Mode is the wire form. The ZERO VALUE is SecretModeFakeTLS, so every
	// existing Secret{Key: k, Host: h} literal in the tree and its tests keeps
	// its exact current meaning with no edit.
	Mode SecretMode
}

// MarshalText is to support text.Marshaller interface.
func (s Secret) MarshalText() ([]byte, error) {
	if s.Valid() {
		return []byte(s.String()), nil
	}

	return nil, nil
}

// UnmarshalText is to support text.Unmarshaller interface.
func (s *Secret) UnmarshalText(data []byte) error {
	return s.Set(string(data))
}

func (s *Secret) Set(text string) error {
	if text == "" {
		return ErrSecretEmpty
	}

	decoded, err := hex.DecodeString(text)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(text)
	}

	if err != nil {
		return fmt.Errorf("incorrect secret format: %w", err)
	}

	// Length discriminates before the first byte does, so a 16-byte value whose
	// first byte happens to be 0xee or 0xdd is unambiguously plain. This is what
	// tdlib's ProxySecret::from_binary does.
	switch {
	case len(decoded) == SecretKeyLength:
		s.Mode, s.Host = SecretModePlain, ""
		copy(s.Key[:], decoded)

	case len(decoded) == SecretKeyLength+1:
		if decoded[0] != secretDDFirstByte {
			return fmt.Errorf("a 17-byte secret is the dd form and must start with 0xdd, got %#x", decoded[0])
		}

		s.Mode, s.Host = SecretModeDD, ""
		copy(s.Key[:], decoded[1:])

	case len(decoded) > SecretKeyLength+1:
		if decoded[0] != secretFakeTLSFirstByte {
			return fmt.Errorf("incorrect first byte of secret: %#x", decoded[0])
		}

		s.Mode = SecretModeFakeTLS
		copy(s.Key[:], decoded[1:1+SecretKeyLength])
		s.Host = string(decoded[1+SecretKeyLength:])

		if s.Host == "" {
			return fmt.Errorf("hostname cannot be empty: %s", text)
		}

	default:
		return fmt.Errorf(
			"unrecognised secret: %d bytes (expected 16 for plain, 17 starting with 0xdd for dd, "+
				"or 0xee followed by 16 key bytes and a hostname for ee)", len(decoded),
		)
	}

	// An all-zero key parses today and then fails Valid() deep inside
	// swapSecretConfigLocked with a message that names nothing. Reject it here so
	// the operator gets the secret name and the reason at parse time.
	if s.Key == secretEmptyKey {
		return ErrSecretInvalid
	}

	return nil
}

// Valid checks if this secret is valid and can be used in proxy.
//
// A key is always required; a hostname is required only by the ee form, which
// is the only one that carries it on the wire. Demanding a Host from a dd/plain
// secret would mean storing a hostname that is a lie, and that lie would then
// enter secretSet.hostnames and make SNI matching answer to a domain no real ee
// client ever presents.
func (s Secret) Valid() bool {
	if s.Key == secretEmptyKey {
		return false
	}

	return s.Mode != SecretModeFakeTLS || s.Host != ""
}

// Hosted reports whether this secret can serve the FakeTLS entry: it has an SNI
// hostname to be matched by and a cover site to front to.
func (s Secret) Hosted() bool { return s.Mode == SecretModeFakeTLS }

// String is to support fmt.Stringer interface.
func (s Secret) String() string {
	return s.Base64()
}

// Base64 returns a base64-encoded form of this secret.
func (s Secret) Base64() string {
	return base64.RawURLEncoding.EncodeToString(s.makeBytes())
}

// Hex returns a hex-encoded form of this secret, in its own mode's wire form.
func (s Secret) Hex() string {
	return hex.EncodeToString(s.makeBytes())
}

// DDHex renders THIS KEY in the dd link form, regardless of stored Mode. The
// three forms are presentations of the same 16 bytes.
func (s Secret) DDHex() string {
	return hex.EncodeToString(append([]byte{secretDDFirstByte}, s.Key[:]...))
}

// PlainHex renders this key as a bare 32-hex-character link secret.
func (s Secret) PlainHex() string {
	return hex.EncodeToString(s.Key[:])
}

func (s *Secret) makeBytes() []byte {
	switch s.Mode {
	case SecretModePlain:
		return slices.Clone(s.Key[:])
	case SecretModeDD:
		return append([]byte{secretDDFirstByte}, s.Key[:]...)
	default: // SecretModeFakeTLS
		return append(append([]byte{secretFakeTLSFirstByte}, s.Key[:]...), s.Host...)
	}
}

// GenerateSecret makes a new secret with a given hostname.
func GenerateSecret(hostname string) Secret {
	s := Secret{
		Host: hostname,
	}

	if _, err := rand.Read(s.Key[:]); err != nil {
		panic(err)
	}

	return s
}

// GenerateSecretMode makes a new secret of the given mode. hostname is used
// only by SecretModeFakeTLS and must be empty for the other two.
func GenerateSecretMode(mode SecretMode, hostname string) (Secret, error) {
	switch mode {
	case SecretModeFakeTLS:
		if hostname == "" {
			return Secret{}, fmt.Errorf("mode %s requires a domain fronting hostname", mode)
		}
	case SecretModeDD, SecretModePlain:
		if hostname != "" {
			return Secret{}, fmt.Errorf("mode %s does not carry a hostname on the wire, got %q", mode, hostname)
		}
	default:
		return Secret{}, fmt.Errorf("unknown secret mode %s", mode)
	}

	s := Secret{
		Host: hostname,
		Mode: mode,
	}

	if _, err := rand.Read(s.Key[:]); err != nil {
		panic(err)
	}

	return s, nil
}

// ParseSecret parses a secret (both hex and base64 forms).
func ParseSecret(secret string) (Secret, error) {
	s := Secret{}

	return s, s.UnmarshalText([]byte(secret))
}
