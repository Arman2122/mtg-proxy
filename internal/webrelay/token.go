package webrelay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
)

// Token layout. A token is 32 opaque bytes -- a 16-byte nonce and 16 bytes of
// MAC over it -- carried as 43 characters of unpadded base64url, the same
// spelling and length as a bridge capability.
//
// # What the MAC is for, and what it is not for
//
// It establishes provenance only: that this process, or a previous run of it
// holding the same key, minted the value. It authorises nothing. Session state,
// bootstrap expiry, single use, the request method and the request path are all
// still checked afterwards, and a token that passes the MAC and fails any of
// them is refused.
//
// The reason to have it at all is the origin's three-tier rule. A request
// carrying a token this relay minted must never be handed to the cover site,
// even when the token is expired, spent, or presented on the wrong path --
// otherwise an operator's real credential lands in a third party's access log.
// Recognising one after a restart, or after the session it belonged to is gone,
// needs a key that outlives both. That is the whole job.
const (
	tokenNonceSize = 16
	tokenMACSize   = 16
	tokenSize      = tokenNonceSize + tokenMACSize

	// TokenLength is the number of characters a token occupies in a header.
	TokenLength = 43

	// TokenKeySize is the length of the signing key on disk.
	TokenKeySize = 32
)

// tokenLabel pins the derivation. The trailing NUL separates the label from the
// kind byte so no label can ever be a prefix of another.
const tokenLabel = "tproxy-server-token-v1\x00"

// TokenKind distinguishes the two credentials, so a bootstrap can never be
// presented as a session token or the other way round.
type TokenKind byte

// The two kinds.
const (
	// KindBootstrap is minted into one bridge page and spent once, on session
	// creation.
	KindBootstrap TokenKind = 0x01

	// KindSession authenticates the carrier and the teardown request.
	KindSession TokenKind = 0x02
)

var (
	// ErrTokenKeyMissing means the signing key file is absent. It is never
	// generated silently: an ephemeral key would work perfectly until the
	// relay restarts, at which point every token it ever minted becomes
	// unrecognisable and starts leaking to the cover site.
	ErrTokenKeyMissing = errors.New("WEB relay token key file is missing")

	// ErrTokenKeySize means the key file is not exactly TokenKeySize bytes.
	ErrTokenKeySize = errors.New("WEB relay token key file is the wrong size")

	// ErrTokenKeyPermissions means the key file is readable by group or other.
	ErrTokenKeyPermissions = errors.New("WEB relay token key file is readable by group or other")
)

// Signer mints and recognises tokens.
type Signer struct {
	key []byte
}

// NewSigner builds a signer from raw key bytes.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) != TokenKeySize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrTokenKeySize, len(key), TokenKeySize)
	}

	return &Signer{key: append([]byte(nil), key...)}, nil
}

// LoadTokenKey reads the persistent signing key.
//
// Every failure here is a startup failure. A relay that generated its own key
// when the file was missing would run correctly until the first restart and
// then answer its own live clients with the cover site; one that accepted a
// world-readable key would let anyone who can read it mint credentials that
// look authentic to the recognition tier.
func LoadTokenKey(path string) (*Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTokenKeyMissing, path)
	}

	// Windows does not express this in mode bits -- its ACLs are not a
	// permission triple -- so the check applies where it means something rather
	// than being approximated where it does not.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is %#o, want 0600", ErrTokenKeyPermissions, path, info.Mode().Perm())
	}

	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the token key %s: %w", path, err)
	}

	return NewSigner(key)
}

// GenerateTokenKey writes a new signing key, refusing to overwrite one. Rotating
// it invalidates every live session, so replacing a file is always a deliberate
// act rather than a side effect of running a command twice.
func GenerateTokenKey(path string) error {
	key := make([]byte, TokenKeySize)

	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("cannot draw a token key: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create the token key %s: %w", path, err)
	}

	defer file.Close()

	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("cannot write the token key %s: %w", path, err)
	}

	return nil
}

// Mint returns a fresh token of one kind.
func (s *Signer) Mint(kind TokenKind) (string, error) {
	raw := make([]byte, tokenSize)

	if _, err := rand.Read(raw[:tokenNonceSize]); err != nil {
		return "", fmt.Errorf("cannot draw a token nonce: %w", err)
	}

	copy(raw[tokenNonceSize:], s.mac(kind, raw[:tokenNonceSize]))

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Verify reports whether token is an authentic token of exactly this kind. It
// says nothing about whether the operation it is presented for is allowed.
func (s *Signer) Verify(token string, kind TokenKind) bool {
	raw, ok := decodeToken(token)
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare(raw[tokenNonceSize:], s.mac(kind, raw[:tokenNonceSize])) == 1
}

// IsAuthentic reports whether token is an authentic token of ANY kind. This is
// the tier-two test: a true answer means the request must be answered locally
// with an uncacheable 404 rather than handed to the cover site, whatever else is
// wrong with it.
//
// Both kinds are always checked, with no early return, so the answer's duration
// does not say which kind was presented.
func (s *Signer) IsAuthentic(token string) bool {
	raw, ok := decodeToken(token)
	if !ok {
		return false
	}

	found := 0

	for _, kind := range []TokenKind{KindBootstrap, KindSession} {
		found |= subtle.ConstantTimeCompare(raw[tokenNonceSize:], s.mac(kind, raw[:tokenNonceSize]))
	}

	return found == 1
}

func (s *Signer) mac(kind TokenKind, nonce []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(tokenLabel))
	mac.Write([]byte{byte(kind)})
	mac.Write(nonce)

	return mac.Sum(nil)[:tokenMACSize]
}

// decodeToken accepts only the canonical spelling, for the same reason a
// capability does: a padded or standard-alphabet variant of a real token is
// still a real token, and the lenient forms belong to the recognition tier, not
// to the decoder that authorises an operation.
func decodeToken(token string) ([]byte, bool) {
	if len(token) != TokenLength {
		return nil, false
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != tokenSize {
		return nil, false
	}

	if base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, false
	}

	return raw, true
}
