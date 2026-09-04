// Package webrelay is the server side of the WEB proxy v1 transport a Telegram
// client reaches over HTTPS. This file holds the bridge capability: the value a
// client derives from its own hostname and secret, and the only thing a request
// presents to pick one configured profile.
//
// # The three recognition tiers
//
// Recognition is a security invariant, not a routing convenience, and a handler
// must place every request into exactly one of three tiers:
//
//   - Exact. An exact GET / carrying one canonical CapabilityLength parameter
//     that [Registry.Lookup] resolves. Serve the bridge page.
//   - Authentic but unusable. [Registry.IsAuthentic] says the value is a
//     spelling of a configured capability, but something else disqualifies it:
//     a padded or standard-alphabet spelling, a set unused trailing bit, the
//     wrong path, the wrong method, a duplicated query field. Answer LOCALLY
//     with an uncacheable 404. Never proxy such a request to the public site --
//     that would write an operator's real capability into a third party's
//     access log, which is the leak this tier exists to prevent.
//   - Unauthentic. Everything else. Serve the ordinary cover site, unaltered,
//     so the origin looks like the website it claims to be.
//
// Two obligations the registry cannot enforce for the caller:
//
//   - Percent decoding is the caller's job. Both entry points compare the
//     string they are given, so pass the decoded value -- and decode it with
//     [net/url.PathUnescape] or off RawQuery, not with [net/url.Values] or
//     [net/url.QueryUnescape]. Those two turn the standard base64 alphabet's
//     "+" into a space, which is exactly one of the tier-two disguises.
//     [ParseCapabilityLenient] undoes that mangling anyway, but only because
//     the leak it would otherwise cause is unrecoverable.
//   - A repeated query field must be tested in full. Test EVERY value the
//     request carries under the bridge key, not the one net/url happens to
//     return first, or a duplicate field smuggles a capability past tier two.
package webrelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"golang.org/x/net/idna"
)

// bridgeContextLabel pins the v1 derivation. Both the text and its trailing
// newline are HMAC input, so editing either would silently rotate every
// capability already handed out and every client would then miss the lookup.
// The name mentions one client but the value is not client-specific.
const bridgeContextLabel = "tdesktop-web-proxy-bridge-v1\n"

// CapabilityLength is the number of characters a derived capability occupies in
// a bridge query: 32 bytes of HMAC-SHA256 in unpadded base64url.
const CapabilityLength = 43

// MaxProfiles bounds the configured profile set. Every request scans the whole
// set without breaking early -- that is what keeps the scan constant-time -- so
// the set length is per-request work an operator chooses, and an unbounded one
// would turn a config edit into a slow-loris amplifier. The ceiling is far above
// any real inbound: a scan of this many 32-byte comparisons is tens of
// microseconds.
const MaxProfiles = 4096

var (
	// ErrInvalidHost means the hostname is not the canonical form both sides
	// must agree on before they derive anything.
	ErrInvalidHost = errors.New("hostname is not a canonical WEB proxy host")

	// ErrUnsupportedSecretMode means the secret cannot be handed to a WEB
	// client at all.
	ErrUnsupportedSecretMode = errors.New("secret mode is not usable for a WEB proxy")

	// ErrCapabilityCollision means two configured profiles derive the same
	// capability, so a request could not name one of them.
	ErrCapabilityCollision = errors.New("two profiles derive the same bridge capability")

	// ErrNoProfiles means the profile set is empty. A registry that can match
	// nothing answers every request with the cover site, which looks exactly
	// like a working relay whose clients all typed the wrong hostname.
	ErrNoProfiles = errors.New("no WEB proxy profiles configured")

	// ErrTooManyProfiles means the profile set is above MaxProfiles.
	ErrTooManyProfiles = errors.New("more WEB proxy profiles than the maximum")

	// ErrInvalidSecret means the secret is not a usable one -- in practice an
	// empty key, whose capability anyone could derive without knowing anything.
	ErrInvalidSecret = errors.New("secret is not valid")
)

// hostProfile is the IDNA profile used for canonicalisation. Lookup mapping
// lowercases and folds; StrictDomainName keeps the result to the LDH letter set
// a DNS hostname may use; VerifyDNSLength enforces the 63-byte label and
// 253-byte name limits the client contract also imposes.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// Capability is the 32-byte value a client derives from its configured hostname
// and secret and presents as the bridge query parameter.
type Capability [sha256.Size]byte

// String renders the capability the way it travels in the query: unpadded
// base64url, always CapabilityLength characters.
func (c Capability) String() string {
	return base64.RawURLEncoding.EncodeToString(c[:])
}

// CanonicalHost normalises a configured hostname into the exact bytes the
// client hashes. Anything the client would refuse to store is an error here
// rather than a silently different capability, because a mismatch shows up only
// as every real client missing the lookup.
//
// Note for internationalised names: the ACE (xn--) form is the only input
// guaranteed to round-trip identically on every client. A hand-typed Unicode
// host can be mapped differently by different client toolkit versions and then
// derive a capability this server never computes.
func CanonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidHost)
	}

	// IDNA mapping replaces invalid bytes with U+FFFD and then punycodes the
	// result, so a config saved in a legacy 8-bit codepage would derive a
	// capability over the WRONG A-label -- accepted, logged nowhere, and
	// unreachable by every real client.
	if !utf8.ValidString(host) {
		return "", fmt.Errorf("%w: %q is not valid UTF-8", ErrInvalidHost, host)
	}

	// A scheme, port, path, query, fragment or userinfo means the operator
	// pasted a URL. Rejected before mapping, because IDNA mapping can turn
	// exotic runes into these very delimiters.
	if idx := strings.IndexAny(host, ":/?#@"); idx >= 0 {
		return "", fmt.Errorf("%w: %q must not contain %q", ErrInvalidHost, host, host[idx])
	}

	ascii, err := hostProfile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrInvalidHost, host, err)
	}

	// Re-checked on the OUTPUT: U+FF0E and friends become "." only after
	// mapping, so a pre-check alone cannot see the resulting label structure.
	for _, r := range ascii {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return "", fmt.Errorf("%w: %q maps to %q, which is not lowercase LDH",
				ErrInvalidHost, host, ascii)
		}
	}

	// Canonicalisation must be a fixed point: the client hashes exactly these
	// bytes, so mapping them again has to be a no-op. Asserted rather than
	// assumed, because it catches ANY future asymmetry in x/net/idna, not only
	// the non-UTF-8 one rejected above.
	remapped, err := hostProfile.ToASCII(ascii)
	if err != nil {
		return "", fmt.Errorf("%w: %q maps to %q, which is not itself mappable: %w",
			ErrInvalidHost, host, ascii, err)
	}

	if remapped != ascii {
		return "", fmt.Errorf("%w: %q maps to %q, which maps on to %q",
			ErrInvalidHost, host, ascii, remapped)
	}

	// A trailing dot is a different string and would hash differently; the
	// client stores the name without one, so reject rather than strip.
	if strings.HasSuffix(ascii, ".") {
		return "", fmt.Errorf("%w: %q has a trailing dot", ErrInvalidHost, host)
	}

	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") {
		return "", fmt.Errorf("%w: %q has an empty label", ErrInvalidHost, host)
	}

	// An IP literal has no certificate story and is not a DNS hostname. This
	// catches dotted-quad and (via the delimiter check above) bracketed IPv6.
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", fmt.Errorf("%w: %q is an IP address", ErrInvalidHost, host)
	}

	// Single-label names cannot hold a public certificate; this is also what
	// rejects "localhost".
	if !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("%w: %q is a single-label name", ErrInvalidHost, host)
	}

	return ascii, nil
}

// Derive computes the bridge capability for a secret on a host. The secret's
// bytes are the HMAC KEY in the wire form a client is given -- including the
// leading 0xdd of a dd secret, so dd and plain spellings of the same 16 key
// bytes deliberately derive different capabilities.
//
// host is canonicalised here; pass the raw configured value.
func Derive(secret mtglib.Secret, host string) (Capability, error) {
	canonical, err := CanonicalHost(host)
	if err != nil {
		return Capability{}, err
	}

	// A WEB-capable client refuses an ee secret outright, before any network
	// activity, so deriving one would only produce a capability nothing can
	// present. WEB profiles are dd or plain. Checked before the key, so an
	// operator who configured the wrong FORM is told that, which is the
	// actionable half of the two.
	var key []byte

	switch secret.Mode {
	case mtglib.SecretModeDD:
		key = append([]byte{0xdd}, secret.Key[:]...)
	case mtglib.SecretModePlain:
		key = secret.Key[:]
	default: // mtglib.SecretModeFakeTLS
		return Capability{}, fmt.Errorf("%w: %s (WEB accepts dd or plain)",
			ErrUnsupportedSecretMode, secret.Mode)
	}

	// An all-zero key is the one Secret a caller can hold by accident -- an
	// unparsed field, a zero struct -- and its capability is derivable by
	// anyone, since the key is the only secret input. Refused here rather than
	// in the registry so no path can reach the HMAC with it.
	if !secret.Valid() {
		return Capability{}, fmt.Errorf("%w: %s secret with an empty key",
			ErrInvalidSecret, secret.Mode)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(bridgeContextLabel + canonical))

	return Capability(mac.Sum(nil)), nil
}

// ParseCapability decodes a bridge query parameter, accepting only the one
// canonical spelling of a 32-byte value. Strict decoding rejects a 43rd
// character whose unused low bits are set, and the re-encode comparison is the
// same rule stated a second way.
func ParseCapability(param string) (Capability, bool) {
	if len(param) != CapabilityLength {
		return Capability{}, false
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(param)
	if err != nil || len(decoded) != sha256.Size {
		return Capability{}, false
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != param {
		return Capability{}, false
	}

	return Capability(decoded), true
}

// lenientEncodings are the base64 spellings a 32-byte capability can be written
// in. Order is irrelevant: each rejects the others' alphabet or padding, so at
// most one can decode a given string.
var lenientEncodings = [...]*base64.Encoding{
	base64.RawURLEncoding,
	base64.URLEncoding,
	base64.RawStdEncoding,
	base64.StdEncoding,
}

// ParseCapabilityLenient decodes a bridge parameter under every base64 spelling
// of a 32-byte value: either alphabet, padded or not, and -- because these
// decoders are not Strict -- with the 43rd character's unused low bits set.
//
// It exists to recognise an AUTHENTIC capability that arrived in a form the
// bridge cannot be served for, so the request can be answered locally instead of
// being handed upstream with a real capability in its query. It is deliberately
// wider than [ParseCapability] and must never gate serving the bridge.
func ParseCapabilityLenient(param string) (Capability, bool) {
	if capability, ok := decodeAnyBase64(param); ok {
		return capability, true
	}

	// net/url's query decoders turn "+" into a space, so a handler that used
	// one hands us a mangled spelling of a genuine capability. Undoing it here
	// is cheaper than the alternative: calling it unauthentic sends a real
	// capability to the public site's access log.
	if strings.ContainsRune(param, ' ') {
		return decodeAnyBase64(strings.ReplaceAll(param, " ", "+"))
	}

	return Capability{}, false
}

func decodeAnyBase64(param string) (Capability, bool) {
	for _, encoding := range lenientEncodings {
		decoded, err := encoding.DecodeString(param)
		if err == nil && len(decoded) == sha256.Size {
			return Capability(decoded), true
		}
	}

	return Capability{}, false
}

// Registry resolves a presented bridge parameter to one of the profiles the
// operator configured, without revealing through timing which of them matched.
type Registry struct {
	capabilities []Capability
}

// WebSecret re-expresses a secret's key in the one form a WEB client can hold.
// The three forms are spellings of the same 16 bytes, so a panel that mints ee
// secrets needs no second credential: this is the same key, told to the client
// as dd.
//
// dd rather than plain, deliberately. Both are accepted by the client, but the
// dd form makes every stream padded-intermediate, which is the transport the
// ad-tag path supports -- a plain WEB client with an ad tag would silently lose
// its sponsored channel.
func WebSecret(secret mtglib.Secret) mtglib.Secret {
	return mtglib.Secret{Key: secret.Key, Mode: mtglib.SecretModeDD}
}

// NewRegistry derives a capability for every profile secret against one public
// hostname, in the caller's order. Collisions are rejected because a request
// carrying that capability could not name a single profile.
//
// Pass secrets through [WebSecret] first unless they are already dd or plain:
// Derive refuses an ee secret, because the client refuses one too.
func NewRegistry(host string, secrets []mtglib.Secret) (*Registry, error) {
	switch {
	case len(secrets) == 0:
		return nil, ErrNoProfiles
	case len(secrets) > MaxProfiles:
		return nil, fmt.Errorf("%w: %d, maximum %d", ErrTooManyProfiles, len(secrets), MaxProfiles)
	}

	registry := &Registry{capabilities: make([]Capability, 0, len(secrets))}

	for i, secret := range secrets {
		capability, err := Derive(secret, host)
		if err != nil {
			return nil, fmt.Errorf("profile %d: %w", i, err)
		}

		for j, other := range registry.capabilities {
			if other == capability {
				return nil, fmt.Errorf("%w: profiles %d and %d", ErrCapabilityCollision, j, i)
			}
		}

		registry.capabilities = append(registry.capabilities, capability)
	}

	return registry, nil
}

// Len is the number of configured profiles.
func (r *Registry) Len() int {
	return len(r.capabilities)
}

// Lookup returns the index of the profile a bridge parameter selects, in the
// order the profiles were given to NewRegistry. A false result does NOT mean the
// value was unauthentic; ask [Registry.IsAuthentic] before falling through to
// the cover site.
//
// The scan visits every entry and never breaks early, so its duration does not
// depend on WHICH profile matched or on whether one did -- that would tell an
// unauthenticated prober something about the secrets this server holds. Parse
// failures do return early: they depend only on the attacker's own input.
func (r *Registry) Lookup(param string) (int, bool) {
	presented, ok := ParseCapability(param)
	if !ok {
		return 0, false
	}

	index, found := 0, 0

	for i, capability := range r.capabilities {
		match := subtle.ConstantTimeCompare(capability[:], presented[:])
		index = subtle.ConstantTimeSelect(match, i, index)
		found |= match
	}

	return index, found == 1
}

// IsAuthentic reports whether a presented value is any spelling at all of a
// configured capability -- the tier-two test described in the package doc. A
// true answer means the request must be answered with a local uncacheable 404,
// never delegated to the cover site.
//
// It returns no index on purpose: an index would invite a caller to serve the
// bridge on a lenient match, which is exactly the tier boundary this method
// exists to draw. Only [Registry.Lookup] may select a profile.
//
// The scan is the same non-breaking constant-time one Lookup uses.
func (r *Registry) IsAuthentic(param string) bool {
	presented, ok := ParseCapabilityLenient(param)
	if !ok {
		return false
	}

	found := 0

	for _, capability := range r.capabilities {
		found |= subtle.ConstantTimeCompare(capability[:], presented[:])
	}

	return found == 1
}
