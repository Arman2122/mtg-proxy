package mtglib

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/units"
)

// QuotaReset defines how a per-secret data quota is replenished.
type QuotaReset int32

const (
	// QuotaResetNone means the quota is a single lifetime allowance that is
	// never automatically replenished (it can still be cleared explicitly via
	// the management API).
	QuotaResetNone QuotaReset = iota

	// QuotaResetMonthly means the used-bytes counter is reset to zero at the
	// start of every calendar month.
	QuotaResetMonthly
)

// String returns the config/API spelling of the reset policy.
func (q QuotaReset) String() string {
	switch q {
	case QuotaResetMonthly:
		return "monthly"
	default:
		return "none"
	}
}

// SecretLimits carries the optional per-user governance limits attached to a
// named secret: a data quota (with an optional monthly reset), a validity
// deadline, and an on/off switch. The zero value means "no limits" — unlimited
// traffic, never expires, enabled — so a secret without an entry is unrestricted.
type SecretLimits struct {
	// QuotaBytes is the maximum number of relayed bytes (client read + write)
	// allowed in the current quota period. 0 means unlimited.
	QuotaBytes int64

	// QuotaReset selects how QuotaBytes is replenished.
	QuotaReset QuotaReset

	// ExpiresAt is the instant after which the secret stops working. The zero
	// time means the secret never expires.
	ExpiresAt time.Time

	// Disabled, when true, rejects every new connection for the secret without
	// removing it from the set.
	Disabled bool

	// SpeedBytesPerSecond is the sustained throughput this user is allowed,
	// in bytes per second, upload and download combined, across every
	// connection and every door they use at once. 0 means unlimited.
	//
	// It is a per-user allowance, not a per-connection one: two devices on
	// the same secret share it. It is enforced by holding reads and writes
	// to the rate rather than by buffering, so backpressure reaches the
	// client's own TCP window and nothing is queued in memory.
	SpeedBytesPerSecond int64

	// SpeedUpBytesPerSecond and SpeedDownBytesPerSecond cap one direction each,
	// from the client's side: up is what the client sends, down is what it
	// receives. Each is its own bucket, so a user may be given a slow upload
	// and a fast download, and both apply on top of the combined cap when that
	// is set too. 0 means unlimited.
	SpeedUpBytesPerSecond   int64
	SpeedDownBytesPerSecond int64

	// IPLimit is how many distinct addresses this user may hold connections
	// from at once, counting the addresses of their live connections here
	// together with any a panel has reported them present at elsewhere. 0
	// means unlimited.
	//
	// A connection from an address already counted is always admitted -- a
	// second socket from the same phone is the same device -- and one from a
	// new address is refused while the count is at the limit. An IPv6
	// address counts as its /64. Refusal happens at admission, after the
	// secret matched, so only a holder of the valid secret can observe it.
	IPLimit int

	// ClientConns is how many live connections one address may hold to this
	// secret at once, client-conns: the per-address connection cap. 0 means
	// unlimited.
	//
	// It is counted from the address ledger -- the same unit and the same live
	// count IPLimit reads, so a v4-mapped address is its IPv4 address and an
	// IPv6 address is its /64 -- and not from the per-address table, so it
	// holds when the table is full and counts the connections that were open
	// before it was set. A connection from an address already holding that
	// many is refused after the handshake, as an IPLimit refusal is. An
	// address that does not stand for one place (loopback, private and the
	// like: behind a carrier that forwards no client address, every client) is
	// never capped. Distinct from IPLimit, which counts places: a Telegram
	// client opens several connections, so this is set to a few times that.
	ClientConns int

	// ClientSpeedBytesPerSecond is how fast one address may move bytes on this
	// secret, upload and download combined across all of its connections,
	// client-speed: the per-address ceiling. 0 means unlimited.
	//
	// It is the address's own bucket, beside the user's SpeedBytesPerSecond,
	// which still holds the secret as a whole: an address is held to whichever
	// is reached first, and two addresses are each held to it, not to it
	// between them. An address is the unit IPLimit counts (an IPv4 address, an
	// IPv6 /64). Every peer that does not stand for one place, and every
	// address the per-address table has no room for, shares the secret's one
	// rest entry, which has no ceiling: it stands for many clients at once, and
	// one address's ceiling would hold all of them together.
	ClientSpeedBytesPerSecond int64
}

// IsZero reports whether the limits impose no restriction at all, i.e. the
// secret is unlimited, never-expiring and enabled. Callers use it to avoid
// materialising empty entries in maps and API responses.
func (l SecretLimits) IsZero() bool {
	return l.QuotaBytes == 0 && l.QuotaReset == QuotaResetNone &&
		l.ExpiresAt.IsZero() && !l.Disabled && l.SpeedBytesPerSecond == 0 &&
		l.SpeedUpBytesPerSecond == 0 && l.SpeedDownBytesPerSecond == 0 &&
		l.IPLimit == 0 && l.ClientConns == 0 && l.ClientSpeedBytesPerSecond == 0
}

// hasClientControl reports whether the limits carry a per-address control --
// client-conns, client-speed or client-fair -- which needs the per-address
// table to hold an entry for every address of the secret even when the proxy
// does not track client addresses. It is the one place that says which limits
// are per-address: admission, a reload's backfill and the secret set's own
// summary all ask it. Each control adds itself here as it lands; client-conns
// is the first.
func (l SecretLimits) hasClientControl() bool {
	return l.ClientConns > 0
}

// DenyReason explains why a connection was refused by the per-user limits.
type DenyReason int

const (
	// DenyNone means the connection is allowed.
	DenyNone DenyReason = iota

	// DenyDisabled means the secret is administratively disabled.
	DenyDisabled

	// DenyExpired means the secret's expiry deadline has passed.
	DenyExpired

	// DenyQuota means the secret has used up its data quota.
	DenyQuota

	// DenyIPLimit means the connection came from an address the user is not
	// already counted at, while they are at their address limit.
	DenyIPLimit

	// DenyClientConns means the connection came from an address that already
	// holds the per-address connection cap of live connections to this secret.
	DenyClientConns

	// DenyBanned means the connection came from an address an operator banned
	// from this secret.
	DenyBanned
)

// String returns a short machine-friendly reason label for logs.
func (d DenyReason) String() string {
	switch d {
	case DenyDisabled:
		return "disabled"
	case DenyExpired:
		return "expired"
	case DenyQuota:
		return "quota_exceeded"
	case DenyIPLimit:
		return "ip_limit"
	case DenyClientConns:
		return "client_conns"
	case DenyBanned:
		return "banned"
	default:
		return "allowed"
	}
}

// quotaBytesCleaner mirrors the config parser so the management API accepts the
// same human-friendly sizes as the config file ("10GB", "500 MiB", ...).
var quotaBytesCleaner = strings.NewReplacer(" ", "", "\t", "", "IB", "iB")

// ParseQuotaBytes parses a byte size as a bare integer count ("1048576") or a
// human-friendly unit form ("10GB", "500MiB", ...). An empty string yields 0
// (unlimited).
func ParseQuotaBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// A bare integer is interpreted as a plain byte count.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("quota must be positive (%q)", s)
		}

		return n, nil
	}

	parsed, err := units.ParseBase2Bytes(quotaBytesCleaner.Replace(strings.ToUpper(s)))
	if err != nil {
		return 0, fmt.Errorf("incorrect quota value (%q): %w", s, err)
	}

	if parsed < 0 {
		return 0, fmt.Errorf("quota must be positive (%q)", s)
	}

	return int64(parsed), nil
}

// MinSpeedBytesPerSecond is the lowest speed limit accepted: 64 kbit/s, which
// is exactly 8,000 bytes a second. Below that Telegram is not usable, and a
// bucket that small would make every read a stall; a value under it is a typo
// in the units far more often than an intention, so it is refused rather than
// honoured. Spelled in bits deliberately, so that "64kbit" -- the number the
// error message names -- is itself accepted.
const MinSpeedBytesPerSecond = 64_000 / 8

// ParseSpeed parses a speed limit into bytes per second. An empty string
// yields 0 (unlimited). Both the config file and the management API go through
// this one function, so they cannot disagree about a spelling.
//
// A bare number is bytes per second. Bit units are decimal, as every network
// link is sold -- "5mbit" is 5,000,000 bits, 625,000 bytes; byte units are
// binary, as ParseQuotaBytes reads them -- "1MB" is 1,048,576 bytes. A
// trailing "/s" or "ps" is accepted and means nothing: every value is per
// second. Case does not matter.
//
//	5mbit   500kbit   10gbit   2mbps   1MB/s   512KB/s   625000
func ParseSpeed(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, nil
	}

	lower := strings.ToLower(strings.ReplaceAll(raw, " ", ""))

	// Split the number from its unit at the first character that is not part
	// of a number.
	split := 0
	for split < len(lower) && (lower[split] >= '0' && lower[split] <= '9' || lower[split] == '.') {
		split++
	}

	number, unit := lower[:split], lower[split:]

	value, err := strconv.ParseFloat(number, 64)
	if err != nil || number == "" {
		return 0, fmt.Errorf("incorrect speed %q: want a number and a unit, like \"5mbit\" or \"1MB/s\"", s)
	}

	if value <= 0 {
		return 0, fmt.Errorf("speed must be positive (%q); leave it out for no limit", s)
	}

	unit = strings.TrimSuffix(unit, "/s")

	var bytesPerSecond float64

	switch {
	case unit == "":
		bytesPerSecond = value
	case strings.HasSuffix(unit, "bps") || strings.HasSuffix(unit, "bit"):
		prefix := strings.TrimSuffix(strings.TrimSuffix(unit, "bps"), "bit")

		multiplier, ok := map[string]float64{"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[prefix]
		if !ok {
			return 0, fmt.Errorf("incorrect speed unit in %q", s)
		}

		bytesPerSecond = value * multiplier / 8
	default:
		multiplier, ok := map[string]float64{
			"b": 1, "kb": 1 << 10, "mb": 1 << 20, "gb": 1 << 30,
			"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30,
		}[strings.TrimSuffix(unit, "ps")]
		if !ok {
			return 0, fmt.Errorf("incorrect speed unit in %q", s)
		}

		bytesPerSecond = value * multiplier
	}

	// Far beyond any link this could run on, and beyond what an int can hold
	// on the 32-bit builds; a value up here is a mistake, not a policy.
	if bytesPerSecond > 1<<40 {
		return 0, fmt.Errorf("speed %q is unreasonably large", s)
	}

	if bytesPerSecond < MinSpeedBytesPerSecond {
		return 0, fmt.Errorf("speed %q is below the minimum of 64kbit/s (8000 bytes/s)", s)
	}

	return int64(bytesPerSecond), nil
}

// ParseQuotaReset parses the reset policy spelling. Empty and "none" both map to
// QuotaResetNone.
func ParseQuotaReset(s string) (QuotaReset, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return QuotaResetNone, nil
	case "monthly":
		return QuotaResetMonthly, nil
	default:
		return QuotaResetNone, fmt.Errorf("unknown quota reset %q (want \"none\" or \"monthly\")", s)
	}
}

// ParseExpiry parses an expiry deadline in RFC3339 ("2026-12-31T00:00:00Z") or
// plain date ("2026-12-31") form. An empty string yields the zero time (never).
func ParseExpiry(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid expiry %q (want RFC3339 or YYYY-MM-DD)", s)
}
