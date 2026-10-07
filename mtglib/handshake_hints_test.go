package mtglib

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hint cache on its own: what an address is keyed by, which addresses are
// keyed at all, and the bounds.

// hintedAddress is the i-th of a run of distinct keyed addresses, one per IPv6
// /64 inside the documentation prefix 2001:db8::/32, which holds 2^32 of them.
func hintedAddress(i int) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, []byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
	ip[15] = 1

	return ip
}

func hintsSize(h *matchHints) (current, previous int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.current), len(h.previous)
}

func TestHintKeyIsTheLimiterKeyOfARoutableAddress(t *testing.T) {
	t.Parallel()

	// Every address the end-to-end hint tests connect from is here: they are the
	// documentation ranges, and the tests are worthless if those read as
	// private or loopback (the harness's own peers are loopback, and unkeyed).
	keyed := map[string]string{
		"203.0.113.7":                     "203.0.113.7",
		"203.0.113.200":                   "203.0.113.200",
		"198.51.100.20":                   "198.51.100.20",
		"192.0.2.33":                      "192.0.2.33",
		"::ffff:203.0.113.7":              "203.0.113.7",
		"2001:db8::1":                     "2001:db8::",
		"2001:db8:1:2::1":                 "2001:db8:1:2::",
		"2001:db8:1:2:aaaa:bbbb:cccc:ddd": "2001:db8:1:2::",
	}

	for text, want := range keyed {
		ip := net.ParseIP(text)
		require.NotNil(t, ip, text)

		got, ok := hintKey(ip)
		require.True(t, ok, "%s is a routable address and must be keyed", text)
		assert.Equal(t, netip.MustParseAddr(want), got, text)

		limiter, ok := limiterKey(ip)
		require.True(t, ok, text)
		assert.Equal(t, limiter, got, "%s: the hint key is the limiter's key", text)
	}

	// The 4-byte and the 16-byte (v4-mapped) forms of one IPv4 address are one
	// key (Review Focus 1).
	short, ok := hintKey(net.IPv4(203, 0, 113, 7).To4())
	require.True(t, ok)

	long, ok := hintKey(net.IPv4(203, 0, 113, 7).To16())
	require.True(t, ok)
	assert.Equal(t, short, long)
}

func TestHintKeyRefusesAddressesThatAreNotOnePlace(t *testing.T) {
	t.Parallel()

	unkeyed := []string{
		// loopback, both families, and a v4 loopback written v4-mapped
		"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1",
		// private, both families
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "::ffff:10.1.2.3", "fd00::1", "fc00::1",
		// link-local unicast
		"169.254.1.1", "::ffff:169.254.1.1", "fe80::1",
		// unspecified
		"0.0.0.0", "::",
		// multicast is not a client
		"224.0.0.1", "ff02::1",
	}

	for _, text := range unkeyed {
		ip := net.ParseIP(text)
		require.NotNil(t, ip, text)

		_, ok := hintKey(ip)
		assert.False(t, ok, "%s must not be keyed", text)
	}

	for name, ip := range map[string]net.IP{"nil": nil, "empty": {}, "three bytes": {1, 2, 3}} {
		_, ok := hintKey(ip)
		assert.False(t, ok, "%s is no address", name)
	}
}

func TestHintsAreMostRecentFirstAndMoveToFront(t *testing.T) {
	t.Parallel()

	h := newMatchHints(t.Context())
	ip := net.ParseIP("203.0.113.7")

	assert.Nil(t, h.recall(ip), "an address never seen has no hints")

	h.remember(ip, "alice")
	h.remember(ip, "bob")
	h.remember(ip, "carol")
	assert.Equal(t, []string{"carol", "bob", "alice"}, h.recall(ip))

	h.remember(ip, "alice")
	assert.Equal(t, []string{"alice", "carol", "bob"}, h.recall(ip), "a name seen again moves to the front")

	h.remember(ip, "alice")
	assert.Equal(t, []string{"alice", "carol", "bob"}, h.recall(ip), "and is never listed twice")

	got := h.recall(ip)
	require.NotEmpty(t, got)
	got[0] = "mallory"
	assert.Equal(t, []string{"alice", "carol", "bob"}, h.recall(ip), "recall hands out a copy")

	assert.Nil(t, h.recall(net.ParseIP("203.0.113.8")), "a hint belongs to its own address")

	h.remember(ip, "")
	assert.Equal(t, []string{"alice", "carol", "bob"}, h.recall(ip), "the empty name is not a secret")
}

func TestHintsKeepSixteenNamesAndDropTheOldest(t *testing.T) {
	t.Parallel()

	h := newMatchHints(t.Context())
	ip := net.ParseIP("198.51.100.20")

	want := make([]string, 0, maxHintNames)

	for i := range maxHintNames {
		name := fmt.Sprintf("n%02d", i)
		h.remember(ip, name)
		want = append([]string{name}, want...)
	}

	require.Equal(t, 16, maxHintNames)
	require.Equal(t, want, h.recall(ip))

	h.remember(ip, "n16")

	got := h.recall(ip)
	assert.Len(t, got, maxHintNames)
	assert.Equal(t, "n16", got[0])
	assert.Equal(t, "n01", got[maxHintNames-1], "n00 was the oldest and is the one that went")
	assert.NotContains(t, got, "n00")

	// The oldest that is left, seen again: it moves to the front, nothing is
	// dropped.
	h.remember(ip, "n01")

	got = h.recall(ip)
	assert.Len(t, got, maxHintNames)
	assert.Equal(t, []string{"n01", "n16", "n15"}, got[:3])
	assert.Equal(t, "n02", got[maxHintNames-1])
}

func TestHintsDropNewAddressesWhenFullAndNeverEvict(t *testing.T) {
	t.Parallel()

	h := newMatchHints(t.Context())

	require.Equal(t, 32768, maxHintAddresses)

	for i := range maxHintAddresses {
		h.remember(hintedAddress(i), "alice")
	}

	newcomer := hintedAddress(maxHintAddresses)

	h.remember(newcomer, "bob")
	assert.Nil(t, h.recall(newcomer), "a full cache does not take a new address")

	// It took nothing from anyone to say so: every address it holds is still
	// there, and an address it holds is still updated.
	for i := range maxHintAddresses {
		require.Equal(t, []string{"alice"}, h.recall(hintedAddress(i)), "address %d", i)
	}

	h.remember(hintedAddress(0), "bob")
	assert.Equal(t, []string{"bob", "alice"}, h.recall(hintedAddress(0)))

	// One rotation demotes the full generation: still full, still nothing new.
	h.rotate()

	current, previous := hintsSize(h)
	assert.Equal(t, 0, current)
	assert.Equal(t, maxHintAddresses, previous)

	h.remember(newcomer, "bob")
	assert.Nil(t, h.recall(newcomer), "the older generation still counts until it is dropped")

	// A demoted address is still recalled, and remembering it again promotes it
	// without growing the total.
	assert.Equal(t, []string{"alice"}, h.recall(hintedAddress(1)))

	h.remember(hintedAddress(1), "carol")
	assert.Equal(t, []string{"carol", "alice"}, h.recall(hintedAddress(1)))

	current, previous = hintsSize(h)
	assert.Equal(t, 1, current)
	assert.Equal(t, maxHintAddresses-1, previous, "a promotion moves an address, it does not copy it")

	h.remember(newcomer, "bob")
	assert.Nil(t, h.recall(newcomer))

	// The second rotation drops the generation nobody used: room again.
	h.rotate()

	assert.Equal(t, []string{"carol", "alice"}, h.recall(hintedAddress(1)), "the promoted address survives")
	assert.Nil(t, h.recall(hintedAddress(2)), "an address unused for two rotations is gone")

	h.remember(newcomer, "bob")
	assert.Equal(t, []string{"bob"}, h.recall(newcomer))
}

// Review Focus 1: an IPv4 address and its v4-mapped form, and two hosts in one
// IPv6 /64, are one place.
func TestHintsShareAKeyAcrossMappedFormsAndAPrefix(t *testing.T) {
	t.Parallel()

	h := newMatchHints(t.Context())

	h.remember(net.IPv4(203, 0, 113, 7).To4(), "alice")
	assert.Equal(t, []string{"alice"}, h.recall(net.ParseIP("::ffff:203.0.113.7")))

	h.remember(net.ParseIP("2001:db8:1:2::1"), "bob")
	assert.Equal(t, []string{"bob"}, h.recall(net.ParseIP("2001:db8:1:2:ffff:ffff:ffff:9")),
		"two hosts in one /64 are one key")
	assert.Nil(t, h.recall(net.ParseIP("2001:db8:1:3::1")), "two /64s are two keys")
}

// Review Focus 2: an address that is not one place gets no hint, and remember
// keeps nothing for it -- recall is not just hiding it.
func TestUnkeyedPeersGetNoHints(t *testing.T) {
	t.Parallel()

	h := newMatchHints(t.Context())

	for _, ip := range []net.IP{
		nil,
		{},
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("10.0.0.7"),
		net.ParseIP("192.168.1.7"),
		net.ParseIP("169.254.0.7"),
		net.ParseIP("fe80::7"),
		net.ParseIP("fd00::7"),
		net.ParseIP("0.0.0.0"),
		net.ParseIP("::"),
	} {
		h.remember(ip, "alice")
		assert.Nil(t, h.recall(ip), "%v", ip)
	}

	current, previous := hintsSize(h)
	assert.Zero(t, current, "nothing was stored for an unkeyed peer")
	assert.Zero(t, previous)
}

// A Proxy{} literal has no cache: every method is "hints off".
func TestANilHintCacheIsOff(t *testing.T) {
	t.Parallel()

	var (
		h   *matchHints
		got []string
	)

	ip := net.ParseIP("203.0.113.7")

	assert.NotPanics(t, func() { h.remember(ip, "alice") }, "remember on a nil cache")
	assert.NotPanics(t, func() { h.rotate() }, "rotate on a nil cache")
	assert.NotPanics(t, func() { got = h.recall(ip) }, "recall on a nil cache")
	assert.Nil(t, got, "a nil cache has no hints")
}
