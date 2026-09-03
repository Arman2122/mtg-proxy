package obfuscation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The wire values are the protocol; a typo here silently changes which clients
// can connect, so they are pinned as literals rather than derived.
func TestConnectionTagWireValues(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ConnectionTag{0xdd, 0xdd, 0xdd, 0xdd}, TagPaddedIntermediate)
	assert.Equal(t, ConnectionTag{0xee, 0xee, 0xee, 0xee}, TagIntermediate)
	assert.Equal(t, ConnectionTag{0xef, 0xef, 0xef, 0xef}, TagAbridged)
}

// hfConnectionType is what SendHandshake emitted before the tag was a parameter;
// it must stay the padded-intermediate tag or every existing client breaks.
func TestHFConnectionTypeIsPaddedIntermediate(t *testing.T) {
	t.Parallel()

	assert.Equal(t, TagPaddedIntermediate[:], hfConnectionType[:])
}

func TestConnectionTagString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "padded-intermediate", TagPaddedIntermediate.String())
	assert.Equal(t, "intermediate", TagIntermediate.String())
	assert.Equal(t, "abridged", TagAbridged.String())
	assert.Equal(t, "01020304", ConnectionTag{0x01, 0x02, 0x03, 0x04}.String())
}

func TestConnectionTagValid(t *testing.T) {
	t.Parallel()

	assert.True(t, TagPaddedIntermediate.Valid())
	assert.True(t, TagIntermediate.Valid())
	assert.True(t, TagAbridged.Valid())
	assert.False(t, ConnectionTag{}.Valid())
	assert.False(t, ConnectionTag{0xdd, 0xdd, 0xdd, 0xde}.Valid())
}

func TestTagSetSemantics(t *testing.T) {
	t.Parallel()

	var empty TagSet

	assert.True(t, empty.Empty())
	assert.False(t, empty.Has(TagPaddedIntermediate))
	assert.Equal(t, "", empty.String())

	one := TagSetOf(TagPaddedIntermediate)
	assert.False(t, one.Empty())
	assert.True(t, one.Has(TagPaddedIntermediate))
	assert.False(t, one.Has(TagIntermediate))
	assert.False(t, one.Has(TagAbridged))
	assert.Equal(t, "padded-intermediate", one.String())

	// Idempotent, and order of construction does not matter.
	assert.Equal(t, one, one.With(TagPaddedIntermediate))
	assert.Equal(t,
		TagSetOf(TagAbridged, TagIntermediate),
		TagSetOf(TagIntermediate, TagAbridged))

	// Each transport owns a distinct bit: honouring one must never silently
	// honour another, or "dd" would admit abridged clients.
	assert.False(t, TagSetOf(TagIntermediate).Has(TagAbridged))
	assert.False(t, TagSetOf(TagIntermediate).Has(TagPaddedIntermediate))
	assert.False(t, TagSetOf(TagAbridged).Has(TagIntermediate))
	assert.False(t, TagSetOf(TagAbridged).Has(TagPaddedIntermediate))
	assert.NotEqual(t, TagSetOf(TagIntermediate), TagSetOf(TagAbridged))

	all := TagSetOf(TagPaddedIntermediate, TagIntermediate, TagAbridged)
	assert.True(t, all.Has(TagPaddedIntermediate))
	assert.True(t, all.Has(TagIntermediate))
	assert.True(t, all.Has(TagAbridged))
	assert.Equal(t, "padded-intermediate,intermediate,abridged", all.String())
}

// An unrecognised tag has no bit, so it can never be added to a set and never
// answers Has. That is what keeps a garbage frame from being admitted by a set
// that happens to have every bit set.
func TestTagSetIgnoresUnknownTag(t *testing.T) {
	t.Parallel()

	unknown := ConnectionTag{0xaa, 0xbb, 0xcc, 0xdd}

	assert.True(t, TagSet(0).With(unknown).Empty())
	assert.False(t, TagSet(0xff).Has(unknown))
	assert.False(t, TagSetOf(TagPaddedIntermediate, TagIntermediate, TagAbridged).Has(unknown))
}

// Covers is containment, not overlap. It answers "would this listener serve
// every transport a client of that secret form might pick", which is what the
// unserved-secret warning turns on: a plain-honouring listener covers a dd
// secret, but a dd-only listener does not cover a plain one.
func TestTagSetCovers(t *testing.T) {
	t.Parallel()

	var (
		empty  TagSet
		padded = TagSetOf(TagPaddedIntermediate)
		all    = TagSetOf(TagPaddedIntermediate, TagIntermediate, TagAbridged)
	)

	assert.True(t, all.Covers(padded), "an all-transport listener serves a dd secret")
	assert.False(t, padded.Covers(all), "a dd-only listener does not serve a plain secret")

	assert.True(t, empty.Covers(empty))
	assert.True(t, padded.Covers(empty), "everything covers the empty set")
	assert.False(t, empty.Covers(padded), "no listener covers anything")

	assert.True(t, padded.Covers(padded), "covers is reflexive")
	assert.False(t, padded.Covers(TagSetOf(TagAbridged)), "disjoint sets do not cover")
}
