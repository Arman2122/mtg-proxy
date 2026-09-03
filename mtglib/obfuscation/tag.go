package obfuscation

import (
	"encoding/hex"
	"strings"
)

// ConnectionTag is the 4-byte transport selector at frame offset 56. It decides
// how the INNER MTProto stream is framed, and everything above the obfuscation
// layer is a byte-transparent io.CopyBuffer, so the tag we announce to Telegram
// must be the client's own -- announcing a different one corrupts every packet.
type ConnectionTag [hfLenConnectionType]byte

// The three transports Telegram clients select at frame offset 56.
//
// These are arrays, so they cannot be constants; treat them as read-only.
var (
	TagPaddedIntermediate = ConnectionTag{0xdd, 0xdd, 0xdd, 0xdd}
	TagIntermediate       = ConnectionTag{0xee, 0xee, 0xee, 0xee}
	TagAbridged           = ConnectionTag{0xef, 0xef, 0xef, 0xef}
)

func (t ConnectionTag) String() string {
	switch t {
	case TagPaddedIntermediate:
		return "padded-intermediate"
	case TagIntermediate:
		return "intermediate"
	case TagAbridged:
		return "abridged"
	}

	return hex.EncodeToString(t[:])
}

// Valid reports whether this is one of the three transports we can relay.
func (t ConnectionTag) Valid() bool {
	return tagBit(t) != 0
}

// TagSet is a small set of accepted connection types. A set rather than a single
// tag because "plain" is three transports, not one.
type TagSet uint8

// tagBit maps a tag onto its TagSet bit. An unrecognised tag maps to 0, so With
// is a no-op for it and Has always answers false -- an unknown transport can
// never be admitted by construction.
func tagBit(tag ConnectionTag) TagSet {
	switch tag {
	case TagPaddedIntermediate:
		return 1 << 0
	case TagIntermediate:
		return 1 << 1
	case TagAbridged:
		return 1 << 2
	}

	return 0
}

// orderedTags is the iteration order of TagSet.String, matching the bit order of
// tagBit so the rendering is stable across runs.
var orderedTags = []ConnectionTag{TagPaddedIntermediate, TagIntermediate, TagAbridged}

func TagSetOf(tags ...ConnectionTag) TagSet {
	var set TagSet

	for _, tag := range tags {
		set = set.With(tag)
	}

	return set
}

func (t TagSet) With(tag ConnectionTag) TagSet {
	return t | tagBit(tag)
}

func (t TagSet) Has(tag ConnectionTag) bool {
	bit := tagBit(tag)

	return bit != 0 && t&bit != 0
}

// Covers reports whether t honours every tag in other, i.e. other is a subset.
// It answers "would this listener serve every transport a client of that secret
// form might pick", which is not the same as the two sets overlapping.
func (t TagSet) Covers(other TagSet) bool {
	return other&^t == 0
}

func (t TagSet) Empty() bool {
	return t == 0
}

func (t TagSet) String() string {
	names := make([]string, 0, len(orderedTags))

	for _, tag := range orderedTags {
		if t.Has(tag) {
			names = append(names, tag.String())
		}
	}

	return strings.Join(names, ",")
}
