package obfuscation_test

import (
	"bytes"
	"crypto/rand"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// secretKeyLength duplicates mtglib.SecretKeyLength deliberately: obfuscation is
// a leaf package and its tests must keep building when mtglib does not.
const secretKeyLength = 16

var (
	allTags = []obfuscation.ConnectionTag{
		obfuscation.TagPaddedIntermediate,
		obfuscation.TagIntermediate,
		obfuscation.TagAbridged,
	}

	allTagsSet = obfuscation.TagSetOf(allTags...)
	paddedOnly = obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate)
)

func randomKey() []byte {
	key := make([]byte, secretKeyLength)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	return key
}

// memConn is an essentials.Conn over two buffers. The embedded interface is nil
// on purpose: only Read and Write are exercised, so anything else must panic
// loudly rather than quietly do nothing.
type memConn struct {
	essentials.Conn

	read  *bytes.Reader
	wrote bytes.Buffer
}

func (m *memConn) Read(p []byte) (int, error) {
	return m.read.Read(p) //nolint: wrapcheck
}

func (m *memConn) Write(p []byte) (int, error) {
	return m.wrote.Write(p) //nolint: wrapcheck
}
