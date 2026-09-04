package fake

import (
	"bytes"
	"sync"
)

var bytesPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func acquireBuffer() *bytes.Buffer {
	if b, ok := bytesPool.Get().(*bytes.Buffer); ok {
		return b
	}

	// Unreachable: bytesPool.New only ever returns a *bytes.Buffer. See
	// relay.acquireBuffer for why this allocates instead of asserting.
	return &bytes.Buffer{}
}

func releaseBuffer(b *bytes.Buffer) {
	b.Reset()
	bytesPool.Put(b)
}
