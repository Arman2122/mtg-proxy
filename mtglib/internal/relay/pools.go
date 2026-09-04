package relay

import "sync"

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufPoolSize)
		return &b
	},
}

func acquireBuffer() *[]byte {
	if p, ok := bufPool.Get().(*[]byte); ok {
		return p
	}

	// Unreachable: bufPool.New only ever returns a *[]byte. Allocating is
	// still the right answer if that ever stops being true -- this runs on
	// every relayed connection, and a panic here would take the process down.
	b := make([]byte, bufPoolSize)

	return &b
}

func releaseBuffer(p *[]byte) {
	bufPool.Put(p)
}
