package webrelay

import (
	"sync"
	"weak"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
)

// A stream reads its backend into a buffer from one of two pools, and the DATA
// frame carries that buffer to the client as it is: no copy, and no
// allocation once the pools are warm. The write loop hands the buffer back
// after the bytes are on the socket.
//
// The two sizes are the adaptive part. A stream reads small until a read
// fills its buffer, then large, and back to small after a large read that
// comes back under the small size. A stream that is idle -- blocked in a read,
// which is where an idle stream always is -- therefore holds 4 KiB, not 64.
const (
	smallRead = 4 << 10
	largeRead = frame.MaxRelayDataChunk
)

// readBufferPools is one pool per size. The relay uses one set, readBuffers;
// a test that checks the pools' own rules makes its own, so no buffer it
// touches after a release can be one a stream has since taken.
type readBufferPools struct {
	small, large sync.Pool

	// released is, while poisonReleased is set, every buffer released and not
	// taken since. It cannot be read off the buffer: a read puts the backend's
	// bytes in it, and those may be the poison's. Weak, so a buffer the pool
	// drops is not kept alive by its entry.
	mu       sync.Mutex
	released map[weak.Pointer[byte]]struct{}
}

func newReadBufferPools() *readBufferPools {
	return &readBufferPools{
		small:    sync.Pool{New: func() any { return make([]byte, smallRead) }},
		large:    sync.Pool{New: func() any { return make([]byte, largeRead) }},
		released: make(map[weak.Pointer[byte]]struct{}),
	}
}

var readBuffers = newReadBufferPools()

// poisonReleased is set by this package's tests: every released buffer is then
// overwritten with poison, so a buffer used after its release corrupts what
// the client receives and the byte-exact tests fail, and a buffer released
// twice -- not taken in between -- panics.
var poisonReleased bool

const poison = 0xA5

func getReadBuffer(large bool) []byte { return readBuffers.get(large) }

// releaseReadBuffer returns b to the pool its capacity names. A slice of any
// other capacity is not the pools' and is ignored. b must not be used again.
func releaseReadBuffer(b []byte) { readBuffers.release(b) }

func (p *readBufferPools) get(large bool) []byte {
	pool := &p.small
	if large {
		pool = &p.large
	}

	buf := pool.Get().([]byte) //nolint: forcetypeassert // the pool's own New

	if poisonReleased {
		// Taken, so its next release is its first.
		p.mark(buf, false)
	}

	return buf
}

func (p *readBufferPools) release(b []byte) {
	b = b[:cap(b)]

	var pool *sync.Pool

	switch len(b) {
	case smallRead:
		pool = &p.small
	case largeRead:
		pool = &p.large
	default:
		return
	}

	if poisonReleased {
		if p.mark(b, true) {
			panic("webrelay: a read buffer was released twice")
		}

		for i := range b {
			b[i] = poison
		}
	}

	pool.Put(b) //nolint: staticcheck // SA6002: boxing the slice header is 24 bytes against a 4-64 KiB buffer
}

// mark records whether b's buffer is released, and reports whether it already
// was.
func (p *readBufferPools) mark(b []byte, released bool) bool {
	key := weak.Make(&b[0])

	p.mu.Lock()
	defer p.mu.Unlock()

	_, was := p.released[key]

	if released {
		p.released[key] = struct{}{}
	} else {
		delete(p.released, key)
	}

	return was
}

// nextReadLarge is the size of a stream's next read, from its last: large
// after a read of at least smallRead bytes -- a small one that filled its
// buffer, or a large one that kept the data coming -- and small otherwise.
func nextReadLarge(_ bool, n int) bool {
	return n >= smallRead
}
