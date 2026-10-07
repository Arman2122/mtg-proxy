package fake

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"slices"
	"time"
)

// Parsed is a ClientHello read off a connection that has passed the SNI gate,
// kept with the bytes its digest covers, so that any number of candidate keys
// can be verified against it without reading it again.
//
// A Parsed is for one goroutine: Verify works in scratch space that lives in it.
type Parsed struct {
	Hello       *ClientHello
	MatchedHost string

	// handshake is the hello re-synthesised as one record -- 5-byte record
	// header, 4-byte handshake header, body -- which is what the client's HMAC
	// covers.
	handshake []byte

	scratch scratch
}

// scratch is where Verify works. It lives in Parsed rather than on the stack
// because a buffer handed to Sum through the hash.Hash interface escapes: a
// stack array there would be an allocation per candidate.
type scratch struct {
	// inner and outer are made on the first precomputed Verify, so a hello
	// that only ever meets plain candidates never pays for them.
	inner, outer         hash.Hash
	loadInner, loadOuter encoding.BinaryUnmarshaler

	// stateless is set when the digests cannot load a state: every Verify on
	// this Parsed is then plain.
	stateless bool

	innerSum [sha256.Size]byte
	mac      [sha256.Size]byte
}

// ready makes the scratch digests if they are not made yet, and reports
// whether they can load a precomputed state.
func (s *scratch) ready() bool {
	if s.inner != nil {
		return true
	}

	if s.stateless {
		return false
	}

	inner, outer := sha256.New(), sha256.New()
	loadInner, okInner := inner.(encoding.BinaryUnmarshaler)
	loadOuter, okOuter := outer.(encoding.BinaryUnmarshaler)

	if !okInner || !okOuter {
		s.stateless = true

		return false
	}

	s.inner, s.outer = inner, outer
	s.loadInner, s.loadOuter = loadInner, loadOuter

	return true
}

// ParseClientHelloFor reads a ClientHello off conn and puts it through the SNI
// gate: everything ReadClientHelloMulti does before it tries a secret, with the
// same errors. A hello naming none of hostnames is an error with no Parsed, and
// the caller fronts it with its own default host.
func ParseClientHelloFor(conn net.Conn, hostnames []string) (*Parsed, error) {
	clientHelloCopy, handshakeReader, err := parseClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("cannot read client hello: %w", err)
	}

	hello, err := parseHandshake(handshakeReader)
	if err != nil {
		return nil, fmt.Errorf("cannot parse handshake: %w", err)
	}

	sniHostnames, err := parseSNI(handshakeReader)
	if err != nil {
		return nil, fmt.Errorf("cannot parse SNI: %w", err)
	}

	var matchedHost string

	for _, h := range hostnames {
		if slices.Contains(sniHostnames, h) {
			matchedHost = h

			break
		}
	}

	if matchedHost == "" {
		return nil, fmt.Errorf("cannot find any of %v in %v", hostnames, sniHostnames)
	}

	return &Parsed{
		Hello:       hello,
		MatchedHost: matchedHost,
		handshake:   clientHelloCopy.Bytes(),
	}, nil
}

// Blocks is what verifying one candidate against this hello costs on the plain
// HMAC path, in SHA-256 blocks: 3 + ceil((L+9)/64), L the length of the hello
// as one record. The inner hash is the key's pad block, then the L bytes with
// SHA-256's own padding (a 0x80 byte and an 8-byte length, so L+9 bytes); the
// outer hash is the pad block and the 32-byte inner digest, padded into one
// more. That is 12 for a 517-byte hello and 1,028 for the largest one taken,
// 65,540 bytes. It is the price whichever path verifies.
func (p *Parsed) Blocks() int {
	return 3 + (len(p.handshake)+9+sha256.BlockSize-1)/sha256.BlockSize
}

// Verify reports whether the hello was made with c's key no more than skew
// away from now, either way: its client random must be the HMAC-SHA256 of the
// hello (taken with the random zeroed) XORed with a little-endian Unix time in
// its last 4 bytes. It is the check ReadClientHelloMulti has always made for
// each secret -- the first 28 bytes compared in constant time, then the clock.
//
// On a precomputed Candidate it allocates nothing.
func (p *Parsed) Verify(c *Candidate, skew time.Duration) bool {
	if p.Hello == nil || c == nil || len(p.handshake) < RandomOffset+RandomLen {
		return false
	}

	computed := &p.scratch.mac

	c.mac(&p.scratch, computed,
		p.handshake[:RandomOffset], emptyRandom[:], p.handshake[RandomOffset+RandomLen:])

	for i := range RandomLen {
		computed[i] ^= p.Hello.Random[i]
	}

	if subtle.ConstantTimeCompare(emptyRandom[:RandomLen-4], computed[:RandomLen-4]) != 1 {
		return false
	}

	timestamp := int64(binary.LittleEndian.Uint32(computed[RandomLen-4:]))
	createdAt := time.Unix(timestamp, 0)

	return time.Since(createdAt).Abs() <= skew
}

// Candidate is one secret's key, ready to be verified against any number of
// hellos. It is read-only once built, so one Candidate may serve every
// goroutine at once.
type Candidate struct {
	// key is the caller's slice, not a copy: it must not change after the
	// Candidate is built.
	key []byte

	// innerState and outerState are SHA-256 states that have absorbed the
	// key's inner (key XOR 0x36) and outer (key XOR 0x5c) pad block, as
	// MarshalBinary exports them. Both nil is the plain path: hmac.New for
	// every Verify.
	innerState, outerState []byte
}

const (
	innerPad = 0x36
	outerPad = 0x5c
)

var errNoDigestState = errors.New("the digest cannot export its state")

// exportDigestState is how NewCandidate exports a pad state. A variable so a
// test can make it fail.
var exportDigestState = func(h hash.Hash) ([]byte, error) {
	marshaler, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errNoDigestState
	}

	return marshaler.MarshalBinary()
}

// NewCandidate builds a candidate whose key pads are hashed once, here, so a
// Verify hashes only the hello and the inner digest: 2 SHA-256 blocks fewer
// than plain HMAC, and no allocation. If the states cannot be exported, or the
// key is longer than the 64-byte block (which HMAC hashes first; secret keys
// are 16 bytes), it is a plain candidate, as NewPlainCandidate makes.
func NewCandidate(key []byte) *Candidate {
	c := NewPlainCandidate(key)

	if len(key) > sha256.BlockSize {
		return c
	}

	innerState, err := padState(key, innerPad)
	if err != nil {
		return c
	}

	outerState, err := padState(key, outerPad)
	if err != nil {
		return c
	}

	c.innerState, c.outerState = innerState, outerState

	return c
}

// NewPlainCandidate builds a candidate that runs crypto/hmac afresh for every
// Verify: the reference path.
func NewPlainCandidate(key []byte) *Candidate {
	return &Candidate{key: key}
}

// padState is the exported state of a SHA-256 that has absorbed the key,
// zero-padded to the block, XOR pad. key is at most a block long.
func padState(key []byte, pad byte) ([]byte, error) {
	var block [sha256.BlockSize]byte

	copy(block[:], key)

	for i := range block {
		block[i] ^= pad
	}

	digest := sha256.New()
	digest.Write(block[:])

	return exportDigestState(digest)
}

func (c *Candidate) precomputed() bool {
	return c.innerState != nil && c.outerState != nil
}

// mac writes HMAC-SHA256 under c's key of the parts, in order, into dst. The
// precomputed path loads the pad states into the scratch digests; if they will
// not load, this one call is plain.
func (c *Candidate) mac(s *scratch, dst *[sha256.Size]byte, parts ...[]byte) {
	if c.precomputed() && s.ready() &&
		s.loadInner.UnmarshalBinary(c.innerState) == nil &&
		s.loadOuter.UnmarshalBinary(c.outerState) == nil {
		for _, part := range parts {
			s.inner.Write(part)
		}

		// Sum appends to a zero-length slice of a 32-byte array, so it fills
		// that array and allocates nothing.
		s.outer.Write(s.inner.Sum(s.innerSum[:0]))
		s.outer.Sum(dst[:0])

		return
	}

	digest := hmac.New(sha256.New, c.key)

	for _, part := range parts {
		digest.Write(part)
	}

	digest.Sum(dst[:0])
}
