package middleproxy

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	frameMinMessageLength = 12
	frameMaxMessageLength = 16777216

	// cbcReadBuffer is how much of the middle proxy's stream one read system
	// call may bring in. Every ad-tagged connection holds one, so it is sized
	// for memory per connection as much as for throughput.
	cbcReadBuffer = 16 << 10
)

// framePadding is the 4-byte word repeated to pad a frame up to a 16-byte
// multiple. On read, leading padding words are skipped.
var framePadding = []byte{0x04, 0x00, 0x00, 0x00}

// cbcConn wraps a raw connection with AES-256-CBC in both directions. The RPC
// transport frame guarantees every write is a whole number of 16-byte blocks.
//
// Reads come off a buffered reader in bulk: one call decrypts as many whole
// blocks as the caller has room for and the socket has already delivered,
// straight into the caller's buffer. Only a read shorter than a block, or
// frameBuffered looking ahead, decrypts into the small plaintext area, whose
// unread bytes are served first. CBC decryption chains on ciphertext, so
// decrypting a block early changes nothing about the blocks after it.
type cbcConn struct {
	raw io.ReadWriter
	r   *bufio.Reader
	enc cipher.BlockMode
	dec cipher.BlockMode

	plain   [2 * aes.BlockSize]byte
	pending []byte
}

func newCBCConn(raw io.ReadWriter, enc, dec cipher.BlockMode) *cbcConn {
	return &cbcConn{raw: raw, enc: enc, dec: dec}
}

func (c *cbcConn) reader() *bufio.Reader {
	if c.r == nil {
		c.r = bufio.NewReaderSize(c.raw, cbcReadBuffer)
	}

	return c.r
}

func (c *cbcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]

		return n, nil
	}

	if err := c.awaitBlock(); err != nil {
		return 0, err
	}

	if len(p) < aes.BlockSize {
		c.pending = c.plain[:aes.BlockSize]
		c.decryptNext(c.pending)

		n := copy(p, c.pending)
		c.pending = c.pending[n:]

		return n, nil
	}

	// As many whole blocks as fit p and are already buffered: no second
	// blocking read.
	n := min(len(p), c.r.Buffered()) &^ (aes.BlockSize - 1)
	c.decryptNext(p[:n])

	return n, nil
}

// awaitBlock blocks until at least one whole block is buffered. One read
// system call fills as much of the buffer as the socket has.
func (c *cbcConn) awaitBlock() error {
	r := c.reader()

	if _, err := r.Peek(aes.BlockSize); err != nil {
		if errors.Is(err, io.EOF) && r.Buffered() > 0 {
			return io.ErrUnexpectedEOF
		}

		return err //nolint: wrapcheck
	}

	return nil
}

// decryptNext moves len(dst) buffered bytes, a whole number of blocks, into
// dst and decrypts them in place. The caller has checked they are buffered.
func (c *cbcConn) decryptNext(dst []byte) {
	if _, err := io.ReadFull(c.r, dst); err != nil {
		panic(fmt.Sprintf("cbcConn: %d buffered bytes vanished: %v", len(dst), err))
	}

	c.dec.CryptBlocks(dst, dst)
}

// frameBuffered reports whether the next frame -- after any padding words --
// has fully arrived, so reading it cannot block. It may decrypt up to two
// blocks ahead into the plaintext area to learn the frame's length, and drops
// the padding words it passes, as readPacket would.
func (c *cbcConn) frameBuffered() bool {
	r := c.reader()

	for {
		if len(c.pending) < 4 {
			if r.Buffered() < aes.BlockSize {
				return false
			}

			kept := copy(c.plain[:], c.pending)
			c.pending = c.plain[:kept+aes.BlockSize]
			c.decryptNext(c.pending[kept:])
		}

		if !bytes.Equal(c.pending[:4], framePadding) {
			break
		}

		c.pending = c.pending[4:]
	}

	length := binary.LittleEndian.Uint32(c.pending[:4])
	if length < frameMinMessageLength || length > frameMaxMessageLength {
		// Not this function's to judge: the next read reports it.
		return false
	}

	return int(length) <= len(c.pending)+r.Buffered()
}

func (c *cbcConn) Write(p []byte) (int, error) {
	if len(p)%aes.BlockSize != 0 {
		return 0, fmt.Errorf("cbc write of non-block-aligned length %d", len(p))
	}

	encrypted := make([]byte, len(p))
	c.enc.CryptBlocks(encrypted, p)

	if _, err := c.raw.Write(encrypted); err != nil {
		return 0, err //nolint: wrapcheck
	}

	return len(p), nil
}

// frameConn layers the MTProto RPC transport frame over an io.ReadWriter:
//
//	[ MSGLEN(4) | SEQNO(4) | MSG(...) | CRC32(4) | PADDING(4*k) ]
//
// MSGLEN counts itself, SEQNO, MSG and CRC32; CRC32 covers MSGLEN+SEQNO+MSG;
// PADDING is 0x04000000 words repeated until the frame length is a 16-byte
// multiple. Read/write sequence numbers must match the peer's.
type frameConn struct {
	raw        io.ReadWriter
	readSeqNo  int32
	writeSeqNo int32

	// body holds the frame readPacket last read. The message it returns is a
	// slice of it, valid until the next readPacket.
	body []byte
}

func newFrameConn(raw io.ReadWriter, seqNo int32) *frameConn {
	return &frameConn{raw: raw, readSeqNo: seqNo, writeSeqNo: seqNo}
}

func (f *frameConn) writePacket(msg []byte) error {
	messageLength := 4 + 4 + len(msg) + 4
	paddingLength := (aes.BlockSize - messageLength%aes.BlockSize) % aes.BlockSize

	buf := &bytes.Buffer{}

	// G115: messageLength is 12+len(msg) for a message this process just
	// assembled; readPacket rejects anything above frameMaxMessageLength
	// (16 MiB) on the way in, and nothing here builds a larger one.
	binary.Write(buf, binary.LittleEndian, uint32(messageLength)) //nolint: errcheck,gosec
	binary.Write(buf, binary.LittleEndian, f.writeSeqNo)          //nolint: errcheck
	buf.Write(msg)

	checksum := crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.LittleEndian, checksum) //nolint: errcheck

	buf.Write(bytes.Repeat(framePadding, paddingLength/4))

	f.writeSeqNo++

	_, err := f.raw.Write(buf.Bytes())

	return err //nolint: wrapcheck
}

func (f *frameConn) readPacket() ([]byte, error) {
	var lenBuf [4]byte

	for {
		if _, err := io.ReadFull(f.raw, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("cannot read frame length: %w", err)
		}

		if !bytes.Equal(lenBuf[:], framePadding) {
			break
		}
	}

	messageLength := binary.LittleEndian.Uint32(lenBuf[:])
	if messageLength%4 != 0 || messageLength < frameMinMessageLength || messageLength > frameMaxMessageLength {
		return nil, fmt.Errorf("incorrect frame message length %d", messageLength)
	}

	if cap(f.body) < int(messageLength-4) {
		f.body = make([]byte, messageLength-4)
	}

	rest := f.body[:messageLength-4]
	if _, err := io.ReadFull(f.raw, rest); err != nil {
		return nil, fmt.Errorf("cannot read frame body: %w", err)
	}

	// G115: not a narrowing conversion. The middleproxy sequence number is
	// a SIGNED 32-bit wire field, and this is the two's-complement
	// reinterpretation the protocol specifies. Do not "fix" it -- the
	// golden trace test pins these bytes.
	seqNo := int32(binary.LittleEndian.Uint32(rest[:4])) //nolint:gosec
	if seqNo != f.readSeqNo {
		return nil, fmt.Errorf("unexpected sequence number %d (want %d)", seqNo, f.readSeqNo)
	}

	msg := rest[4 : len(rest)-4]
	checksum := binary.LittleEndian.Uint32(rest[len(rest)-4:])

	sum := crc32.Update(crc32.Update(0, crc32.IEEETable, lenBuf[:]), crc32.IEEETable, rest[:len(rest)-4])

	if got := sum; got != checksum {
		return nil, fmt.Errorf("crc32 mismatch: want %d, got %d", checksum, got)
	}

	f.readSeqNo++

	return msg, nil
}

// nextFrameBuffered reports whether reading the next frame cannot block. Only
// the AES-CBC channel can tell; on any other transport the answer is no.
func (f *frameConn) nextFrameBuffered() bool {
	cbc, ok := f.raw.(*cbcConn)

	return ok && cbc.frameBuffered()
}
