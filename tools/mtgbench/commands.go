package main

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	errShortAck = errors.New("the data centre acknowledged a different count")
	errCorrupt  = errors.New("what arrived is not what was sent")
)

// clientChunk is the size of the client's own reads and writes.
const clientChunk = 64 << 10

// zeros is what clients send. Writers encrypt in place, so each write takes a
// copy into its own buffer first.
var zeros = make([]byte, clientChunk)

func command(op byte, n int64) []byte {
	b := make([]byte, commandSize)
	b[0] = op
	binary.BigEndian.PutUint64(b[1:], uint64(n)) //nolint: gosec // non-negative

	return b
}

// Download asks for n bytes, reads every one of them in clientChunk pieces,
// and checks each is the zero the data centre sends.
func Download(conn io.ReadWriter, n int64) error {
	if _, err := conn.Write(command(cmdDownload, n)); err != nil {
		return fmt.Errorf("cannot ask for a download: %w", err)
	}

	buf := make([]byte, clientChunk)

	for got := int64(0); got < n; {
		m, err := conn.Read(buf[:min(int64(len(buf)), n-got)])
		if m > 0 && !bytes.Equal(buf[:m], zeros[:m]) {
			return fmt.Errorf("download, at byte %d: %w", got, errCorrupt)
		}

		got += int64(m)

		if err != nil && got < n {
			return fmt.Errorf("download ended at %d of %d bytes: %w", got, n, cmp.Or(err, io.ErrUnexpectedEOF))
		}
	}

	return nil
}

// Upload sends n bytes and waits for the data centre to acknowledge all of them.
func Upload(conn io.ReadWriter, n int64) error {
	if _, err := conn.Write(command(cmdUpload, n)); err != nil {
		return fmt.Errorf("cannot announce an upload: %w", err)
	}

	buf := make([]byte, clientChunk)

	for left := n; left > 0; {
		chunk := min(left, int64(len(buf)))
		copy(buf, zeros[:chunk])

		if _, err := conn.Write(buf[:chunk]); err != nil {
			return fmt.Errorf("upload stopped with %d of %d bytes left: %w", left, n, err)
		}

		left -= chunk
	}

	var ack [8]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return fmt.Errorf("no acknowledgement for the upload: %w", err)
	}

	if got := int64(binary.BigEndian.Uint64(ack[:])); got != n { //nolint: gosec // our own data centre's count
		return fmt.Errorf("%w: %d of %d", errShortAck, got, n)
	}

	return nil
}

// Echo sends message and reads it back, as it went. It writes before it reads,
// so it is for messages that fit the sockets' buffers: a ping, not a transfer.
func Echo(conn io.ReadWriter, message []byte) error {
	out := append(command(cmdEcho, int64(len(message))), message...)

	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("cannot send the echo: %w", err)
	}

	echoed := make([]byte, len(message))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		return fmt.Errorf("no echo: %w", err)
	}

	if !bytes.Equal(echoed, message) {
		return fmt.Errorf("echo: %w", errCorrupt)
	}

	return nil
}

// Hold asks the data centre to keep the connection open and idle.
func Hold(conn io.Writer) error {
	if _, err := conn.Write(command(cmdHold, 0)); err != nil {
		return fmt.Errorf("cannot ask for a hold: %w", err)
	}

	return nil
}
