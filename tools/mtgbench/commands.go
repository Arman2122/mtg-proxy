package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var errShortAck = errors.New("the data centre acknowledged a different count")

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

// Download asks for n bytes and reads every one of them.
func Download(conn io.ReadWriter, n int64) error {
	if _, err := conn.Write(command(cmdDownload, n)); err != nil {
		return fmt.Errorf("cannot ask for a download: %w", err)
	}

	got, err := io.CopyBuffer(io.Discard, io.LimitReader(conn, n), make([]byte, clientChunk))
	if err != nil || got != n {
		return fmt.Errorf("download ended at %d of %d bytes: %w", got, n, err)
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

// Echo sends message and reads the same number of bytes back.
func Echo(conn io.ReadWriter, message []byte) error {
	out := append(command(cmdEcho, int64(len(message))), message...)

	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("cannot send the echo: %w", err)
	}

	if _, err := io.ReadFull(conn, make([]byte, len(message))); err != nil {
		return fmt.Errorf("no echo: %w", err)
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
