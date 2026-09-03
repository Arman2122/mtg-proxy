package obfuscation

import (
	"crypto/cipher"

	"github.com/Arman2122/mtg-proxy/essentials"
)

type conn struct {
	essentials.Conn

	sendCipher cipher.Stream
	recvCipher cipher.Stream
}

func (c conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)

	// io.Reader is allowed to return n > 0 together with an error, and callers
	// like io.CopyBuffer do forward those n bytes. Decryption cannot be skipped
	// on the error path for a second reason too: the CTR keystream must advance
	// by exactly n, otherwise every later read decrypts at the wrong offset.
	if n > 0 {
		c.recvCipher.XORKeyStream(p, p[:n])
	}

	return n, err
}

func (c conn) Write(p []byte) (int, error) {
	// yes, this is a bit violent and goes against a contract in io.Writer
	// but we do it to avoid creating a new buffer just to perform this
	// encryption.
	c.sendCipher.XORKeyStream(p, p)

	return c.Conn.Write(p)
}
