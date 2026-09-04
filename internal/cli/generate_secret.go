package cli

import (
	"fmt"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

type GenerateSecret struct {
	// hostname is optional now: only the ee (FakeTLS) form carries one on the
	// wire, and GenerateSecretMode rejects the wrong combination with a message
	// that names the mode.
	HostName string `kong:"arg,optional,help='Hostname to use for domain fronting. Required by (and only by) the ee mode.',name='hostname'"` //nolint: lll
	Hex      bool   `kong:"help='Print secret in hex encoding.',short='x'"`
	Mode     string `kong:"name='mode',default='ee',help='Secret wire form: ee (FakeTLS), dd or plain.'"`
}

func (g *GenerateSecret) Run(_ *CLI, _ string) error {
	mode, err := mtglib.ParseSecretMode(g.Mode)
	if err != nil {
		return fmt.Errorf("incorrect mode: %w", err)
	}

	secret, err := mtglib.GenerateSecretMode(mode, g.HostName)
	if err != nil {
		return fmt.Errorf("cannot generate a secret: %w", err)
	}

	if g.Hex {
		fmt.Println(secret.Hex()) //nolint: forbidigo
	} else {
		fmt.Println(secret.Base64()) //nolint: forbidigo
	}

	return nil
}
