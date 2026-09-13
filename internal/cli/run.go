package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
)

type Run struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"` //nolint: lll
	Check      bool   `kong:"help='Verify the configuration and exit without listening.'"`
}

func (r *Run) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	if r.Check {
		return checkConfig(conf)
	}

	return runProxy(conf, version, r.ConfigPath)
}

var errUnknownKeys = errors.New("unknown config keys")

// checkConfig is `run --check`: the parse and validation `run` does before it
// listens, with an unknown key a refusal rather than a warning. It exists for
// a panel that stages a new binary and needs proof it reads every key the
// panel writes before the running binary is replaced with it.
func checkConfig(conf *config.Config) error {
	if len(conf.UnknownKeys) > 0 {
		return fmt.Errorf("%w: %s", errUnknownKeys, strings.Join(conf.UnknownKeys, ", "))
	}

	return nil
}
