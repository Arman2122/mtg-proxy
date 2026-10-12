package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/pelletier/go-toml/v2"
)

type Run struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"` //nolint: lll
	Check      bool   `kong:"help='Verify the configuration and exit without listening.'"`
}

func (r *Run) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", explainConfigError(err))
	}

	if r.Check {
		// A separate, short-lived process with no high-water history: the wall
		// clock is the only one it has.
		return checkConfig(conf, time.Now())
	}

	return runProxy(conf, version, r.ConfigPath)
}

var (
	errUnknownKeys      = errors.New("unknown config keys")
	errRetiringProblems = errors.New("retiring-secret entries that run ignores or warns about")
)

// checkConfig is `run --check`: the parse and validation `run` does before it
// listens, with an unknown key a refusal rather than a warning. It exists for
// a panel that stages a new binary and needs proof it reads every key the
// panel writes before the running binary is replaced with it.
//
// It refuses the [[retiring-secret]] table the same way: run drops a problem
// entry, and keeps an over-long one, with a Warning; --check refuses the file
// for any of those lines, judged at now. An inert entry -- expired, its own
// primary, a duplicate -- is accepted, so what --check accepts at one instant
// it accepts later. The lines name an entry by its position and name, never by
// its value.
func checkConfig(conf *config.Config, now time.Time) error {
	var refusals []error

	if len(conf.UnknownKeys) > 0 {
		refusals = append(refusals, fmt.Errorf("%w: %s", errUnknownKeys, strings.Join(conf.UnknownKeys, ", ")))
	}

	if lines := conf.GetRetiringSecrets(now).Lines; len(lines) > 0 {
		refusals = append(refusals, fmt.Errorf("%w:\n  %s", errRetiringProblems, strings.Join(lines, "\n  ")))
	}

	return errors.Join(refusals...)
}

// retiringShapeAdvice is what run, run --check and doctor say when a file does
// not parse at its [[retiring-secret]] table. It names the shapes that refuse
// the whole file, never what the file holds: the refused line may carry a key.
const retiringShapeAdvice = "write one [[retiring-secret]] block per old key, with name, secret and until; " +
	"a scalar (retiring-secret = ...), an inline table (retiring-secret = { ... }) " +
	"or a TOML syntax error inside a block refuses the whole file"

// explainConfigError puts words of its own before a parse error that stopped at
// the [[retiring-secret]] table. go-toml names a scalar or an inline table there
// by the Go type it could not decode into, struct tags and all, which tells an
// operator nothing about the file; it says which shapes are refused instead.
//
// The table is recognised by the key the parser was at when it stopped, and
// only the line is taken from the error. Neither the key's other parts nor any
// of the document are printed: the parser's own text follows in its Error()
// form, which carries none of the document, and never in its String() form,
// which quotes the refused line -- a key, for a scalar holding a secret. An
// error elsewhere in the file, a byte-order mark among them, is returned as it
// is.
func explainConfigError(err error) error {
	var decodeErr *toml.DecodeError
	if !errors.As(err, &decodeErr) {
		return err
	}

	if key := decodeErr.Key(); len(key) == 0 || key[0] != "retiring-secret" {
		return err
	}

	line, _ := decodeErr.Position()

	return fmt.Errorf("the retiring-secret table does not parse at line %d: %s: %w", line, retiringShapeAdvice, err)
}
