package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

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
	errUnknownKeys = errors.New("unknown config keys")
	// "Settings": a [[retiring-secret]] block and a [secrets] user of that name
	// alike. "Keys" would read as credentials.
	errRetiringProblems = errors.New("retiring-secret settings that run ignores or warns about")
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

// retiringShapeAdvice is what run, run --check, doctor and a refused reload say
// when a file does not parse at a key named retiring-secret. It says how the
// table is written and which shapes are not it, never what the file holds: the
// refused line may carry a key. It opens as the line run gives a [secrets] user
// of that name, the same mis-edit when it parses.
const retiringShapeAdvice = "[[retiring-secret]] blocks go in their own table, above or between the other tables, " +
	"one per old key, each with name, secret and until: not a scalar (retiring-secret = ...), " +
	"not an inline table (retiring-secret = { ... }), not a key of that name under another table such as [secrets]"

// retiringReloadKept is what a reload refused at such a key adds: the file is
// refused whole, so the set in force stays, and a re-key in the same edit -- the
// usual company of a rotation, in [secrets] or the top-level secret -- is not
// applied either. The reloader cannot tell whether the edit re-keyed anything,
// hence the "if". run does not watch its file: the old key stays until the file
// is fixed and reloaded (or run restarted).
const retiringReloadKept = "the secret set in force is kept: nothing in this edit is applied; " +
	"if it re-keyed [secrets] or secret, the old key stays the primary until the file is fixed and reloaded"

// retiringParseAdvice is the words to put before a parse error that stopped at a
// key named retiring-secret, and whether it did. go-toml names a scalar or an
// inline table there by the Go type it could not decode into, struct tags and
// all, which tells an operator nothing about the file.
//
// The key is recognised by the first part of the key the parser was at when it
// stopped: the table itself (a scalar, an inline table, a duplicate table), a
// field inside one of its blocks (a syntax error such as an impossible date),
// or -- the key being relative there -- a duplicate key of that name inside
// another table, such as two retiring-secret users in [secrets]. Only the line
// is taken from the error, and no other part of the key, which could be a value
// pasted where a key belongs.
//
// What follows the words is config.Parse's error, a config.ParseError: the
// parser's Error() form, never its String() form, which quotes the refused line
// and so, for a scalar holding a secret, the key. Error() quotes no line of the
// document, but go-toml puts a key's name into some messages (a key defined
// twice) and a number's literal into others (a float out of range): a value
// written as a TOML key or as an unquoted number would be echoed there, so
// config.Parse replaces any text of the file that could spell a value, and
// names the line and column instead. The key it keeps has such parts replaced
// too, so only its first part, the table's name, is compared here.
func retiringParseAdvice(err error) (string, bool) {
	var parseErr *config.ParseError
	if !errors.As(err, &parseErr) {
		return "", false
	}

	key := parseErr.Key()
	if len(key) == 0 || key[0] != "retiring-secret" {
		return "", false
	}

	line, _ := parseErr.Position()

	where := "at a key named retiring-secret"
	if len(key) > 1 {
		where = "inside a [[retiring-secret]] block"
	}

	return fmt.Sprintf("the file does not parse at line %d, %s: %s", line, where, retiringShapeAdvice), true
}

// explainConfigError is err with retiringParseAdvice's words before it when it
// stopped at a key named retiring-secret, and err as it is otherwise -- a
// byte-order mark, say, which has nothing to do with the table.
func explainConfigError(err error) error {
	advice, ok := retiringParseAdvice(err)
	if !ok {
		return err
	}

	return fmt.Errorf("%s: %w", advice, err)
}
