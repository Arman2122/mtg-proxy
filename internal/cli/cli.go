package cli

import "github.com/alecthomas/kong"

type CLI struct {
	GenerateSecret GenerateSecret   `kong:"cmd,help='Generate new proxy secret'"`
	Doctor         Doctor           `kong:"cmd,help='Check that proxy can run correctly'"`
	Access         Access           `kong:"cmd,help='Print access information.'"`
	Run            Run              `kong:"cmd,help='Run proxy.'"`
	SimpleRun      SimpleRun        `kong:"cmd,help='Run proxy without config file.'"`
	WebRelay       WebRelay         `kong:"cmd,help='Run the WEB proxy relay for the secrets in a config file.'"`
	GenerateWebKey GenerateWebKey   `kong:"cmd,help='Generate the WEB relay token signing key.'"`
	Version        kong.VersionFlag `kong:"help='Print version.',short='v'"`
}
