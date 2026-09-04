//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// reloadSignals is what asks a running relay to re-read its profiles.
//
// SIGHUP, because that is what every supervisor already sends and what every
// operator already expects: systemd's ExecReload, nginx, haproxy, sshd. The
// alternative -- a management port on the relay -- would put a second HTTP
// server on a process whose entire security argument is that it presents one
// hostname to the open internet and nothing else.
func reloadSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}
