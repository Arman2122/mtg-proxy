//go:build windows

package cli

import "os"

// reloadSignals is empty on Windows, which has no SIGHUP: Go defines the
// constant but nothing ever delivers it, so registering for it would advertise
// a reload that silently never happens.
//
// Nothing is lost. The relay watches its config file on every platform, and on
// this one the watcher is the only trigger: a changed file is applied within a
// few seconds, with no signal to send.
func reloadSignals() []os.Signal {
	return nil
}
