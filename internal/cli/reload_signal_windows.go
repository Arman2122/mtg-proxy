//go:build windows

package cli

import "os"

// reloadSignals is empty on Windows, which has no SIGHUP: Go defines the
// constant but nothing ever delivers it, so registering for it would advertise
// a reload that silently never happens.
//
// Nothing is lost. The relay is a server component that runs behind a TLS front
// proxy on a host the panel manages, and the Windows builds exist for the proxy.
// A Windows deployment that needs a new profile set restarts the relay.
func reloadSignals() []os.Signal {
	return nil
}
