//go:build windows

package cli

import (
	"io/fs"
	"os"
)

// keepOwner does nothing on Windows: a file has no Unix owner and group to
// keep, and the new file inherits its directory's access control list, as the
// target did.
func keepOwner(*os.File, string, fs.FileInfo) error { return nil }

// syncDirectory does nothing on Windows, which cannot open a directory to
// fsync it; the rename is the platform's own.
func syncDirectory(string) error { return nil }
