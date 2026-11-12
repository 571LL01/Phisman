//go:build !windows

package main

import (
	"fmt"
	"os"
)

// enforceDataDirMode re-applies 0700 after MkdirAll, whose mode argument is
// filtered by the process umask. It only runs for a directory this process just
// created; an existing directory is verified, never silently changed.
func enforceDataDirMode(path string) error {
	return os.Chmod(path, 0o700)
}

// checkDataDirMode refuses a pre-existing data directory that group or others
// can read or traverse. Without execute they cannot open artifacts.db even if
// the file itself were world-readable.
//
// Docker creates named-volume mount points as 0755 by default, so an image that
// mounts data_dir must chmod 700 it in the entrypoint. This check is what turns
// a forgotten chmod into a startup error instead of a quiet data leak; the
// step-9 Dockerfile documents the corresponding RUN/chmod.
func checkDataDirMode(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("data_dir %q has mode %04o; group and others must have no access (chmod 700)", path, perm)
	}
	return nil
}
