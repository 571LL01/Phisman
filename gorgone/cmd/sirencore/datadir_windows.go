//go:build windows

package main

import "os"

// Windows access is governed by ACLs, not by the POSIX bits Go synthesises for
// FileMode. The directory is still requested as 0700 for consistency, and the
// ACL inherited from its parent is the actual boundary.
func enforceDataDirMode(string) error { return nil }

func checkDataDirMode(string, os.FileInfo) error { return nil }
