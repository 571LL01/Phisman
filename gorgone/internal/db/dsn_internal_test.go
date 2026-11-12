package db

import "testing"

func TestIsMemoryDSN(t *testing.T) {
	cases := map[string]bool{
		":memory:":                            true,
		":memory:?cache=shared":               true,
		"file::memory:":                       true,
		"file::memory:?cache=shared":          true,
		"file:siren?mode=memory&cache=shared": true,
		"file:/var/lib/siren/artifacts.db":    false,
		"artifacts.db":                        false,
		"file:memdb1.db":                      false,
	}
	for dsn, want := range cases {
		if got := isMemoryDSN(dsn); got != want {
			t.Errorf("isMemoryDSN(%q) = %v, want %v", dsn, got, want)
		}
	}
}
