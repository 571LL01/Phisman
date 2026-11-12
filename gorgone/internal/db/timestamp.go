package db

import "time"

// timestampLayout is fixed width on purpose: timestamps are stored as TEXT and
// ordered by SQLite with plain string comparison. RFC3339Nano trims trailing
// zeros, so "…:06.5Z" sorts after "…:06.55Z" even though 0.5 < 0.55.
const timestampLayout = "2006-01-02T15:04:05.000000000Z"

// FormatTime encodes t for a TEXT timestamp column.
func FormatTime(t time.Time) string {
	return t.UTC().Format(timestampLayout)
}

// ParseTime accepts any RFC 3339 fractional precision, so rows written before
// the fixed-width convention still load.
func ParseTime(raw string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, raw)
}
