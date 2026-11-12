package dga

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, minSeedBytes) }

var baseDay = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func TestLabelsDeterministic(t *testing.T) {
	want, err := Labels(seedOf(0x11), "acme", baseDay, 8)
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if len(want) != 8 {
		t.Fatalf("labels = %d, want 8", len(want))
	}
	for i := 0; i < 100; i++ {
		got, err := Labels(seedOf(0x11), "acme", baseDay, 8)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: labels changed\n got %v\nwant %v", i, got, want)
		}
	}
}

// TestLabelsPrefixStable pins the property that makes n a window size rather
// than a schema decision: extending a day's derivation must not orphan labels
// already published. The index is in the HMAC message, so n=64[:8] must equal
// n=8 exactly.
func TestLabelsPrefixStable(t *testing.T) {
	eight, err := Labels(seedOf(0x11), "acme", baseDay, 8)
	if err != nil {
		t.Fatalf("n=8: %v", err)
	}
	sixtyFour, err := Labels(seedOf(0x11), "acme", baseDay, maxLabels)
	if err != nil {
		t.Fatalf("n=64: %v", err)
	}
	if !slices.Equal(eight, sixtyFour[:8]) {
		t.Fatalf("prefix changed with n\n n=8  %v\n n=64 %v", eight, sixtyFour[:8])
	}
}

func TestLabelsCampaignSeparation(t *testing.T) {
	a, err := Labels(seedOf(0x11), "acme", baseDay, 8)
	if err != nil {
		t.Fatalf("Labels campaign A: %v", err)
	}
	b, err := Labels(seedOf(0x11), "globex", baseDay, 8)
	if err != nil {
		t.Fatalf("Labels campaign B: %v", err)
	}

	seen := make(map[string]struct{}, len(a))
	for _, label := range a {
		seen[label] = struct{}{}
	}
	for _, label := range b {
		if _, ok := seen[label]; ok {
			t.Fatalf("label %q produced by two campaigns sharing a seed", label)
		}
	}
}

func TestLabelsDoesNotMutateSeed(t *testing.T) {
	seed := seedOf(0x11)
	before := slices.Clone(seed)
	if _, err := Labels(seed, "acme", baseDay, 8); err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if !slices.Equal(seed, before) {
		t.Fatalf("seed mutated\n got %x\nwant %x", seed, before)
	}
}

func TestLabelsSeedSeparation(t *testing.T) {
	a, err := Labels(seedOf(0x11), "acme", baseDay, 8)
	if err != nil {
		t.Fatalf("Labels seed A: %v", err)
	}
	b, err := Labels(seedOf(0x22), "acme", baseDay, 8)
	if err != nil {
		t.Fatalf("Labels seed B: %v", err)
	}

	seen := make(map[string]struct{}, len(a))
	for _, label := range a {
		seen[label] = struct{}{}
	}
	for _, label := range b {
		if _, ok := seen[label]; ok {
			t.Fatalf("label %q produced by both seeds on the same day", label)
		}
	}
}

func TestLabelsWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seen := make(map[string]struct{}, 90*8)

	for d := 0; d < 90; d++ {
		day := start.AddDate(0, 0, d)
		labels, err := Labels(seedOf(0x11), "acme", day, 8)
		if err != nil {
			t.Fatalf("day %s: %v", day.Format(dayLayout), err)
		}
		for _, label := range labels {
			if !validLabel(label) {
				t.Fatalf("day %s: %q is not a valid DNS label", day.Format(dayLayout), label)
			}
			if strings.ContainsAny(label, "01ol") {
				t.Fatalf("day %s: %q contains a confusable character", day.Format(dayLayout), label)
			}
			if _, ok := seen[label]; ok {
				t.Fatalf("day %s: duplicate label %q", day.Format(dayLayout), label)
			}
			seen[label] = struct{}{}
		}
	}
	if len(seen) != 90*8 {
		t.Fatalf("unique labels = %d, want %d", len(seen), 90*8)
	}
}

func TestLabelsMidnightUTC(t *testing.T) {
	before := time.Date(2026, 3, 10, 23, 59, 59, 999999999, time.UTC)
	after := before.Add(time.Nanosecond)

	beforeLabels, err := Labels(seedOf(0x11), "acme", before, 8)
	if err != nil {
		t.Fatalf("before: %v", err)
	}
	afterLabels, err := Labels(seedOf(0x11), "acme", after, 8)
	if err != nil {
		t.Fatalf("after: %v", err)
	}
	for i := range beforeLabels {
		if beforeLabels[i] == afterLabels[i] {
			t.Fatalf("index %d: label %q survived the UTC day change", i, beforeLabels[i])
		}
	}

	// The same instant expressed in a non-UTC zone must derive the same labels:
	// the truncation is on UTC, not on the caller's wall clock.
	local := time.Date(2026, 3, 11, 1, 0, 0, 0, time.FixedZone("UTC+1", 3600))
	localLabels, err := Labels(seedOf(0x11), "acme", local, 8)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	midnight := time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC)
	midnightLabels, err := Labels(seedOf(0x11), "acme", midnight, 8)
	if err != nil {
		t.Fatalf("midnight: %v", err)
	}
	if !slices.Equal(localLabels, midnightLabels) {
		t.Fatalf("labels depend on the time zone\nlocal %v\nUTC   %v", localLabels, midnightLabels)
	}
}

func TestLabelsBounds(t *testing.T) {
	cases := []struct {
		name     string
		seed     []byte
		campaign string
		n        int
	}{
		{name: "nil seed", seed: nil, campaign: "acme", n: 8},
		{name: "short seed", seed: bytes.Repeat([]byte{1}, minSeedBytes-1), campaign: "acme", n: 8},
		{name: "empty campaign", seed: seedOf(0x11), campaign: "", n: 8},
		{name: "zero count", seed: seedOf(0x11), campaign: "acme", n: 0},
		{name: "negative count", seed: seedOf(0x11), campaign: "acme", n: -1},
		{name: "too many labels", seed: seedOf(0x11), campaign: "acme", n: maxLabels + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Labels(tc.seed, tc.campaign, baseDay, tc.n); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}

	labels, err := Labels(bytes.Repeat([]byte{7}, minSeedBytes), "acme", baseDay, maxLabels)
	if err != nil {
		t.Fatalf("exact bounds: %v", err)
	}
	if len(labels) != maxLabels {
		t.Fatalf("labels = %d, want %d", len(labels), maxLabels)
	}
}

func TestFull(t *testing.T) {
	labels := []string{"abc234", "def567"}
	got, err := Full("example.com", labels)
	if err != nil {
		t.Fatalf("Full: %v", err)
	}
	want := []string{"abc234.example.com", "def567.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("Full = %v, want %v", got, want)
	}

	empty, err := Full("example.com", nil)
	if err != nil {
		t.Fatalf("Full with no labels: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("Full with no labels = %v, want empty", empty)
	}
}

func TestFullRejectsBadApex(t *testing.T) {
	tooLong := strings.Repeat("a", maxNameLen+1)
	cases := []string{
		"",
		"Example.com",
		"-bad.example",
		"bad-.example",
		"bad..example",
		"bad_domain.example",
		"bad label.example",
		tooLong,
	}
	for _, apex := range cases {
		t.Run(apex, func(t *testing.T) {
			if _, err := Full(apex, []string{"abc234"}); err == nil {
				t.Fatalf("apex %q accepted", apex)
			}
		})
	}
}

func TestFullRejectsBadLabels(t *testing.T) {
	cases := []string{
		"",
		"-abc",
		"abc-",
		"Abc234",
		"abc_234",
		"abc.234",
		strings.Repeat("a", maxLabelLen+1),
	}
	for _, label := range cases {
		if _, err := Full("example.com", []string{label}); err == nil {
			t.Fatalf("label %q accepted", label)
		}
	}
}

func TestFullLabelLengthBoundary(t *testing.T) {
	const apex = "example.com"

	label63 := strings.Repeat("a", maxLabelLen)
	names, err := Full(apex, []string{label63})
	if err != nil {
		t.Fatalf("63-byte label rejected: %v", err)
	}
	if want := label63 + "." + apex; names[0] != want {
		t.Fatalf("name = %q, want %q", names[0], want)
	}

	label64 := strings.Repeat("a", maxLabelLen+1)
	if _, err := Full(apex, []string{label64}); err == nil {
		t.Fatal("64-byte label accepted")
	}
}

func TestFullNameLengthBoundary(t *testing.T) {
	label := strings.Repeat("d", maxLabelLen)

	apexFits63 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61)
	names, err := Full(apexFits63, []string{label})
	if err != nil {
		t.Fatalf("253-byte name rejected: %v", err)
	}
	if got := len(names[0]); got != maxNameLen {
		t.Fatalf("name length = %d, want %d", got, maxNameLen)
	}

	apex254 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 62)
	if _, err := Full(apex254, []string{label}); err == nil {
		t.Fatal("254-byte name accepted")
	}

	// This apex is exactly 253 bytes: valid on its own, but with no room for
	// any label. The error must name the apex, not merely report a generic name
	// length.
	apexNoRoom := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(apexNoRoom) != maxNameLen {
		t.Fatalf("test apex = %d bytes, want %d", len(apexNoRoom), maxNameLen)
	}
	_, err = Full(apexNoRoom, []string{"a"})
	if err == nil {
		t.Fatal("apex with no room for a label accepted")
	}
	if got := err.Error(); !strings.Contains(got, "apex") || !strings.Contains(got, "cannot accommodate") {
		t.Fatalf("error = %q, want a dedicated apex message", got)
	}
}

func TestValidLabel(t *testing.T) {
	cases := map[string]bool{
		"a":                           true,
		"a-b":                         true,
		"2abc":                        true,
		strings.Repeat("a", 63):       true,
		"":                            false,
		"-a":                          false,
		"a-":                          false,
		"A":                           false,
		"a_b":                         false,
		"a.b":                         false,
		strings.Repeat("a", 64):       false,
		strings.Repeat("-", 63):       false,
		strings.Repeat("a", 62) + "-": false,
	}
	for label, want := range cases {
		if got := validLabel(label); got != want {
			t.Errorf("validLabel(%q) = %v, want %v", label, got, want)
		}
	}
}
