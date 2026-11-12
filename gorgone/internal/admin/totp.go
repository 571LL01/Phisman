package admin

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// totpStep returns the TOTP counter for t.
func totpStep(t time.Time) int64 {
	return t.Unix() / 30
}

// totpCode computes the 6-digit TOTP code for a base32-encoded secret and counter.
func totpCode(secretB32 string, counter int64) (string, error) {
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimRight(secretB32, "=")))
	if err != nil {
		return "", fmt.Errorf("admin: totp secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	code := (uint32(h[offset])&0x7f)<<24 |
		uint32(h[offset+1])<<16 |
		uint32(h[offset+2])<<8 |
		uint32(h[offset+3])
	return fmt.Sprintf("%06d", code%1_000_000), nil
}

// ValidateTOTP checks code against the ±1 window around t. It returns the
// step index that matched so the caller can record and reject replays.
// Returns -1, false when no window matches.
func ValidateTOTP(secretB32, code string, t time.Time) (int64, bool) {
	base := totpStep(t)
	for _, step := range []int64{base - 1, base, base + 1} {
		got, err := totpCode(secretB32, step)
		if err != nil {
			return -1, false
		}
		if hmac.Equal([]byte(got), []byte(code)) {
			return step, true
		}
	}
	return -1, false
}
