package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Iterations = 600_000
	pbkdf2SaltBytes  = 16
	pbkdf2KeyBytes   = 32
)

// HashPassword derives a verifier from a plain-text password using
// PBKDF2-SHA256 with 600 000 iterations and a 16-byte random salt.
// The returned string has the format:
//
//	pbkdf2$<iterations>$<salt-hex>$<hash-hex>
//
// Store only this string; never the clear password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("admin: hash password: %w", err)
	}
	key := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes)
	return fmt.Sprintf("pbkdf2$%d$%s$%s",
		pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// CheckPassword verifies password against the stored verifier returned by
// HashPassword. The comparison is constant-time so a timing attack cannot
// distinguish a bad password from a bad hash format.
func CheckPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	wantKey, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	gotKey := pbkdf2Key([]byte(password), salt, iter, len(wantKey))
	return subtle.ConstantTimeCompare(gotKey, wantKey) == 1
}

// ValidatePasswordHash checks the stored verifier format at boot. A malformed
// verifier would make every login fail with 401 and look like a wrong password,
// with no operator-visible indication that the file itself is broken.
func ValidatePasswordHash(stored string) error {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return fmt.Errorf("admin: PasswordHash must have the form pbkdf2$<iterations>$<salt-hex>$<hash-hex>")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 100_000 || iter > 10_000_000 {
		return fmt.Errorf("admin: PasswordHash iterations must be an integer between 100000 and 10000000")
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return fmt.Errorf("admin: PasswordHash salt must be hex and at least 16 bytes")
	}
	key, err := hex.DecodeString(parts[3])
	if err != nil || len(key) != 32 {
		return fmt.Errorf("admin: PasswordHash key must be 32 bytes of hex")
	}
	return nil
}

// pbkdf2Key implements PBKDF2 (RFC 2898) with HMAC-SHA256.
// This is the RFC 2898 §5.2 construction: for each block index, compute
//
//	T_i = F(password, salt, c, i)
//
// where F = XOR of c HMAC applications, with the first keyed on salt||INT(i).
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	hashLen := sha256.Size // 32 bytes
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	out := make([]byte, 0, numBlocks*hashLen)

	for block := 1; block <= numBlocks; block++ {
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)

		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(buf[:])
		U := mac.Sum(nil)
		T := make([]byte, hashLen)
		copy(T, U)

		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(U)
			U = mac.Sum(nil)
			for j := range T {
				T[j] ^= U[j]
			}
		}
		out = append(out, T...)
	}
	return out[:keyLen]
}
