package charon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const tokenBytes = 32

// TokenStore is the slice of the campaign store token authentication needs.
type TokenStore interface {
	GetExportTokenHash(ctx context.Context, campaignID string) (string, error)
	SetExportTokenHash(ctx context.Context, campaignID, hash string) error
}

// NewToken returns a fresh 256-bit bearer token. Raw URL encoding keeps it
// usable in an Authorization header without percent-encoding.
func NewToken() (string, error) {
	var b [tokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("charon: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HashToken is the only form persisted. The clear token exists once, when it is
// issued.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IssueToken creates a token for a campaign, stores its hash, and returns the
// clear value. The store call doubles as the campaign existence check.
func IssueToken(ctx context.Context, tokens TokenStore, campaignID string) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	if err := tokens.SetExportTokenHash(ctx, campaignID, HashToken(token)); err != nil {
		return "", err
	}
	return token, nil
}

// authorize compares the presented hash in constant time. Absence is 401;
// a present but wrong token is 403, whether it is random or belongs to another
// campaign.
func authorize(r *http.Request, expectedHash string) (int, string) {
	token, ok := bearerToken(r)
	if !ok {
		return http.StatusUnauthorized, "missing bearer token"
	}
	if expectedHash == "" {
		return http.StatusForbidden, "campaign has no export token"
	}
	got := HashToken(token)
	if subtle.ConstantTimeCompare([]byte(got), []byte(expectedHash)) != 1 {
		return http.StatusForbidden, "invalid token"
	}
	return 0, ""
}

func bearerToken(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(raw[len(prefix):])
	return token, token != ""
}

var errNoCampaign = errors.New("charon: campaign id is required")
