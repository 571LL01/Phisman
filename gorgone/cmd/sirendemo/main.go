// Command sirendemo is a throwaway local-testing helper (NOT part of the
// product). It wires admin secrets, seeds a campaign + contact, prints the
// tracking funnel, and prints a live TOTP code, so the open/click tracking can
// be exercised locally without the full operator workflow.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/siren-core/gorgone/internal/admin"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: sirendemo <setup|seed|stats|totp> ...")
	}
	switch os.Args[1] {
	case "setup":
		// setup <run-dir> <password>
		cmdSetup(arg(2), arg(3))
	case "seed":
		// seed <db-path>
		cmdSeed(arg(2))
	case "stats":
		// stats <db-path> <campaign-id>
		cmdStats(arg(2), arg(3))
	case "totp":
		// totp <totp-secret-file>
		cmdTOTP(arg(2))
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func cmdSetup(runDir, password string) {
	if runDir == "" || password == "" {
		fail("usage: sirendemo setup <run-dir> <password>")
	}
	secretsDir := filepath.Join(runDir, "secrets")
	mustMkdir(secretsDir)
	mustMkdir(filepath.Join(runDir, "data"))

	hash, err := admin.HashPassword(password)
	must(err)
	mustWrite(filepath.Join(secretsDir, "admin-password-hash"), []byte(hash))

	totpRaw := mustRand(20)
	totpSecret := base32.StdEncoding.EncodeToString(totpRaw) // 32 chars, no padding
	if err := admin.ValidateTOTPSecret(totpSecret); err != nil {
		fail("generated TOTP secret invalid: %v", err)
	}
	mustWrite(filepath.Join(secretsDir, "admin-totp-secret"), []byte(totpSecret))

	mustWrite(filepath.Join(secretsDir, "admin-csrf-secret"), mustRand(32))

	fmt.Println("OK setup")
	fmt.Println("password    :", password)
	fmt.Println("totp_secret :", totpSecret)
	fmt.Println("totp_now    :", totpNow(totpSecret))
}

func cmdSeed(dbPath string) {
	if dbPath == "" {
		fail("usage: sirendemo seed <db-path>")
	}
	ctx := context.Background()
	st := openStore(dbPath)

	c, err := st.CreateCampaign(ctx, "Demo Tracking")
	must(err)
	_, err = st.AddContacts(ctx, c.ID, []store.ContactInput{
		{Email: "cible@example.com", Vars: map[string]string{"FirstName": "Cible", "lang": "fr"}},
	})
	must(err)
	contacts, err := st.ListContacts(ctx, c.ID)
	must(err)

	fmt.Println("OK seed")
	fmt.Println("campaign_id :", c.ID)
	fmt.Println("contact_id  :", contacts[0].ID)
}

func cmdStats(dbPath, campaignID string) {
	if dbPath == "" || campaignID == "" {
		fail("usage: sirendemo stats <db-path> <campaign-id>")
	}
	ctx := context.Background()
	st := openStore(dbPath)

	es, err := st.EventStats(ctx, campaignID)
	must(err)
	sends, err := st.ListSendsByCampaign(ctx, campaignID)
	must(err)
	events, err := st.ListEventsByCampaign(ctx, campaignID)
	must(err)

	fmt.Println("=== Tunnel ===")
	fmt.Printf("Envois      : %d\n", len(sends))
	fmt.Printf("Ouvertures  : %d (contacts distincts)\n", es.Opened)
	fmt.Printf("Clics       : %d (contacts distincts)\n", es.Clicked)
	fmt.Println("--- événements bruts ---")
	for _, e := range events {
		fmt.Printf("%s  %-5s  contact=%s  ip=%s  ua=%q\n",
			e.OccurredAt.Format("15:04:05"), e.Kind, short(e.ContactID), e.RemoteIP, e.UserAgent)
	}
}

func cmdTOTP(secretFile string) {
	if secretFile == "" {
		fail("usage: sirendemo totp <totp-secret-file>")
	}
	raw, err := os.ReadFile(secretFile)
	must(err)
	fmt.Println(totpNow(strings.TrimSpace(string(raw))))
}

// --- helpers -----------------------------------------------------------------

func openStore(dbPath string) *store.SQL {
	handle, err := sirendb.Open("file:" + dbPath)
	must(err)
	st, err := store.New(handle.DB)
	must(err)
	return st
}

func totpNow(secretB32 string) string {
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimRight(secretB32, "=")))
	must(err)
	counter := time.Now().Unix() / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	h := mac.Sum(nil)
	off := h[len(h)-1] & 0x0f
	code := (uint32(h[off])&0x7f)<<24 | uint32(h[off+1])<<16 | uint32(h[off+2])<<8 | uint32(h[off+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func arg(i int) string {
	if i < len(os.Args) {
		return os.Args[i]
	}
	return ""
}

func mustMkdir(p string) { must(os.MkdirAll(p, 0o755)) }

func mustWrite(p string, b []byte) { must(os.WriteFile(p, b, 0o600)) }

func mustRand(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	must(err)
	return b
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
