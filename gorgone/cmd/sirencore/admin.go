package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/siren-core/gorgone/internal/admin"
	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
)

// adminFileConfig is the on-disk admin section. It intentionally has no field
// able to hold a secret: strict decoding (DisallowUnknownFields) turns an
// inline "password_hash", "totp_secret" or "csrf_secret" into a boot error
// instead of silently accepting a secret in config.json.
type adminFileConfig struct {
	PasswordHashFile string   `json:"password_hash_file"`
	TOTPSecretFile   string   `json:"totp_secret_file"`
	CSRFSecretFile   string   `json:"csrf_secret_file"`
	Allowlist        []string `json:"allowlist"`
	// RateLimit is a pointer so "absent" and "explicitly 0" differ. Absent
	// uses defaultAdminRateLimit; 0 disables the limiter and is documented as
	// development-only.
	RateLimit *int `json:"rate_limit"`

	// allowlist is parsed by validate, exactly like trusted_proxies.
	allowlist []*net.IPNet
}

const defaultAdminRateLimit = 5

// validate enforces the file-only secret contract and parses the allowlist.
// Secret files are not opened here: loadConfig also serves -healthcheck, which
// must keep working when the secrets live in a tmpfs mounted only for the
// server process. The file paths are still checked so a typo fails at config
// load rather than after the database has been opened.
func (a *adminFileConfig) validate() error {
	if a == nil {
		return nil
	}
	if strings.TrimSpace(a.PasswordHashFile) == "" {
		return errors.New("admin.password_hash_file is required")
	}
	if strings.TrimSpace(a.TOTPSecretFile) == "" {
		return errors.New("admin.totp_secret_file is required")
	}
	if strings.TrimSpace(a.CSRFSecretFile) == "" && !admin.DevMode() {
		return errors.New("admin.csrf_secret_file is required outside SIREN_DEV=1")
	}

	networks, bad := collect.ParseCIDRs(a.Allowlist)
	if len(bad) > 0 {
		return fmt.Errorf("admin.allowlist: %w", errors.Join(bad...))
	}
	if len(networks) == 0 && !admin.DevMode() {
		return errors.New("admin.allowlist is empty: set at least one CIDR; " +
			"an empty allowlist means \"allow every IP\" and is accepted only with SIREN_DEV=1")
	}
	a.allowlist = networks

	if a.RateLimit != nil && *a.RateLimit < 0 {
		return fmt.Errorf("admin.rate_limit must not be negative, got %d", *a.RateLimit)
	}
	return nil
}

// loadAdminSecrets reads the three secrets from files and assembles the
// runtime admin.Config. It is called only in server mode, after the
// rotate/retire/export/issue switch, so a CLI export never needs the admin
// files to be mounted.
func loadAdminSecrets(cfg *fileConfig, db *sql.DB, logger *slog.Logger) (*admin.Config, error) {
	if cfg.Admin == nil {
		return nil, nil
	}
	a := cfg.Admin

	passwordHash, err := readTextSecret(a.PasswordHashFile)
	if err != nil {
		return nil, fmt.Errorf("admin password hash: %w", err)
	}
	totpSecret, err := readTextSecret(a.TOTPSecretFile)
	if err != nil {
		return nil, fmt.Errorf("admin TOTP secret: %w", err)
	}

	var csrfSecret []byte
	if path := strings.TrimSpace(a.CSRFSecretFile); path != "" {
		csrfSecret, err = readCSRFSecret(path)
		if err != nil {
			return nil, err
		}
	}

	sessions, err := admin.NewSQLiteSessionStore(db)
	if err != nil {
		return nil, err
	}

	rateLimit := defaultAdminRateLimit
	if a.RateLimit != nil {
		rateLimit = *a.RateLimit
	}

	ac := &admin.Config{
		PasswordHash:   passwordHash,
		TOTPSecret:     totpSecret,
		CSRFSecret:     csrfSecret,
		Allowlist:      a.allowlist,
		TrustedProxies: cfg.trusted,
		Sessions:       sessions,
		RateLimit:      rateLimit,
		SecureCookies:  !admin.DevMode(),
		Logger:         logger,
	}
	// Validate is the boot gate: a missing CSRF secret outside SIREN_DEV=1, a
	// malformed password hash, a malformed TOTP secret or an empty allowlist
	// must stop the process before the admin listener exists.
	if err := ac.Validate(); err != nil {
		return nil, err
	}
	return ac, nil
}

const (
	maxAdminTextSecretBytes = 64 << 10 // password hash / TOTP secret
	maxAdminCSRFSecretBytes = 4 << 10  // raw key material
)

// readTextSecret reads a text secret, refusing directories, writable files and
// oversized payloads. The write-bit check mirrors collect.LoadKeyFile: a file
// another process can modify is equivalent to a compromised secret. POSIX mode
// bits are not meaningful on Windows, so the check is skipped there.
func readTextSecret(path string) (string, error) {
	data, err := readAdminSecretFile(path, maxAdminTextSecretBytes)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%q is empty", path)
	}
	return value, nil
}

// readCSRFSecret reads the CSRF key as raw bytes. No trimming: a trailing CR/LF
// is a configuration mistake (the documented generation command is
// `openssl rand 32 > csrf.key`) and accepting it would silently change the key.
func readCSRFSecret(path string) ([]byte, error) {
	data, err := readAdminSecretFile(path, maxAdminCSRFSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("admin CSRF secret: %w", err)
	}
	if len(data) < 32 {
		return nil, fmt.Errorf("admin CSRF secret %q: %d bytes, need at least 32 raw bytes", path, len(data))
	}
	if strings.ContainsAny(string(data), "\r\n") {
		return nil, fmt.Errorf("admin CSRF secret %q contains CR/LF; write raw bytes (openssl rand 32 > csrf.key)", path)
	}
	return data, nil
}

func readAdminSecretFile(path string, limit int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%q is group- or world-writable (mode %04o); a writable secret is a compromised secret",
			path, info.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q exceeds %d bytes", path, limit)
	}
	return data, nil
}

// adminCampaignLister adapts the operational store to the narrow projection the
// admin package renders. Keeping the adapter here is what lets internal/admin
// stay independent of internal/store.
func adminCampaignLister(ops opsStore) admin.CampaignLister {
	return func(ctx context.Context) ([]admin.Campaign, error) {
		rows, err := ops.ListCampaigns(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]admin.Campaign, 0, len(rows))
		for _, c := range rows {
			created := ""
			if !c.CreatedAt.IsZero() {
				created = sirendb.FormatTime(c.CreatedAt)
			}
			out = append(out, admin.Campaign{
				ID:      c.ID,
				Name:    c.Name,
				State:   string(c.State),
				Created: created,
			})
		}
		return out, nil
	}
}
