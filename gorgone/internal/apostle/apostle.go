// Package apostle performs read-only reconnaissance on an IMAP mailbox.
//
// # What it does
//
// Apostle connects to an IMAP server, selects a mailbox in read-only mode
// (EXAMINE, never SELECT), searches for messages, fetches only the envelope
// headers (From, To, Cc), and extracts unique normalised email addresses. It
// never issues STORE, COPY, EXPUNGE or any command that mutates state.
//
// It also verifies a submitted password by logging in with it and observing
// whether the server accepts it. The session used for verification is
// immediately LOGOUT'd; no mail is read during it.
//
// # Guarantees
//
//   - No write command is ever sent; a fake IMAP server can assert this.
//   - No message body, subject, or date is retained after the call returns.
//   - A configurable limit on the number of messages examined prevents runaway
//     fetches against a large inbox.
//   - A single context deadline controls the entire operation.
package apostle

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ErrTimeout is returned when the context deadline expires before the
// operation completes. It wraps the underlying context error so callers can
// use errors.Is(err, ErrTimeout).
var ErrTimeout = errors.New("apostle: operation timed out")

// ErrWriteCommand is returned by the safety guard if any attempt to send a
// write command is detected at the client level. It should never be reached in
// normal use; it exists so tests can assert the invariant structurally.
var ErrWriteCommand = errors.New("apostle: write command refused")

// Config carries the connection and operation parameters for one apostle call.
type Config struct {
	// Host is the IMAP server hostname, e.g. "imap.example.com".
	Host string
	// Port is the IMAP port. 993 (implicit TLS) is the default.
	Port int
	// Username is the mailbox owner used for authentication.
	Username string
	// Password is the mailbox password used for authentication.
	// It is compared against the IMAP server; it is never stored or logged.
	Password string
	// Mailbox is the IMAP folder to examine. "INBOX" if empty.
	Mailbox string
	// FilterDomain, when non-empty, restricts extracted addresses to that
	// domain. The comparison is case-insensitive.
	FilterDomain string
	// MaxMessages caps the number of messages whose envelopes are fetched.
	// Zero means no cap (not recommended against large inboxes).
	MaxMessages int
	// FetchSize caps the number of octets returned per FETCH. Zero means 4096.
	FetchSize int
	// Timeout is the wall-clock deadline for the entire operation.
	// Zero means 30 seconds.
	Timeout time.Duration
	// STARTTLS forces a plain TCP connection upgraded with STARTTLS even
	// when Port is not 143. Port 143 always uses STARTTLS automatically.
	STARTTLS bool
	// ImplicitTLS forces implicit TLS even on port 143. It exists for the
	// rare server that speaks implicit TLS on the submission-style port;
	// it overrides both Port 143 auto-detection and STARTTLS.
	ImplicitTLS bool
	// TLSConfig overrides the default TLS configuration. Used by tests to
	// inject a self-signed certificate.
	TLSConfig *tls.Config
}

func (c *Config) port() int {
	if c.Port == 0 {
		return 993
	}
	return c.Port
}

// useSTARTTLS reports whether the connection should use a plain TCP dial
// followed by a STARTTLS upgrade, rather than implicit TLS from the start.
// Port 143 is the conventional STARTTLS port; callers may also set
// Config.STARTTLS to force it on another port, or Config.ImplicitTLS to
// force implicit TLS on 143.
func (c *Config) useSTARTTLS() bool {
	if c.ImplicitTLS {
		return false
	}
	return c.STARTTLS || c.port() == 143
}

func (c *Config) mailbox() string {
	if c.Mailbox == "" {
		return "INBOX"
	}
	return c.Mailbox
}

func (c *Config) fetchSize() int {
	if c.FetchSize <= 0 {
		return 4096
	}
	return c.FetchSize
}

func (c *Config) timeout() time.Duration {
	if c.Timeout == 0 {
		return 30 * time.Second
	}
	return c.Timeout
}

const maxAddresses = 500

// Result is returned by Examine and Authenticate.
type Result struct {
	// Contacts is the deduplicated, normalised list of email addresses
	// extracted from the envelope headers of examined messages.
	Contacts []string
	// Partial is true when MaxMessages was reached before the inbox was fully
	// scanned. The caller can resume with a larger cap or accept the partial set.
	Partial bool
	// AddressTruncated is true when the extracted address set exceeded the
	// built-in cap of 500 unique addresses. The Contacts slice is capped at
	// that value; a re-run with a narrower FilterDomain is recommended.
	AddressTruncated bool
}

// Examine connects to the IMAP server, authenticates the mailbox owner,
// examines the configured mailbox in read-only mode, and returns extracted
// contact addresses. The mailbox owner's own address is excluded from the
// result.
//
// The context controls the wall-clock deadline; a tighter Timeout in Config
// further constrains it.
func Examine(ctx context.Context, cfg Config) (Result, error) {
	// Always enforce the config timeout, even when ctx has no deadline of its
	// own. context.WithDeadline takes the earlier of the two deadlines, so a
	// tighter caller deadline still wins.
	deadline := time.Now().Add(cfg.timeout())
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	c, err := dial(ctx, cfg)
	if err != nil {
		return Result{}, wrapTimeout(ctx, err)
	}
	defer c.logout()

	if err := c.login(cfg.Username, cfg.Password); err != nil {
		return Result{}, wrapTimeout(ctx, err)
	}

	ids, partial, err := c.search(ctx, cfg)
	if err != nil {
		return Result{}, wrapTimeout(ctx, err)
	}

	addrs, err := c.fetchEnvelopes(ctx, cfg, ids)
	if err != nil {
		return Result{}, wrapTimeout(ctx, err)
	}

	contacts := filterAddresses(addrs, cfg.Username, cfg.FilterDomain)
	truncated := false
	if len(contacts) > maxAddresses {
		contacts = contacts[:maxAddresses]
		truncated = true
	}
	return Result{Contacts: contacts, Partial: partial, AddressTruncated: truncated}, nil
}

// Authenticate opens a fresh IMAP connection and attempts to log in with the
// supplied credentials. It returns true when the server accepts the login.
// No mail is read; the connection is LOGOUT'd immediately.
//
// This is used to verify a password captured from a phishing flow: the
// verification stays within the same tenant and never exfiltrates credentials
// to a third party.
func Authenticate(ctx context.Context, cfg Config, username, password string) (bool, error) {
	// Same deadline logic as Examine: always bound even with context.Background().
	deadline := time.Now().Add(cfg.timeout())
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	c, err := dial(ctx, cfg)
	if err != nil {
		return false, wrapTimeout(ctx, err)
	}
	defer c.logout()

	err = c.login(username, password)
	if err != nil {
		if isAuthError(err) {
			return false, nil
		}
		return false, wrapTimeout(ctx, err)
	}
	return true, nil
}

func wrapTimeout(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// A connection read/write deadline can fire a few microseconds before the
	// context's own timer is observed; both mean the global timeout elapsed.
	if ctx.Err() != nil || isTimeoutError(err) {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return err
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no") || strings.Contains(msg, "bad") ||
		strings.Contains(msg, "invalid") || strings.Contains(msg, "authenticationfailed")
}
