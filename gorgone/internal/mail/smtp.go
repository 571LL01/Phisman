package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig holds the connection parameters for one SMTP relay.
type SMTPConfig struct {
	// Host is the SMTP server hostname, e.g. "smtp.example.com".
	Host string
	// Port is the SMTP port. 587 (STARTTLS) is the default; 465 (implicit TLS)
	// is not supported by net/smtp and must be proxied externally.
	Port int
	// Username and Password are used for PLAIN or LOGIN auth. Both empty means
	// no auth (relay trusts the sender IP).
	Username string
	Password string
	// ConnectTimeout caps the TCP dial and TLS handshake. Zero means 10 s.
	ConnectTimeout time.Duration
	// SendTimeout caps a single message DATA transaction. Zero means 30 s.
	SendTimeout time.Duration
	// tlsConfig overrides the TLS configuration used for STARTTLS. The zero
	// value builds a config from Host. It is intentionally unexported so only
	// test code (in the same package) can inject a self-signed certificate.
	tlsConfig *tls.Config
}

func (c *SMTPConfig) host() string {
	if c.Port == 0 || c.Port == 25 {
		return c.Host
	}
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c *SMTPConfig) connectTimeout() time.Duration {
	if c.ConnectTimeout == 0 {
		return 10 * time.Second
	}
	return c.ConnectTimeout
}

func (c *SMTPConfig) sendTimeout() time.Duration {
	if c.SendTimeout == 0 {
		return 30 * time.Second
	}
	return c.SendTimeout
}

// Sender delivers a single message via SMTP. It opens one connection per call
// so the caller controls concurrency.
type Sender struct {
	cfg SMTPConfig
}

// NewSender returns a Sender from cfg. The connection is not opened until Send.
func NewSender(cfg SMTPConfig) (*Sender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("mail: smtp host is required")
	}
	return &Sender{cfg: cfg}, nil
}

// Send opens a fresh SMTP connection, upgrades to STARTTLS, optionally
// authenticates, delivers msg and closes. The context controls the overall
// lifetime; individual timeouts from SMTPConfig still apply.
func (s *Sender) Send(ctx context.Context, msg *Message) error {
	raw, err := msg.Bytes()
	if err != nil {
		return fmt.Errorf("mail: serialize: %w", err)
	}

	// Dial with the connect timeout; honour ctx cancellation too.
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.connectTimeout())
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", s.cfg.host())
	if err != nil {
		return fmt.Errorf("mail: smtp dial %s: %w", s.cfg.host(), err)
	}
	// Wrap with send timeout for the SMTP exchange.
	deadline := time.Now().Add(s.cfg.sendTimeout())
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return fmt.Errorf("mail: smtp deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mail: smtp client: %w", err)
	}
	defer client.Close()

	// STARTTLS: required. The TLS config uses the hostname for SNI and
	// certificate validation; callers may inject a custom config for tests.
	tlsCfg := s.cfg.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
	}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("mail: starttls: %w", err)
	}

	// Auth is optional: a relay that trusts the sender IP needs none.
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: smtp auth: %w", err)
		}
	}

	envelopeFrom := envelopeAddress(msg.From)
	envelopeTo := envelopeAddress(msg.To)

	if err := client.Mail(envelopeFrom); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(envelopeTo); err != nil {
		return fmt.Errorf("mail: RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, err := wc.Write(raw); err != nil {
		wc.Close()
		return fmt.Errorf("mail: DATA write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mail: DATA close: %w", err)
	}
	return client.Quit()
}

// envelopeAddress extracts the bare RFC 5321 address from a header value that
// may contain a display name. For "Name <addr>" it returns "addr"; for a bare
// address it returns the value unchanged.
func envelopeAddress(headerValue string) string {
	headerValue = strings.TrimSpace(headerValue)
	if idx := strings.LastIndex(headerValue, "<"); idx >= 0 {
		addr := headerValue[idx+1:]
		if end := strings.Index(addr, ">"); end >= 0 {
			return strings.TrimSpace(addr[:end])
		}
	}
	return headerValue
}
