package apostle

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// bannedCommands is the closed set of IMAP commands that must never be sent.
// The list is normalised to uppercase. Any attempt to send one returns
// ErrWriteCommand immediately.
var bannedCommands = []string{
	"SELECT", // read-write; use EXAMINE instead
	"STORE", "COPY", "UID STORE", "UID COPY",
	"EXPUNGE", "CLOSE", "DELETE", "RENAME",
	"SUBSCRIBE", "UNSUBSCRIBE", "CREATE", "APPEND",
	"SETACL", "DELETEACL", "SETQUOTA",
}

// ErrFetchWithoutPeek is returned when a FETCH body-part is requested without
// the .PEEK modifier. Without .PEEK the server sets the \Seen flag, which is a
// server-side write.
var ErrFetchWithoutPeek = errors.New("apostle: FETCH without BODY.PEEK refused; would set \\Seen")

// client is a minimal, read-only IMAP client.
type client struct {
	conn net.Conn
	r    *bufio.Reader
	w    io.Writer
	tag  uint32 // monotonic tag counter, accessed via atomic
}

// dial opens a connection to the IMAP server and reads the server greeting.
// For implicit TLS (port 993) it dials with tls.Dialer.
// For STARTTLS (port 143 or Config.STARTTLS=true) it dials plain TCP, reads
// the greeting, issues STARTTLS, and upgrades the connection to TLS.
func dial(ctx context.Context, cfg Config) (*client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.port())
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	}

	if cfg.useSTARTTLS() {
		return dialSTARTTLS(ctx, addr, tlsCfg)
	}
	return dialImplicit(ctx, addr, tlsCfg)
}

// dialImplicit dials with implicit TLS (port 993 convention).
func dialImplicit(ctx context.Context, addr string, tlsCfg *tls.Config) (*client, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("apostle: dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	c := &client{conn: conn, r: bufio.NewReaderSize(conn, 32<<10), w: conn}
	if _, err := c.readLine(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apostle: greeting: %w", err)
	}
	return c, nil
}

// dialSTARTTLS dials plain TCP, reads the greeting, sends STARTTLS, and
// upgrades to TLS. The post-upgrade EHLO / greeting is not consumed here;
// the caller continues with the already-authenticated session.
func dialSTARTTLS(ctx context.Context, addr string, tlsCfg *tls.Config) (*client, error) {
	nd := &net.Dialer{}
	rawConn, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("apostle: starttls dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(dl)
	}

	plainClient := &client{conn: rawConn, r: bufio.NewReaderSize(rawConn, 32<<10), w: rawConn}

	// Read the plain-text greeting.
	if _, err := plainClient.readLine(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apostle: starttls greeting: %w", err)
	}

	// Negotiate STARTTLS.
	tag, err := plainClient.send("STARTTLS")
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apostle: STARTTLS send: %w", err)
	}
	_, status, err := plainClient.collect(tag)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apostle: STARTTLS response: %w", err)
	}
	if !ok(status) {
		rawConn.Close()
		return nil, fmt.Errorf("apostle: server declined STARTTLS: %s", status)
	}

	// Upgrade to TLS.
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("apostle: TLS handshake after STARTTLS: %w", err)
	}
	c := &client{conn: tlsConn, r: bufio.NewReaderSize(tlsConn, 32<<10), w: tlsConn}
	return c, nil
}

// send formats and sends one IMAP command. It refuses any command whose verb
// appears in bannedCommands. This is a defence-in-depth guard; it must not be
// relied upon as the sole protection.
func (c *client) send(format string, args ...any) (string, error) {
	tag := fmt.Sprintf("A%d", atomic.AddUint32(&c.tag, 1))
	body := fmt.Sprintf(format, args...)
	line := tag + " " + body + "\r\n"

	// Extract the verb from the composed line (second token: first is the tag).
	parts := strings.Fields(line)
	var verb string
	if len(parts) >= 2 {
		verb = strings.ToUpper(parts[1])
		// Check for UID <VERB> compound commands.
		fullVerb := verb
		if verb == "UID" && len(parts) >= 3 {
			fullVerb = "UID " + strings.ToUpper(parts[2])
		}
		for _, banned := range bannedCommands {
			if fullVerb == banned || verb == banned {
				return "", ErrWriteCommand
			}
		}
		// A FETCH body-part without .PEEK implicitly sets \Seen on the server —
		// a write that EXAMINE does not prevent. Refuse any such command before
		// it is transmitted.
		isFetch := verb == "FETCH" || (verb == "UID" && len(parts) >= 3 && strings.ToUpper(parts[2]) == "FETCH")
		if isFetch {
			upper := strings.ToUpper(body)
			if strings.Contains(upper, "BODY[") && !strings.Contains(upper, "BODY.PEEK[") {
				return "", ErrFetchWithoutPeek
			}
		}
	}

	if _, err := fmt.Fprint(c.w, line); err != nil {
		return "", fmt.Errorf("apostle: send: %w", err)
	}
	return tag, nil
}

// readLine reads one line from the server, stripping CRLF.
func (c *client) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	return line, err
}

// collect reads server lines until the tagged response for tag. It returns all
// untagged lines and the final tagged status line.
func (c *client) collect(tag string) ([]string, string, error) {
	var untagged []string
	for {
		line, err := c.readLine()
		if err != nil {
			return untagged, "", fmt.Errorf("apostle: read: %w", err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return untagged, line, nil
		}
		untagged = append(untagged, line)
	}
}

// ok returns true when the tagged status is OK.
func ok(status string) bool {
	parts := strings.Fields(status)
	return len(parts) >= 2 && strings.EqualFold(parts[1], "OK")
}

// login sends LOGIN and reads the response. It returns a typed auth error when
// the server responds with NO or BAD.
func (c *client) login(username, password string) error {
	tag, err := c.send("LOGIN %s %s", imapLiteral(username), imapLiteral(password))
	if err != nil {
		return err
	}
	_, status, err := c.collect(tag)
	if err != nil {
		return err
	}
	if !ok(status) {
		return fmt.Errorf("apostle: login NO: %s", status)
	}
	return nil
}

// examine opens a mailbox in read-only mode (EXAMINE, never SELECT).
func (c *client) examine(mailbox string) error {
	tag, err := c.send("EXAMINE %s", imapLiteral(mailbox))
	if err != nil {
		return err
	}
	_, status, err := c.collect(tag)
	if err != nil {
		return err
	}
	if !ok(status) {
		return fmt.Errorf("apostle: EXAMINE %s: %s", mailbox, status)
	}
	return nil
}

// logout sends LOGOUT best-effort, then closes the connection regardless.
// Close is separated from LOGOUT so a network error during LOGOUT does not
// leak the socket.
func (c *client) logout() {
	defer c.conn.Close() // always close, even if LOGOUT fails
	tag, err := c.send("LOGOUT")
	if err == nil {
		c.collect(tag) //nolint:errcheck // best-effort
	}
}

// search performs SEARCH ALL and returns the message sequence numbers.
func (c *client) search(ctx context.Context, cfg Config) ([]int, bool, error) {
	if err := c.examine(cfg.mailbox()); err != nil {
		return nil, false, err
	}

	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	tag, err := c.send("SEARCH ALL")
	if err != nil {
		return nil, false, err
	}
	untagged, status, err := c.collect(tag)
	if err != nil {
		return nil, false, err
	}
	if !ok(status) {
		return nil, false, fmt.Errorf("apostle: SEARCH: %s", status)
	}

	var ids []int
	for _, line := range untagged {
		if !strings.HasPrefix(line, "* SEARCH") {
			continue
		}
		for _, part := range strings.Fields(line[8:]) {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				ids = append(ids, n)
			}
		}
	}

	partial := false
	if cfg.MaxMessages > 0 && len(ids) > cfg.MaxMessages {
		ids = ids[:cfg.MaxMessages]
		partial = true
	}
	return ids, partial, nil
}

// fetchEnvelopes fetches the RFC822.HEADER of each message and returns all
// From, To, Cc addresses found. Message content is never retained.
func (c *client) fetchEnvelopes(ctx context.Context, cfg Config, ids []int) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var addrs []string
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return addrs, err
		}

		tag, err := c.send("FETCH %d (BODY.PEEK[HEADER.FIELDS (FROM TO CC)])", id)
		if err != nil {
			return addrs, err
		}

		untagged, status, err := c.collect(tag)
		if err != nil {
			return addrs, err
		}
		if !ok(status) {
			// Skip individual fetch failures; the message may be gone.
			continue
		}

		// Collect header lines from the untagged response.
		for _, line := range untagged {
			addrs = append(addrs, parseAddressLine(line)...)
		}
	}
	return addrs, nil
}

// parseAddressLine extracts RFC 5322 addresses from a single header line.
// It handles From:, To:, and Cc: headers and returns any bare addresses found.
func parseAddressLine(line string) []string {
	var out []string
	lower := strings.ToLower(line)
	var value string
	switch {
	case strings.HasPrefix(lower, "from:"):
		value = line[5:]
	case strings.HasPrefix(lower, "to:"):
		value = line[3:]
	case strings.HasPrefix(lower, "cc:"):
		value = line[3:]
	default:
		return nil
	}
	for _, addr := range extractAddresses(value) {
		if a := normalizeAddress(addr); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// extractAddresses splits a header value into individual addresses. It strips
// display names and angle brackets, leaving only the bare addr-spec.
func extractAddresses(value string) []string {
	// Split on commas first (multiple recipients).
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Prefer angle-bracket form: "Display Name <addr>".
		if start := strings.LastIndex(part, "<"); start >= 0 {
			if end := strings.Index(part[start:], ">"); end > 0 {
				out = append(out, part[start+1:start+end])
				continue
			}
		}
		// Bare address.
		out = append(out, part)
	}
	return out
}

// normalizeAddress lowercases and trims the address. Returns "" for strings
// that do not look like email addresses (no "@").
func normalizeAddress(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if !strings.Contains(addr, "@") {
		return ""
	}
	return addr
}

// filterAddresses deduplicates, removes the mailbox owner's own address, and
// (when filterDomain is non-empty) keeps only addresses on that domain.
func filterAddresses(addrs []string, owner, filterDomain string) []string {
	owner = normalizeAddress(owner)
	filterDomain = strings.ToLower(strings.TrimSpace(filterDomain))

	seen := make(map[string]struct{}, len(addrs))
	var out []string
	for _, a := range addrs {
		a = normalizeAddress(a)
		if a == "" || a == owner {
			continue
		}
		if filterDomain != "" {
			atIdx := strings.LastIndex(a, "@")
			if atIdx < 0 || a[atIdx+1:] != filterDomain {
				continue
			}
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// imapLiteral quotes a string for use as an IMAP astring. It uses the quoted
// string form for values that contain only safe characters, and the literal
// form ({n}\r\n...) for everything else. For this read-only client, all values
// are user-supplied strings that must round-trip safely.
func imapLiteral(s string) string {
	// If the string contains only safe characters, use quoted form.
	safe := true
	for _, r := range s {
		if r == '"' || r == '\\' || r > 126 || r < 32 {
			safe = false
			break
		}
	}
	if safe {
		return `"` + s + `"`
	}
	// Literal form.
	return fmt.Sprintf("{%d}\r\n%s", len(s), s)
}
