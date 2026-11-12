// Package mail composes and delivers campaign emails. The composition layer is
// separate from the delivery layer: Compose returns a fully-formed *Message
// that tests can inspect without touching a network.
//
// # HTML body
//
// The HTML body is a complete render of one campaign step, identical to what a
// visitor sees in the browser. The form action carries both the recipient id
// (rid) and the language tag (l), so the first click lands on the right
// language for that contact.
//
// # Plain-text body
//
// The plain-text body is derived from the HTML by stripping <script> and
// <style> blocks first, then all remaining tags, then decoding entities and
// collapsing whitespace. It is a best-effort fallback: MUAs that render HTML
// correctly use the HTML part.
//
// # Message-ID
//
// Message-ID is deterministic: HMAC-SHA256(campaignID|contactID|stepID) in hex,
// wrapped in angle brackets with the fixed host "siren". Two calls for the same
// inputs produce the same value; two different contacts produce different values.
// The key is derived from the campaign ID without an external secret.
package mail

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/siren-core/gorgone/internal/collect"
	"github.com/siren-core/gorgone/internal/tmpl"
)

// Message is a fully-formed email ready to hand to a Sender.
type Message struct {
	// From is the RFC 5321 envelope sender and also the From header.
	From string
	// To is the envelope recipient and the To header.
	To string
	// Subject is the UTF-8 subject line.
	Subject string
	// MessageID is the opaque value that goes between angle brackets.
	MessageID string
	// Date is the message timestamp.
	Date time.Time
	// RequestedLang is the language tag requested for this contact.
	// It may differ from SelectedLang when the contact's language is not
	// shipped by the template.
	RequestedLang string
	// SelectedLang is the BCP 47 tag of the variant that was actually rendered.
	// Use this for Content-Language; RequestedLang may name a non-shipped tag.
	SelectedLang string
	// ListUnsubscribe is optional. When non-empty it is emitted as the
	// List-Unsubscribe header value (must already include the angle brackets).
	ListUnsubscribe string
	// HTMLBody is the complete rendered HTML page.
	HTMLBody []byte
	// TextBody is the plain-text fallback derived from HTMLBody.
	TextBody []byte
}

// Bytes serialises the message as RFC 5322 / MIME multipart/alternative bytes.
// The return value is suitable as the DATA argument of an SMTP transaction.
func (m *Message) Bytes() ([]byte, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	boundary := mw.Boundary()

	// Plain-text part first: MUAs show the last matching part; text/plain
	// before text/html means HTML-capable clients see the HTML.
	th := make(textproto.MIMEHeader)
	th.Set("Content-Type", "text/plain; charset=utf-8")
	th.Set("Content-Transfer-Encoding", "quoted-printable")
	pw, err := mw.CreatePart(th)
	if err != nil {
		return nil, err
	}
	qw := quotedprintable.NewWriter(pw)
	if _, err := qw.Write(m.TextBody); err != nil {
		return nil, err
	}
	if err := qw.Close(); err != nil {
		return nil, err
	}

	// HTML part.
	hh := make(textproto.MIMEHeader)
	hh.Set("Content-Type", "text/html; charset=utf-8")
	hh.Set("Content-Transfer-Encoding", "quoted-printable")
	hw, err := mw.CreatePart(hh)
	if err != nil {
		return nil, err
	}
	qw = quotedprintable.NewWriter(hw)
	if _, err := qw.Write(m.HTMLBody); err != nil {
		return nil, err
	}
	if err := qw.Close(); err != nil {
		return nil, err
	}

	if err := mw.Close(); err != nil {
		return nil, err
	}

	// RFC 5322 headers above the body.
	var hdr bytes.Buffer
	hdr.WriteString("MIME-Version: 1.0\r\n")
	hdr.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	hdr.WriteString("From: " + m.From + "\r\n")
	hdr.WriteString("To: " + m.To + "\r\n")
	hdr.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", m.Subject) + "\r\n")
	hdr.WriteString("Message-ID: <" + m.MessageID + ">\r\n")
	hdr.WriteString("Date: " + m.Date.UTC().Format(time.RFC1123Z) + "\r\n")
	if m.SelectedLang != "" {
		hdr.WriteString("Content-Language: " + m.SelectedLang + "\r\n")
	}
	if m.ListUnsubscribe != "" {
		hdr.WriteString("List-Unsubscribe: " + m.ListUnsubscribe + "\r\n")
	}
	hdr.WriteString("\r\n")

	return append(hdr.Bytes(), body.Bytes()...), nil
}

// Composer holds the configuration needed to compose messages for a campaign.
// It is built once from a Renderer and reused across all contacts.
type Composer struct {
	renderer *tmpl.Renderer
	fromAddr string // RFC 5321 envelope address, e.g. "alice@example.com"
	fromName string // display name, may be empty
	baseURL  string // scheme+host, no trailing slash
	campaign string
	template string
	step     string
	unsubURL string // optional List-Unsubscribe URL
}

// Config carries the operator-supplied values for a Composer.
type Config struct {
	Renderer    *tmpl.Renderer
	FromAddress string
	FromName    string
	// BaseURL is the public root of this deployment, e.g. "https://siren.example.com".
	// Trailing slashes are stripped. Used to build absolute links in the email body.
	BaseURL  string
	Campaign string
	Template string
	Step     string
	UnsubURL string
}

// NewComposer validates Config and returns a Composer.
func NewComposer(cfg Config) (*Composer, error) {
	if cfg.Renderer == nil {
		return nil, fmt.Errorf("mail: renderer is required")
	}
	if cfg.FromAddress == "" {
		return nil, fmt.Errorf("mail: from address is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("mail: base URL is required")
	}
	if cfg.Campaign == "" || cfg.Template == "" || cfg.Step == "" {
		return nil, fmt.Errorf("mail: campaign, template and step are required")
	}
	return &Composer{
		renderer: cfg.Renderer,
		fromAddr: cfg.FromAddress,
		fromName: cfg.FromName,
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		campaign: cfg.Campaign,
		template: cfg.Template,
		step:     cfg.Step,
		unsubURL: cfg.UnsubURL,
	}, nil
}

// Compose renders the step for the given contact and returns a ready-to-send
// Message. lang is the contact's preferred language tag (may be empty); it is
// tried first, then the Accept-Language negotiation inside selectVariant falls
// back to the first shipped variant.
//
// RequestedLang on the returned Message is always lang; SelectedLang reflects
// which variant was actually used. Use SelectedLang for Content-Language.
func (c *Composer) Compose(
	contactID, email string,
	vars tmpl.Vars,
	lang string,
	step collect.Step,
	now time.Time,
) (*Message, error) {
	if err := validateHeaderValue(email); err != nil {
		return nil, fmt.Errorf("mail: to address: %w", err)
	}
	// From comes from config and is set once at construction, but validate at
	// compose time so a misconfigured deployment fails per-message, not silently.
	if err := validateHeaderValue(c.fromAddr); err != nil {
		return nil, fmt.Errorf("mail: from address: %w", err)
	}
	if err := validateHeaderValue(c.fromName); err != nil {
		return nil, fmt.Errorf("mail: from name: %w", err)
	}

	page := tmpl.Page{
		Campaign:  c.campaign,
		Template:  c.template,
		Step:      c.step,
		ContactID: contactID,
	}

	var html bytes.Buffer
	result, err := c.renderer.RenderFull(&html, page, step, vars, lang, lang)
	if err != nil {
		return nil, fmt.Errorf("mail: render: %w", err)
	}

	body := makeAbsolute(html.Bytes(), c.baseURL)
	text := htmlToText(body)

	from := buildFrom(c.fromAddr, c.fromName)
	subject := subjectFromVars(vars, c.step)
	if err := validateHeaderValue(subject); err != nil {
		return nil, fmt.Errorf("mail: subject: %w", err)
	}

	var unsubHeader string
	if c.unsubURL != "" {
		unsubHeader = "<" + c.unsubURL + ">"
	}

	return &Message{
		From:            from,
		To:              email,
		Subject:         subject,
		MessageID:       messageID(c.campaign, contactID, c.step),
		Date:            now,
		RequestedLang:   lang,
		SelectedLang:    result.Lang,
		ListUnsubscribe: unsubHeader,
		HTMLBody:        body,
		TextBody:        text,
	}, nil
}

// buildFrom formats the RFC 5322 From header value. The display name is
// Q-encoded so non-ASCII characters round-trip correctly, and the email
// address is validated against header injection.
func buildFrom(addr, name string) string {
	if name == "" {
		return addr
	}
	return mime.QEncoding.Encode("utf-8", sanitizeDisplayName(name)) + " <" + addr + ">"
}

// sanitizeDisplayName escapes backslashes and double-quotes inside a display
// name before Q-encoding. Without this, a name like `Dupont "Le" Grand` would
// produce a malformed quoted-string if the encoder ever emitted it unquoted,
// and a name containing a backslash could escape the closing quote.
func sanitizeDisplayName(name string) string {
	name = strings.ReplaceAll(name, `\`, `\\`)
	name = strings.ReplaceAll(name, `"`, `\"`)
	return name
}

// validateHeaderValue refuses any value that contains CR or LF.
func validateHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("value contains CR or LF: header injection refused")
	}
	return nil
}

// messageID produces a deterministic, campaign-scoped identifier.
// HMAC-SHA256 keyed with a key derived from the campaign ID binds the value to
// that campaign without requiring an external secret.
func messageID(campaignID, contactID, stepID string) string {
	key := messageIDKey(campaignID)
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, campaignID) //nolint:errcheck // bytes.Buffer never fails
	io.WriteString(mac, "\x00")     //nolint:errcheck
	io.WriteString(mac, contactID)  //nolint:errcheck
	io.WriteString(mac, "\x00")     //nolint:errcheck
	io.WriteString(mac, stepID)     //nolint:errcheck
	return hex.EncodeToString(mac.Sum(nil)) + "@siren"
}

// messageIDKey derives a 32-byte HMAC key from the campaign ID without an
// external secret. It repeats the hex-encoded ID to fill 32 bytes, so short
// IDs do not produce a weak key.
func messageIDKey(campaignID string) []byte {
	src := []byte(hex.EncodeToString([]byte(campaignID)))
	key := make([]byte, 32)
	for i := range key {
		key[i] = src[i%len(src)]
	}
	return key
}

// subjectFromVars builds a subject line. Operators override this by adding a
// "Subject" key to the contact's vars.
func subjectFromVars(vars tmpl.Vars, step string) string {
	if s := strings.TrimSpace(vars.Lookup("Subject")); s != "" {
		return s
	}
	return step
}

var (
	// scriptRe removes <script>…</script> blocks, including their content.
	scriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	// styleRe removes <style>…</style> blocks, including their content.
	styleRe = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	// tagRe matches any remaining HTML tag.
	tagRe = regexp.MustCompile(`<[^>]+>`)
	// wsRe collapses any run of whitespace.
	wsRe = regexp.MustCompile(`\s+`)
	// entityRe matches common HTML entities.
	entityRe = regexp.MustCompile(`&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);`)
)

// htmlToText strips <script> and <style> blocks with their content first, then
// all remaining tags, then decodes common HTML entities and collapses
// whitespace. Block-level closing tags produce paragraph breaks.
// The result is a plain-text representation suitable as the alternative MIME part.
func htmlToText(html []byte) []byte {
	s := string(html)

	// Remove executable/presentational blocks before anything else; leaving
	// them until after tag stripping would dump fingerprint JavaScript and CSS
	// rules verbatim into the text part.
	s = scriptRe.ReplaceAllString(s, "")
	s = styleRe.ReplaceAllString(s, "")

	// Mark paragraph breaks before stripping tags.
	s = strings.NewReplacer(
		"<br>", "\n", "<br/>", "\n", "<br />", "\n",
		"</p>", "\n\n", "</div>", "\n",
		"</h1>", "\n\n", "</h2>", "\n\n", "</h3>", "\n\n",
		"</li>", "\n",
	).Replace(s)
	s = tagRe.ReplaceAllString(s, "")
	s = entityRe.ReplaceAllStringFunc(s, decodeEntity)

	// Split on explicit paragraph breaks, normalise each paragraph's internal
	// whitespace, then rejoin with a blank line between paragraphs.
	paragraphs := strings.Split(s, "\n\n")
	var out []string
	for _, para := range paragraphs {
		lines := strings.Split(para, "\n")
		var kept []string
		for _, line := range lines {
			line = wsRe.ReplaceAllString(strings.TrimSpace(line), " ")
			if line != "" {
				kept = append(kept, line)
			}
		}
		if len(kept) > 0 {
			out = append(out, strings.Join(kept, "\n"))
		}
	}
	result := strings.Join(out, "\n\n")
	return []byte(strings.TrimFunc(result, unicode.IsSpace))
}

func decodeEntity(s string) string {
	switch s {
	case "&amp;":
		return "&"
	case "&lt;":
		return "<"
	case "&gt;":
		return ">"
	case "&quot;":
		return `"`
	case "&apos;":
		return "'"
	}
	return s
}

// makeAbsolute rewrites root-relative (single-slash) href and action attributes
// to absolute URLs using baseURL. Already-absolute URLs (containing "://") and
// protocol-relative URLs ("//") are left unchanged.
//
// The rewrite is a targeted string substitution on known attribute patterns
// rather than a full HTML parse; it is correct for the controlled output of
// the template engine but must not be applied to arbitrary HTML.
func makeAbsolute(html []byte, baseURL string) []byte {
	s := string(html)
	// Replace only root-relative targets. We key on the quote+slash+non-slash
	// sequence to avoid matching protocol-relative URLs (href="//cdn…").
	// Because our baseURL has no trailing slash, the result is "base/path".
	s = rewriteAttr(s, `action="`, baseURL)
	s = rewriteAttr(s, `href="`, baseURL)
	return []byte(s)
}

// rewriteAttr rewrites occurrences of prefix + "/" (where the char after "/" is
// not another "/") to prefix + baseURL + "/". Absolute and protocol-relative
// values are left unchanged.
func rewriteAttr(s, prefix, baseURL string) string {
	const slashSlash = "//"
	var b strings.Builder
	for {
		idx := strings.Index(s, prefix+"/")
		if idx < 0 {
			b.WriteString(s)
			break
		}
		afterPrefix := s[idx+len(prefix):]
		if strings.HasPrefix(afterPrefix, slashSlash) {
			// Protocol-relative or already-rewritten: skip past the prefix.
			b.WriteString(s[:idx+len(prefix)])
			s = afterPrefix
			continue
		}
		b.WriteString(s[:idx])
		b.WriteString(prefix)
		b.WriteString(baseURL)
		b.WriteString("/")
		s = afterPrefix[1:] // consume the leading "/"
	}
	return b.String()
}
