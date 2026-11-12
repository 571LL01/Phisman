package mail

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	"github.com/siren-core/gorgone/internal/lethe"
	"github.com/siren-core/gorgone/internal/tmpl"
)

// testRenderer builds a renderer backed by the real TMP-001 definition.
func testRenderer(t *testing.T) *tmpl.Renderer {
	t.Helper()
	def, ok := lethe.Lookup("tmp-001")
	if !ok {
		t.Fatal("tmp-001 not registered")
	}
	r, err := tmpl.New(map[tmpl.Coord]tmpl.Template{
		{Campaign: "acme", Template: "tmp-001"}: {
			Steps:  def.Steps,
			Assets: def.Assets,
		},
	})
	if err != nil {
		t.Fatalf("tmpl.New: %v", err)
	}
	return r
}

func testComposer(t *testing.T) *Composer {
	t.Helper()
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		FromName:    "Siren",
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}
	return c
}

func testStep() collect.Step {
	return collect.Step{
		Target: "/c/acme/tmp-001/b",
		Fields: []collect.Field{
			{Name: "identifier", Kind: collect.KindText},
		},
	}
}

func testVars(lang string) tmpl.Vars {
	return tmpl.Vars{
		"FirstName": "Alice",
		"email":     "alice@example.com",
		"lang":      lang,
	}
}

func compose(t *testing.T, c *Composer, contactID, lang string) *Message {
	t.Helper()
	msg, err := c.Compose(contactID, contactID+"@example.com", testVars(lang), lang, testStep(),
		time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	return msg
}

// ---------------------------------------------------------------- fix 1: script/style stripped

func TestHTMLToTextStripsScriptAndStyle(t *testing.T) {
	html := []byte(`<html><head>
<style>.x{color:red}</style>
<script>document.getElementById("__siren_fp").value=function(){}</script>
</head><body><p>Hello world</p></body></html>`)

	text := htmlToText(html)
	s := string(text)

	if strings.Contains(s, "getElementById") {
		t.Errorf("text part contains JS: %q", s)
	}
	if strings.Contains(s, "function") {
		t.Errorf("text part contains JS function keyword: %q", s)
	}
	if strings.Contains(s, "color:red") {
		t.Errorf("text part contains CSS: %q", s)
	}
	if !strings.Contains(s, "Hello world") {
		t.Errorf("text part lost the visible content: %q", s)
	}
}

func TestComposePlainTextOmitsFingerprint(t *testing.T) {
	c := testComposer(t)
	msg := compose(t, c, "contact-1", "fr")

	text := string(msg.TextBody)
	if strings.Contains(text, "getElementById") {
		t.Errorf("plain-text part contains fingerprint JS:\n%s", text)
	}
	if strings.Contains(text, "function") {
		t.Errorf("plain-text part contains JS function:\n%s", text)
	}
}

// ---------------------------------------------------------------- fix 2: header injection

func TestComposeRejectsCRLFInToAddress(t *testing.T) {
	c := testComposer(t)
	_, err := c.Compose("c1", "a@b.c\r\nBcc: x@y.z", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("CRLF injection in To was accepted")
	}
	if !strings.Contains(err.Error(), "injection") {
		t.Errorf("error = %v, want injection mention", err)
	}
}

func TestComposeRejectsCRLFInFromConfig(t *testing.T) {
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com\r\nBcc: attacker@evil.com",
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}
	// Validation happens at Compose time (the addr came from operator config,
	// not user input, but it must still be caught).
	_, err = c.Compose("c1", "alice@example.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("CRLF in FromAddress was accepted")
	}
	if !strings.Contains(err.Error(), "from") {
		t.Errorf("error = %v, want 'from' mention", err)
	}
}

func TestSanitizeDisplayNameEscapesQuotesAndBackslash(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`Dupont "Le" Grand`, `Dupont \"Le\" Grand`},
		{`C:\path\to\`, `C:\\path\\to\\`},
		{`Normal Name`, `Normal Name`},
		{`Mix "and" \\both\\`, `Mix \"and\" \\\\both\\\\`},
	}
	for _, tc := range cases {
		got := sanitizeDisplayName(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeDisplayName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestComposeDisplayNameQuotesInFrom(t *testing.T) {
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		FromName:    `Dupont "Le" Grand`,
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}
	msg, err := c.Compose("c1", "alice@example.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	// The raw From must contain the escaped form.
	if strings.Contains(msg.From, `"Le"`) && !strings.Contains(msg.From, `\"Le\"`) {
		t.Errorf("unescaped quote in From: %q", msg.From)
	}
	// The siren address must still be present.
	if !strings.Contains(msg.From, "siren@example.com") {
		t.Errorf("address lost: %q", msg.From)
	}
}

// ---------------------------------------------------------------- fix 3: RequestedLang vs SelectedLang

func TestComposeRequestedVsSelectedLang(t *testing.T) {
	c := testComposer(t)

	// Known language: requested == selected.
	known := compose(t, c, "contact-1", "fr")
	if known.RequestedLang != "fr" {
		t.Errorf("RequestedLang = %q, want fr", known.RequestedLang)
	}
	if known.SelectedLang != "fr" {
		t.Errorf("SelectedLang = %q, want fr", known.SelectedLang)
	}

	// Unknown language: requested is "xx" but selected falls back to the first
	// shipped variant (which is not "xx").
	unknown := compose(t, c, "contact-2", "xx")
	if unknown.RequestedLang != "xx" {
		t.Errorf("RequestedLang = %q, want xx", unknown.RequestedLang)
	}
	if unknown.SelectedLang == "xx" {
		t.Errorf("SelectedLang = %q: should not be the unknown tag", unknown.SelectedLang)
	}

	// Content-Language in the wire bytes must reflect SelectedLang, not RequestedLang.
	raw, err := unknown.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	cl := parsed.Header.Get("Content-Language")
	if cl == "xx" {
		t.Errorf("Content-Language = %q: header lies about the actual language", cl)
	}
}

// ---------------------------------------------------------------- fix 4: makeAbsolute

func TestMakeAbsoluteDoesNotDoubleSlash(t *testing.T) {
	// A base URL with a trailing slash must not produce "//path".
	// NewComposer strips it, so this tests makeAbsolute directly.
	base := "https://siren.example.com" // no trailing slash
	html := []byte(`<form action="/c/acme/t/a?rid=1">`)
	out := string(makeAbsolute(html, base))
	if strings.Contains(out, `action="//`) {
		t.Errorf("double slash in action: %s", out)
	}
	if !strings.Contains(out, `action="https://siren.example.com/c/acme/t/a`) {
		t.Errorf("action not rewritten: %s", out)
	}
}

func TestMakeAbsoluteDoesNotTouchAlreadyAbsolute(t *testing.T) {
	base := "https://siren.example.com"
	// An already-absolute href must pass through unchanged.
	html := []byte(`<a href="https://external.com/path">link</a>`)
	out := string(makeAbsolute(html, base))
	if strings.Contains(out, base+"/https:") {
		t.Errorf("already-absolute href was double-rewritten: %s", out)
	}
	if !strings.Contains(out, `href="https://external.com/path"`) {
		t.Errorf("absolute href was changed: %s", out)
	}
}

func TestMakeAbsoluteDoesNotTouchProtocolRelative(t *testing.T) {
	base := "https://siren.example.com"
	html := []byte(`<a href="//cdn.example.com/style.css">x</a>`)
	out := string(makeAbsolute(html, base))
	// href="// must not be treated as a root-relative target.
	if strings.Contains(out, base+`/`) && strings.Contains(out, "//cdn") {
		t.Errorf("protocol-relative URL rewritten: %s", out)
	}
}

func TestNewComposerStripsTrailingSlashFromBaseURL(t *testing.T) {
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		BaseURL:     "https://siren.example.com/",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}
	// If the trailing slash were kept, the action would be "…//c/…".
	msg, err := c.Compose("c1", "a@example.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(msg.HTMLBody), `action="https://siren.example.com//`) {
		t.Errorf("double slash in action after trailing-slash base:\n%s", msg.HTMLBody)
	}
}

// ---------------------------------------------------------------- existing gate tests

func TestComposeHTMLBodyContainsRidAndLang(t *testing.T) {
	c := testComposer(t)
	msg := compose(t, c, "contact-1", "fr")

	body := string(msg.HTMLBody)
	if !strings.Contains(body, "rid=contact-1") {
		t.Errorf("HTML body is missing rid:\n%s", body)
	}
	if !strings.Contains(body, "l=fr") {
		t.Errorf("HTML body is missing l=fr:\n%s", body)
	}
	if !strings.Contains(body, "https://siren.example.com") {
		t.Errorf("HTML body action is not absolute:\n%s", body)
	}
}

func TestComposePlainTextPartIsPresent(t *testing.T) {
	c := testComposer(t)
	msg := compose(t, c, "contact-1", "en")

	if len(msg.TextBody) == 0 {
		t.Fatal("text body is empty")
	}
	if bytes.Contains(msg.TextBody, []byte("<html")) || bytes.Contains(msg.TextBody, []byte("<form")) {
		t.Errorf("text body contains HTML tags:\n%s", msg.TextBody)
	}
}

func TestComposeMessageIDIsStableAndContactScoped(t *testing.T) {
	c := testComposer(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	comp := func(contactID string) *Message {
		t.Helper()
		msg, err := c.Compose(contactID, contactID+"@example.com", testVars("de"), "de", testStep(), now)
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		return msg
	}

	a1 := comp("alice")
	a2 := comp("alice")
	if a1.MessageID != a2.MessageID {
		t.Errorf("MessageID not stable: %q vs %q", a1.MessageID, a2.MessageID)
	}
	b := comp("bob")
	if a1.MessageID == b.MessageID {
		t.Errorf("MessageID collision between alice and bob: %q", a1.MessageID)
	}
	if strings.ContainsAny(a1.MessageID, " \t\r\n") {
		t.Errorf("MessageID contains whitespace: %q", a1.MessageID)
	}
}

func TestComposeBytesIsValidMIME(t *testing.T) {
	c := testComposer(t)
	msg := compose(t, c, "contact-1", "fr")

	raw, err := msg.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadMessage: %v\nraw:\n%s", err, raw)
	}

	for _, hdr := range []string{"From", "To", "Subject", "Message-Id", "Date", "Mime-Version", "Content-Language"} {
		if v := parsed.Header.Get(hdr); v == "" {
			t.Errorf("header %q is missing", hdr)
		}
	}

	ct := parsed.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("parse Content-Type %q: %v", ct, err)
	}
	if mediaType != "multipart/alternative" {
		t.Errorf("Content-Type = %q, want multipart/alternative", mediaType)
	}

	mr := multipart.NewReader(parsed.Body, params["boundary"])
	var hadText, hadHTML bool
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		ct := part.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/plain") {
			hadText = true
		}
		if strings.HasPrefix(ct, "text/html") {
			hadHTML = true
		}
	}
	if !hadText {
		t.Error("multipart/alternative is missing text/plain part")
	}
	if !hadHTML {
		t.Error("multipart/alternative is missing text/html part")
	}
}

func TestComposeListUnsubscribeHeader(t *testing.T) {
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
		UnsubURL:    "https://siren.example.com/unsub?c=acme",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}

	msg, err := c.Compose("contact-1", "alice@example.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	raw, err := msg.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if unsubHeader := parsed.Header.Get("List-Unsubscribe"); !strings.Contains(unsubHeader, "unsub") {
		t.Errorf("List-Unsubscribe = %q, want the unsub URL", unsubHeader)
	}
}

func TestComposeFromWithDisplayName(t *testing.T) {
	c, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		FromName:    "Siren Platform",
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "a",
	})
	if err != nil {
		t.Fatalf("NewComposer: %v", err)
	}
	msg, err := c.Compose("contact-1", "alice@example.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !strings.Contains(msg.From, "siren@example.com") {
		t.Errorf("From = %q, want the email address", msg.From)
	}
	if !strings.Contains(msg.From, "Siren") {
		t.Errorf("From = %q, want the display name", msg.From)
	}
}

func TestHTMLToTextStripsTagsAndEntities(t *testing.T) {
	cases := []struct {
		html string
		want string
	}{
		{
			html: `<p>Hello &amp; world</p><p>Second paragraph</p>`,
			want: "Hello & world\n\nSecond paragraph",
		},
		{
			html: `<h1>Title</h1><p>Body &lt;text&gt;</p>`,
			want: "Title\n\nBody <text>",
		},
		{
			html: `  <div>  spaces   </div>  `,
			want: "spaces",
		},
	}
	for _, tc := range cases {
		got := string(htmlToText([]byte(tc.html)))
		if got != tc.want {
			t.Errorf("htmlToText(%q) = %q, want %q", tc.html, got, tc.want)
		}
	}
}

func TestMessageIDFormat(t *testing.T) {
	id := messageID("campaign-1", "contact-1", "step-a")
	if !strings.HasSuffix(id, "@siren") {
		t.Errorf("messageID = %q, want @siren suffix", id)
	}
	parts := strings.SplitN(id, "@", 2)
	if len(parts[0]) != 64 {
		t.Errorf("hex prefix length = %d, want 64", len(parts[0]))
	}
}

func TestNewComposerValidates(t *testing.T) {
	r := testRenderer(t)
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{Renderer: nil, FromAddress: "a@b.com", BaseURL: "https://x", Campaign: "c", Template: "t", Step: "s"}, "renderer"},
		{Config{Renderer: r, FromAddress: "", BaseURL: "https://x", Campaign: "c", Template: "t", Step: "s"}, "from address"},
		{Config{Renderer: r, FromAddress: "a@b.com", BaseURL: "", Campaign: "c", Template: "t", Step: "s"}, "base URL"},
		{Config{Renderer: r, FromAddress: "a@b.com", BaseURL: "https://x", Campaign: "", Template: "t", Step: "s"}, "campaign"},
	}
	for _, tc := range cases {
		_, err := NewComposer(tc.cfg)
		if err == nil {
			t.Errorf("accepted config with missing %s", tc.want)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("error = %v, want substring %q", err, tc.want)
		}
	}
}

func TestMessageBytesContainNoNullBytes(t *testing.T) {
	c := testComposer(t)
	msg, err := c.Compose("c1", "a@b.com", testVars("fr"), "fr", testStep(),
		time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte{0}) {
		t.Error("message bytes contain NUL character")
	}
	if _, err := json.Marshal(string(raw)); err != nil {
		t.Errorf("message bytes are not JSON-safe: %v", err)
	}
}
