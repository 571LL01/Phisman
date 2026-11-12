package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"regexp"
	"strings"
	"time"
)

// buildMessage assembles RFC 5322 / MIME bytes for one email with the headers
// mailbox providers expect, so a message is less likely to be scored as spam on
// shape alone:
//
//   - MIME-Version, a real Date, and a unique Message-ID with a domain;
//   - a Q-encoded Subject (UTF-8 safe);
//   - for an HTML body, a multipart/alternative with the plain-text part FIRST,
//     so HTML clients render the HTML and text-only clients still get content.
//
// Header values are rejected if they carry CR or LF: that is the header
// injection guard, since To/From/Subject come from operator input.
func buildMessage(fromHeader, fromAddr, to, subject, contentType, body string) ([]byte, error) {
	for _, v := range []string{fromHeader, to, subject} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("mail header contains CR or LF")
		}
	}

	var typeHeader string
	var mimeBody bytes.Buffer
	if strings.HasPrefix(contentType, "text/html") {
		mw := multipart.NewWriter(&mimeBody)
		if err := writeQPPart(mw, "text/plain; charset=utf-8", htmlToPlain(body)); err != nil {
			return nil, err
		}
		if err := writeQPPart(mw, "text/html; charset=utf-8", body); err != nil {
			return nil, err
		}
		if err := mw.Close(); err != nil {
			return nil, err
		}
		typeHeader = `multipart/alternative; boundary="` + mw.Boundary() + `"`
	} else {
		qw := quotedprintable.NewWriter(&mimeBody)
		if _, err := qw.Write([]byte(body)); err != nil {
			return nil, err
		}
		if err := qw.Close(); err != nil {
			return nil, err
		}
		typeHeader = "text/plain; charset=utf-8"
	}

	var out bytes.Buffer
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	out.WriteString("Message-ID: <" + newMessageID(fromAddr) + ">\r\n")
	out.WriteString("From: " + fromHeader + "\r\n")
	out.WriteString("To: " + to + "\r\n")
	out.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	if strings.HasPrefix(typeHeader, "text/plain") {
		out.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	}
	out.WriteString("Content-Type: " + typeHeader + "\r\n")
	out.WriteString("\r\n")
	out.Write(mimeBody.Bytes())
	return out.Bytes(), nil
}

func writeQPPart(mw *multipart.Writer, contentType, content string) error {
	w, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return err
	}
	qw := quotedprintable.NewWriter(w)
	if _, err := qw.Write([]byte(content)); err != nil {
		return err
	}
	return qw.Close()
}

// newMessageID builds a unique Message-ID value (without the angle brackets),
// domain taken from the sender address so it aligns with the From domain.
func newMessageID(fromAddr string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:]) + "@" + fromDomain(fromAddr)
}

func fromDomain(addr string) string {
	addr = strings.TrimRight(strings.TrimSpace(addr), ">")
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i+1 < len(addr) {
		if d := strings.TrimSpace(addr[i+1:]); d != "" {
			return d
		}
	}
	return "localhost"
}

var (
	reScriptBlock = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyleBlock  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reAnyTag      = regexp.MustCompile(`<[^>]+>`)
	reInlineWS    = regexp.MustCompile(`[ \t]+`)
)

// htmlToPlain derives a readable plain-text alternative from an HTML body. It is
// best-effort: block tags become line breaks, remaining tags are stripped, and
// a few common entities are decoded.
func htmlToPlain(h string) string {
	h = reScriptBlock.ReplaceAllString(h, "")
	h = reStyleBlock.ReplaceAllString(h, "")
	h = strings.NewReplacer(
		"<br>", "\n", "<br/>", "\n", "<br />", "\n",
		"</p>", "\n\n", "</div>", "\n", "</h1>", "\n\n", "</h2>", "\n\n", "</li>", "\n",
	).Replace(h)
	h = reAnyTag.ReplaceAllString(h, "")
	h = strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&nbsp;", " ",
	).Replace(h)

	lines := strings.Split(h, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, strings.TrimSpace(reInlineWS.ReplaceAllString(l, " ")))
	}
	// Collapse 3+ blank lines to at most one blank line.
	joined := strings.Join(out, "\n")
	for strings.Contains(joined, "\n\n\n") {
		joined = strings.ReplaceAll(joined, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(joined)
}
