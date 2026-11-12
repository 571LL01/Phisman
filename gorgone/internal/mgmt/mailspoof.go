package mgmt

import (
	"embed"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// MailSpoof pretext library.
//
// The *.txt files under mailspoof/ are imported from the MailSpoof project
// (https://github.com/syed-sameer-ul-hassan/MailSpoof), Apache-2.0. See
// mailspoof/NOTICE. Each file is a pretext in the form:
//
//	Name: ...
//	Category: ...
//	Severity: ...
//	From Email: ...
//	From Name: ...
//	Subject: ...
//	Body:
//	<html>...</html>
//	Description: ...
//
// At init we parse every file into an EmailTemplate and append it to
// BuiltinEmailTemplates, so the whole library shows up in the send-form picker.
// The call-to-action link in each body is rewritten to the {{.Link}} token so
// the per-recipient tracked phishing link is substituted at send time.

//go:embed mailspoof/*.txt
var mailspoofFS embed.FS

// anchorHrefDouble / anchorHrefSingle rewrite the href of every <a> tag to the
// {{.Link}} token, covering both quoting styles. The pretexts point their CTA
// at placeholder domains; we replace those with our own tracked link.
var (
	anchorHrefDouble = regexp.MustCompile(`(?is)(<a\b[^>]*?\bhref=")[^"]*(")`)
	anchorHrefSingle = regexp.MustCompile(`(?is)(<a\b[^>]*?\bhref=')[^']*(')`)
)

func init() {
	tmpls, err := loadMailspoofTemplates(mailspoofFS)
	if err != nil {
		// A malformed embedded file is a build-time asset problem, not a
		// runtime condition; fail loudly so tests catch it.
		panic("mgmt: loading MailSpoof templates: " + err.Error())
	}
	BuiltinEmailTemplates = append(BuiltinEmailTemplates, tmpls...)
}

func loadMailspoofTemplates(fsys fs.FS) ([]EmailTemplate, error) {
	entries, err := fs.Glob(fsys, "mailspoof/*.txt")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries) // deterministic 01..62 order

	out := make([]EmailTemplate, 0, len(entries))
	for _, name := range entries {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		t := parseMailspoof(string(raw))
		base := name[strings.LastIndex(name, "/")+1:]
		t.ID = "ms-" + strings.TrimSuffix(base, ".txt")
		if strings.TrimSpace(t.Name) == "" {
			t.Name = t.ID
		}
		out = append(out, t)
	}
	return out, nil
}

// parseMailspoof turns one pretext file into an EmailTemplate. It reads the
// leading "Key: Value" headers up to the "Body:" marker, treats everything
// after it as the HTML body (minus a trailing "Description:" line), and
// rewrites anchor targets to the {{.Link}} token.
func parseMailspoof(raw string) EmailTemplate {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")

	var t EmailTemplate
	i := 0
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "Body:" {
			i++
			break
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "Name":
			t.Name = val
		case "Subject":
			t.Subject = val
		case "From Email":
			t.FromEmail = val
		case "From Name":
			t.FromName = val
		}
	}

	bodyLines := make([]string, 0, len(lines)-i)
	for ; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "Description:") {
			break
		}
		bodyLines = append(bodyLines, lines[i])
	}
	body := strings.TrimSpace(strings.Join(bodyLines, "\n"))
	body = anchorHrefDouble.ReplaceAllString(body, `${1}{{.Link}}${2}`)
	body = anchorHrefSingle.ReplaceAllString(body, `${1}{{.Link}}${2}`)
	t.Body = body
	return t
}
