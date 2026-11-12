package mgmt

import (
	"strings"
	"testing"
)

func TestMailspoofLibraryLoads(t *testing.T) {
	got, err := loadMailspoofTemplates(mailspoofFS)
	if err != nil {
		t.Fatalf("loadMailspoofTemplates: %v", err)
	}
	if len(got) < 60 {
		t.Fatalf("loaded %d MailSpoof templates, want >= 60", len(got))
	}

	seen := make(map[string]bool, len(got))
	withFrom := 0
	for _, et := range got {
		if seen[et.ID] {
			t.Fatalf("duplicate template ID %q", et.ID)
		}
		seen[et.ID] = true
		if et.FromEmail != "" && et.FromName != "" {
			withFrom++
		}

		if !strings.HasPrefix(et.ID, "ms-") {
			t.Errorf("%q: ID should be namespaced with ms-", et.ID)
		}
		for name, val := range map[string]string{"Name": et.Name, "Subject": et.Subject, "Body": et.Body} {
			if strings.TrimSpace(val) == "" {
				t.Errorf("%q: %s is empty", et.ID, name)
			}
		}
	}
	if withFrom < 50 {
		t.Errorf("only %d templates carry a spoofed sender; expected most to", withFrom)
	}
}

// Every pretext that ships an anchor must point it at our tracked link, never
// at the upstream placeholder domains.
func TestMailspoofRewritesAnchorsToTrackedLink(t *testing.T) {
	got, err := loadMailspoofTemplates(mailspoofFS)
	if err != nil {
		t.Fatalf("loadMailspoofTemplates: %v", err)
	}
	for _, et := range got {
		if !strings.Contains(et.Body, "<a ") {
			continue
		}
		if !strings.Contains(et.Body, "{{.Link}}") {
			t.Errorf("%q has an anchor but no {{.Link}} token", et.ID)
		}
		for _, bad := range []string{`href="https://secure-payments.example`, `href="https://m365-license.example`, "example.net/approve", "example.com/renew"} {
			if strings.Contains(et.Body, bad) {
				t.Errorf("%q leaks placeholder CTA %q", et.ID, bad)
			}
		}
	}
}

func TestMailspoofAppendedToBuiltins(t *testing.T) {
	var french, mailspoof int
	for _, et := range BuiltinEmailTemplates {
		if strings.HasPrefix(et.ID, "ms-") {
			mailspoof++
		} else {
			french++
		}
	}
	if french < 4 {
		t.Errorf("expected the original hand-written templates to remain, found %d", french)
	}
	if mailspoof < 60 {
		t.Errorf("expected the MailSpoof library in BuiltinEmailTemplates, found %d", mailspoof)
	}
}

func TestParseMailspoofHeadersAndBody(t *testing.T) {
	raw := "Name: Demo Lure\nCategory: Test\nFrom Email: it@spoofme.com\nFrom Name: IT Desk\n" +
		"Subject: Hello there\nBody:\n<html><body>" +
		`<a href="https://evil.example/go">click</a>` +
		"</body></html>\nDescription: a demo.\n"
	et := parseMailspoof(raw)
	if et.Name != "Demo Lure" {
		t.Errorf("Name = %q", et.Name)
	}
	if et.Subject != "Hello there" {
		t.Errorf("Subject = %q", et.Subject)
	}
	if et.FromEmail != "it@spoofme.com" {
		t.Errorf("FromEmail = %q", et.FromEmail)
	}
	if et.FromName != "IT Desk" {
		t.Errorf("FromName = %q", et.FromName)
	}
	if strings.Contains(et.Body, "evil.example") {
		t.Errorf("anchor not rewritten: %q", et.Body)
	}
	if !strings.Contains(et.Body, `href="{{.Link}}"`) {
		t.Errorf("missing tracked link: %q", et.Body)
	}
	if strings.Contains(et.Body, "Description:") {
		t.Errorf("Description leaked into body: %q", et.Body)
	}
}
