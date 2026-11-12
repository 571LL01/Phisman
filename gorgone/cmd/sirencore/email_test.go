package main

import (
	"strings"
	"testing"
)

func TestBuildMessageHTMLIsMultipartWithDeliverabilityHeaders(t *testing.T) {
	msg, err := buildMessage("Équipe IT <it@acme-corp.com>", "it@acme-corp.com",
		"cible@example.com", "Vérification requise",
		"text/html; charset=UTF-8", `<p>Bonjour <a href="https://x/c/1">ici</a></p>`)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	s := string(msg)
	for _, want := range []string{
		"MIME-Version: 1.0",
		"Date: ",
		"Message-ID: <",
		"@acme-corp.com>",
		"multipart/alternative; boundary=",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Type: text/html; charset=utf-8",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("message missing %q\n---\n%s", want, s)
		}
	}
	// Subject carries a non-ASCII char, so it must be Q-encoded, not raw.
	if strings.Contains(s, "Subject: Vérification requise") {
		t.Fatalf("subject not encoded")
	}
	if !strings.Contains(s, "Subject: =?utf-8?q?") {
		t.Fatalf("subject should be Q-encoded")
	}
	// The plain-text alternative must carry the link text, not the tags.
	if !strings.Contains(s, "Bonjour") {
		t.Fatalf("plain-text alternative missing content")
	}
}

func TestBuildMessagePlainTextSinglePart(t *testing.T) {
	msg, err := buildMessage("it@acme.com", "it@acme.com", "to@example.com", "Hello",
		"text/plain; charset=UTF-8", "Bonjour,\r\nlien : https://x\r\n")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	s := string(msg)
	if strings.Contains(s, "multipart/") {
		t.Fatalf("plain body must not be multipart")
	}
	for _, want := range []string{"MIME-Version: 1.0", "Date: ", "Message-ID: <", "Content-Type: text/plain"} {
		if !strings.Contains(s, want) {
			t.Fatalf("message missing %q", want)
		}
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	_, err := buildMessage("it@acme.com", "it@acme.com", "to@example.com\r\nBcc: evil@x.com",
		"Subject", "text/plain; charset=UTF-8", "body")
	if err == nil {
		t.Fatalf("expected header-injection error")
	}
}

func TestHTMLToPlainStripsTags(t *testing.T) {
	got := htmlToPlain(`<p>Bonjour <strong>Alice</strong></p><p>Clique <a href="https://x">ici</a></p>`)
	if strings.Contains(got, "<") {
		t.Fatalf("tags not stripped: %q", got)
	}
	if !strings.Contains(got, "Bonjour Alice") || !strings.Contains(got, "ici") {
		t.Fatalf("content lost: %q", got)
	}
}

func TestFromDomain(t *testing.T) {
	cases := map[string]string{
		"it@acme-corp.com":        "acme-corp.com",
		"Équipe IT <it@acme.com>": "acme.com",
		"noatsign":                "localhost",
		"":                        "localhost",
	}
	for in, want := range cases {
		if got := fromDomain(in); got != want {
			t.Fatalf("fromDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
