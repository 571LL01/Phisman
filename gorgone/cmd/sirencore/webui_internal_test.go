package main

import (
	"strings"
	"testing"
)

func TestBuildPixelURL(t *testing.T) {
	got := buildPixel("https://siren.example.com/", "/__siren", "camp1", "tmp-001", "a", "rid123")
	want := "https://siren.example.com/__siren/o/camp1/tmp-001/a?rid=rid123"
	if got != want {
		t.Fatalf("buildPixel = %q, want %q", got, want)
	}
}

func TestComposeEmailBody(t *testing.T) {
	const link = "https://x/c/1/t/a?rid=r"
	const pixel = "https://x/__siren/o/1/t/a?rid=r"

	t.Run("empty body is plain text without pixel", func(t *testing.T) {
		ct, body := composeEmailBody(link, pixel, "")
		if ct != "text/plain; charset=UTF-8" {
			t.Fatalf("content-type = %q", ct)
		}
		if strings.Contains(body, "<img") {
			t.Fatalf("plain-text default must not carry a pixel: %q", body)
		}
		if !strings.Contains(body, link) {
			t.Fatalf("default body missing link")
		}
	})

	t.Run("plain custom body stays plain and untracked", func(t *testing.T) {
		ct, body := composeEmailBody(link, pixel, "Bonjour, cliquez {{.Link}}")
		if ct != "text/plain; charset=UTF-8" {
			t.Fatalf("content-type = %q, want plain", ct)
		}
		if !strings.Contains(body, link) || strings.Contains(body, "<img") {
			t.Fatalf("plain body = %q", body)
		}
	})

	t.Run("html body gets the pixel appended", func(t *testing.T) {
		ct, body := composeEmailBody(link, pixel, "<p>Bonjour <a href=\"{{.Link}}\">ici</a></p>")
		if ct != "text/html; charset=UTF-8" {
			t.Fatalf("content-type = %q, want html", ct)
		}
		if !strings.Contains(body, pixel) || !strings.Contains(body, "<img") {
			t.Fatalf("html body missing pixel: %q", body)
		}
	})

	t.Run("explicit pixel token is replaced in place and forces html", func(t *testing.T) {
		ct, body := composeEmailBody(link, pixel, "texte {{.Pixel}} fin")
		if ct != "text/html; charset=UTF-8" {
			t.Fatalf("content-type = %q, want html", ct)
		}
		if strings.Contains(body, "{{.Pixel}}") {
			t.Fatalf("pixel token not substituted: %q", body)
		}
		if strings.Count(body, "<img") != 1 || !strings.Contains(body, pixel) {
			t.Fatalf("pixel placement wrong: %q", body)
		}
	})

	t.Run("no pixel url means no image even for html", func(t *testing.T) {
		_, body := composeEmailBody(link, "", "<p>{{.Link}}</p>")
		if strings.Contains(body, "<img") {
			t.Fatalf("expected no pixel when url empty: %q", body)
		}
	})
}
