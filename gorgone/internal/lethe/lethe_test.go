package lethe

import (
	"io/fs"
	"strings"
	"testing"
)

func TestTmp005SingleStepLoginShipsThreeLanguages(t *testing.T) {
	def, ok := Lookup("tmp-005")
	if !ok {
		t.Fatal("tmp-005 is not registered")
	}
	variants, ok := def.Steps["a"]
	if !ok {
		t.Fatal("tmp-005 step \"a\" is missing")
	}
	if len(variants) != 3 {
		t.Fatalf("step a has %d variants, want 3", len(variants))
	}
	seen := make(map[string]bool, 3)
	for _, v := range variants {
		seen[v.Lang] = true
		for name, value := range map[string]string{
			"title": v.Title, "heading": v.Heading, "intro": v.Intro, "submit": v.Submit, "note": v.Note,
		} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("lang %q: %s is empty", v.Lang, name)
			}
		}
	}
	for _, lang := range []string{"fr", "en", "de"} {
		if !seen[lang] {
			t.Fatalf("missing %q variant", lang)
		}
	}
	// Assets must be embedded and resolvable.
	if _, err := fs.Stat(def.Assets, "style.css"); err != nil {
		t.Fatalf("tmp-005 style.css: %v", err)
	}
	if _, err := fs.Stat(def.Assets, "mark.svg"); err != nil {
		t.Fatalf("tmp-005 mark.svg: %v", err)
	}
}

func TestShippedTemplatesShipThreeLanguagesForBothSteps(t *testing.T) {
	for _, templateID := range []string{"tmp-001", "tmp-002", "tmp-003", "tmp-004"} {
		t.Run(templateID, func(t *testing.T) {
			def, ok := Lookup(templateID)
			if !ok {
				t.Fatalf("%s is not registered", templateID)
			}

			for _, stepID := range []string{"a", "b"} {
				variants, ok := def.Steps[stepID]
				if !ok {
					t.Fatalf("step %q is missing", stepID)
				}
				if len(variants) != 3 {
					t.Fatalf("step %q has %d variants, want 3", stepID, len(variants))
				}
				seen := make(map[string]bool, len(variants))
				for _, v := range variants {
					seen[v.Lang] = true
					for name, value := range map[string]string{
						"title": v.Title, "heading": v.Heading,
						"intro": v.Intro, "submit": v.Submit, "note": v.Note,
					} {
						if strings.TrimSpace(value) == "" {
							t.Fatalf("step %q lang %q: %s is empty", stepID, v.Lang, name)
						}
					}
				}
				for _, lang := range []string{"fr", "en", "de"} {
					if !seen[lang] {
						t.Fatalf("step %q has no %q variant", stepID, lang)
					}
				}
			}
		})
	}
}

func TestShippedTemplatesAssetsAreSelfContained(t *testing.T) {
	for _, templateID := range []string{"tmp-001", "tmp-002", "tmp-003", "tmp-004"} {
		t.Run(templateID, func(t *testing.T) {
			def, ok := Lookup(templateID)
			if !ok {
				t.Fatalf("%s is not registered", templateID)
			}
			if def.Assets == nil {
				t.Fatalf("%s has no assets", templateID)
			}

			style, err := fs.ReadFile(def.Assets, "style.css")
			if err != nil {
				t.Fatalf("style.css: %v", err)
			}
			if !strings.Contains(string(style), `url("mark.svg")`) {
				t.Fatalf("style.css does not reference the template mark:\n%s", style)
			}
			mark, err := fs.ReadFile(def.Assets, "mark.svg")
			if err != nil {
				t.Fatalf("mark.svg: %v", err)
			}
			if !strings.Contains(string(mark), "<svg") {
				t.Fatalf("mark.svg is not an SVG document:\n%s", mark)
			}
		})
	}
}

func TestTMP002ConfirmationRecallsEmail(t *testing.T) {
	def, ok := Lookup("tmp-002")
	if !ok {
		t.Fatal("tmp-002 is not registered")
	}
	want := map[string]string{
		"fr": "Adresse e-mail",
		"en": "Email address",
		"de": "E-Mail-Adresse",
	}
	for _, v := range def.Steps["b"] {
		if v.SummaryField != "email" {
			t.Fatalf("step b lang %q recalls %q, want email", v.Lang, v.SummaryField)
		}
		if v.SummaryLabel != want[v.Lang] {
			t.Fatalf("step b lang %q label = %q, want %q", v.Lang, v.SummaryLabel, want[v.Lang])
		}
	}
	for _, v := range def.Steps["a"] {
		if v.SummaryField != "" {
			t.Fatalf("step a lang %q has a summary field %q", v.Lang, v.SummaryField)
		}
	}
}

func TestLookupRejectsUnknownTemplate(t *testing.T) {
	if _, ok := Lookup("tmp-999"); ok {
		t.Fatal("unknown template id was accepted")
	}
}

// Lookup must hand out fresh slices: a handler may mutate its own Definition
// without changing what the next campaign receives.
func TestLookupReturnsFreshVariants(t *testing.T) {
	for _, templateID := range []string{"tmp-001", "tmp-002", "tmp-003", "tmp-004"} {
		first, _ := Lookup(templateID)
		first.Steps["a"][0].Heading = "mutated"

		second, _ := Lookup(templateID)
		if second.Steps["a"][0].Heading == "mutated" {
			t.Fatalf("%s variants are shared between lookups", templateID)
		}
	}
}
