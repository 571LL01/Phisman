package tmpl

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/siren-core/gorgone/internal/collect"
)

func testRenderer(t *testing.T) *Renderer {
	t.Helper()
	r, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: DefaultTemplate(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func renderString(t *testing.T, r *Renderer, step collect.Step, vars Vars, acceptLanguage, override string) string {
	t.Helper()
	var buf bytes.Buffer
	err := r.Render(&buf, Page{Campaign: "acme", Template: "t1", Step: "s1"}, step, vars, acceptLanguage, override)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

func TestRenderEscapesTextAndAttributes(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{
		{Name: "name", Kind: collect.KindText},
		{Name: "email", Kind: collect.KindText},
	}}
	vars := Vars{
		"name":  `<script>alert(1)</script>`,
		"email": `a"b@example.com`,
	}

	out := renderString(t, testRenderer(t), step, vars, "", "")

	if strings.Contains(out, `<script>alert(1)</script>`) {
		t.Fatalf("contact name reached the document as markup:\n%s", out)
	}
	if !strings.Contains(out, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Fatalf("contact name is not escaped in text:\n%s", out)
	}
	if !strings.Contains(out, `value="a&#34;b@example.com"`) {
		t.Fatalf("email is not escaped in the value attribute:\n%s", out)
	}
	if strings.Contains(out, `value="a"b@example.com"`) {
		t.Fatalf("email broke out of the value attribute:\n%s", out)
	}
}

func TestRenderSummaryIsEscapedAndOptional(t *testing.T) {
	r, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: {Variants: []Variant{{
			Lang:         "fr",
			Title:        "Confirmation",
			Heading:      "Confirmez",
			Submit:       "Confirmer",
			SummaryField: "email",
			SummaryLabel: "Adresse e-mail",
		}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out := renderString(t, r, collect.Step{}, Vars{"email": `<b>alice@example.com</b>`}, "", "")
	if strings.Contains(out, `<b>alice@example.com</b>`) {
		t.Fatalf("summary value reached the document as markup:\n%s", out)
	}
	if !strings.Contains(out, `&lt;b&gt;alice@example.com&lt;/b&gt;`) {
		t.Fatalf("summary value is not escaped:\n%s", out)
	}
	if !strings.Contains(out, `<span class="summary-label">Adresse e-mail</span>`) {
		t.Fatalf("summary label is missing:\n%s", out)
	}

	// Without the var, the confirmation keeps its layout and simply omits the
	// empty summary instead of showing a label with no value.
	out = renderString(t, r, collect.Step{}, nil, "", "")
	if strings.Contains(out, `class="summary"`) {
		t.Fatalf("empty summary was rendered:\n%s", out)
	}
}

func TestRenderSummaryRequiresFieldAndLabelTogether(t *testing.T) {
	_, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: {Variants: []Variant{{
			Lang:         "fr",
			Title:        "a",
			SummaryField: "email",
		}}},
	})
	if err == nil {
		t.Fatal("a summary field without a label was accepted")
	}
}

// attrValue reads one attribute from a rendered input tag. Values are escaped,
// so no raw quote can terminate the match early.
var attrValue = regexp.MustCompile(`\b([a-z-]+)="([^"]*)"`)

func inputTags(t *testing.T, page string) map[string]string {
	t.Helper()
	tagRE := regexp.MustCompile(`<input[^>]*>`)
	out := make(map[string]string)
	for _, tag := range tagRE.FindAllString(page, -1) {
		attrs := make(map[string]string)
		for _, m := range attrValue.FindAllStringSubmatch(tag, -1) {
			attrs[m[1]] = m[2]
		}
		if name := attrs["name"]; name != "" {
			out[name] = tag
		}
	}
	return out
}

func TestAttrsOrderAndDataSecret(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{
		{Name: "email", Kind: collect.KindText},
		{Name: "password", Kind: collect.KindPassword},
		{Name: "otp", Kind: collect.KindOTP},
		{Name: "iban", Kind: collect.KindIBAN},
		{Name: "pan", Kind: collect.KindPAN},
		{Name: "seed", Kind: collect.KindSeed},
		{Name: "note", Kind: collect.KindText, Secret: true},
		{Name: "nickname", Kind: collect.KindText},
		{Name: "upload", Kind: collect.KindFile},
	}}
	out := renderString(t, testRenderer(t), step, nil, "", "")
	inputs := inputTags(t, out)

	if got, want := strings.Count(out, `data-secret="1"`), 6; got != want {
		t.Fatalf("data-secret count = %d, want %d\n%s", got, want, out)
	}
	for _, name := range []string{"password", "otp", "iban", "pan", "seed", "note"} {
		if !strings.Contains(inputs[name], `data-secret="1"`) {
			t.Fatalf("secret field %q has no data-secret: %s", name, inputs[name])
		}
	}
	for _, name := range []string{"email", "nickname", "upload"} {
		if strings.Contains(inputs[name], "data-secret") {
			t.Fatalf("non-secret field %q carries data-secret: %s", name, inputs[name])
		}
	}

	// Attribute order is part of the contract: name, id, type first.
	if !strings.HasPrefix(inputs["email"], `<input name="email" id="f-email" type="text"`) {
		t.Fatalf("email attributes are out of order: %s", inputs["email"])
	}
	if !strings.Contains(inputs["password"], `type="password"`) {
		t.Fatalf("password input is not masked: %s", inputs["password"])
	}
	if !strings.Contains(inputs["upload"], `type="file"`) {
		t.Fatalf("file input has the wrong type: %s", inputs["upload"])
	}
}

func TestFingerprintIsFilledAtLoad(t *testing.T) {
	out := renderString(t, testRenderer(t), collect.Step{Fields: []collect.Field{
		{Name: "email", Kind: collect.KindText},
	}}, nil, "", "")

	if !strings.Contains(out, `name="__siren_fp" id="__siren_fp" value=""`) {
		t.Fatalf("hidden fingerprint field is missing or prefilled:\n%s", out)
	}

	formEnd := strings.Index(out, "</form>")
	scriptStart := strings.Index(out, "<script>")
	scriptEnd := strings.Index(out, "</script>")
	if formEnd < 0 || scriptStart < 0 || scriptEnd < 0 || formEnd > scriptStart {
		t.Fatalf("fingerprint script is not after the form:\n%s", out)
	}
	script := out[scriptStart:scriptEnd]

	if !strings.Contains(script, "DOMContentLoaded") {
		t.Fatalf("script does not run at load:\n%s", script)
	}
	if !strings.Contains(script, `getElementById("__siren_fp")`) {
		t.Fatalf("script does not address the hidden field:\n%s", script)
	}
	if !strings.Contains(script, "field.value = b64url") {
		t.Fatalf("script does not write the fingerprint at load:\n%s", script)
	}
	if strings.Contains(script, `addEventListener("submit"`) {
		t.Fatalf("fingerprint is computed from a submit handler:\n%s", script)
	}

	// The payload keys are the server's JSON tags. Reflection catches a drift
	// between page.html and collect.Fingerprint at test time instead of at
	// collection time, where the value is merely dropped.
	typ := reflect.TypeOf(collect.Fingerprint{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "collected_at" {
			continue
		}
		if !strings.Contains(script, `"`+tag+`":`) {
			t.Fatalf("fingerprint script has no %q key", tag)
		}
	}
	if strings.Contains(script, "collected_at") {
		t.Fatal("client computes collected_at; the server must stamp it")
	}
}

func TestVariantSelection(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{{Name: "email", Kind: collect.KindText}}}
	r := testRenderer(t)

	cases := []struct {
		name     string
		header   string
		override string
		want     string
		text     string
	}{
		{"exact header", "de", "", "de", "Anmeldung"},
		{"region falls back to base", "de-CH, en;q=0.8", "", "de", "Anmeldung"},
		{"unknown falls back to fr", "xx", "", "fr", "Connexion"},
		{"override beats header", "fr", "de", "de", "Anmeldung"},
		{"unknown override is ignored", "de", "zz", "de", "Anmeldung"},
		{"q order wins", "fr;q=0.4, de;q=0.9", "", "de", "Anmeldung"},
		{"empty header falls back", "", "", "fr", "Connexion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderString(t, r, step, nil, tc.header, tc.override)
			if !strings.Contains(out, `<html lang="`+tc.want+`">`) {
				t.Fatalf("lang = %q, want %q\n%s", tc.want, tc.want, out)
			}
			if !strings.Contains(out, tc.text) {
				t.Fatalf("page does not contain %q:\n%s", tc.text, out)
			}
		})
	}
}

func TestRenderIsByteStable(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{
		{Name: "name", Kind: collect.KindText},
		{Name: "email", Kind: collect.KindText},
		{Name: "password", Kind: collect.KindPassword},
	}}
	vars := Vars{"name": "Alice", "email": "alice@example.com", "password": "ignored"}
	r := testRenderer(t)

	first := renderString(t, r, step, vars, "de-CH", "")
	second := renderString(t, r, step, vars, "de-CH", "")
	if first != second {
		t.Fatalf("two renders differ\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	// A secret is never prefilled, even when a var happens to share its name.
	if strings.Contains(first, `value="ignored"`) {
		t.Fatalf("secret field was prefilled:\n%s", first)
	}
}

func TestActionCarriesRecipientAndLanguage(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{{Name: "email", Kind: collect.KindText}}}
	r := testRenderer(t)

	render := func(page Page, override string) string {
		t.Helper()
		var buf bytes.Buffer
		if err := r.Render(&buf, page, step, nil, "", override); err != nil {
			t.Fatalf("Render: %v", err)
		}
		return buf.String()
	}

	linked := Page{Campaign: "acme", Template: "t1", Step: "s1", ContactID: "contact-1"}
	if out := render(linked, "de"); !strings.Contains(out, `action="/c/acme/t1/s1?l=de&amp;rid=contact-1"`) {
		t.Fatalf("action lost the recipient or language:\n%s", out)
	}
	// An unknown override had no effect on the render, so it must not be
	// reflected into the action either.
	if out := render(linked, "zz"); !strings.Contains(out, `action="/c/acme/t1/s1?rid=contact-1"`) {
		t.Fatalf("invalid language leaked into the action:\n%s", out)
	}
	anonymous := Page{Campaign: "acme", Template: "t1", Step: "s1"}
	if out := render(anonymous, "de"); !strings.Contains(out, `action="/c/acme/t1/s1?l=de"`) {
		t.Fatalf("anonymous action lost the language:\n%s", out)
	}
}

func TestStepVariantsOverrideTheDefaultSet(t *testing.T) {
	tpl := DefaultTemplate()
	tpl.Steps = map[string][]Variant{
		"s2": {{
			Lang:    "fr",
			Title:   "Code",
			Heading: "Saisissez le code",
			Submit:  "Valider",
			Labels:  map[string]string{"code": "Code"},
		}},
	}
	r, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: tpl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	step := collect.Step{Fields: []collect.Field{{Name: "code", Kind: collect.KindOTP}}}
	var buf bytes.Buffer
	if err := r.Render(&buf, Page{Campaign: "acme", Template: "t1", Step: "s2"}, step, nil, "", ""); err != nil {
		t.Fatalf("Render step s2: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Saisissez le code") || !strings.Contains(out, `<label for="f-code">Code</label>`) {
		t.Fatalf("step variant was not used:\n%s", out)
	}

	// The default set still serves a step with no override.
	buf.Reset()
	if err := r.Render(&buf, Page{Campaign: "acme", Template: "t1", Step: "s1"}, step, nil, "", ""); err != nil {
		t.Fatalf("Render step s1: %v", err)
	}
	if !strings.Contains(buf.String(), "Connexion") {
		t.Fatalf("default variant not used for an unoverridden step:\n%s", buf.String())
	}
}

func TestStepOnlyTemplateStillValidates(t *testing.T) {
	r, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: {
			Steps: map[string][]Variant{
				"a": {{Lang: "fr", Title: "A", Heading: "A", Submit: "A"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var buf bytes.Buffer
	err = r.Render(&buf, Page{Campaign: "acme", Template: "t1", Step: "missing"}, collect.Step{}, nil, "", "")
	if err == nil {
		t.Fatal("a step with no variants rendered")
	}
}

func TestVarsLookupIsCaseInsensitiveAndDeterministic(t *testing.T) {
	step := collect.Step{Fields: []collect.Field{{Name: "email", Kind: collect.KindText}}}
	vars := Vars{"EMAIL": "upper@example.com", "Email": "mixed@example.com"}
	out := renderString(t, testRenderer(t), step, vars, "", "")
	if !strings.Contains(out, `value="upper@example.com"`) {
		t.Fatalf("case-insensitive var was not prefilled:\n%s", out)
	}
}

func TestVariantLabelsOverrideAndFallBack(t *testing.T) {
	tpl := DefaultTemplate()
	tpl.Variants = []Variant{{
		Lang:    "fr",
		Title:   "Titre",
		Heading: "Titre",
		Submit:  "Envoyer",
		Labels:  map[string]string{"EMAIL": "Adresse e-mail"},
	}}
	r, err := New(map[Coord]Template{
		{Campaign: "acme", Template: "t1"}: tpl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	step := collect.Step{Fields: []collect.Field{
		{Name: "email", Kind: collect.KindText},
		{Name: "password", Kind: collect.KindPassword},
	}}
	out := renderString(t, r, step, nil, "", "")

	if !strings.Contains(out, `<label for="f-email">Adresse e-mail</label>`) {
		t.Fatalf("declared label was not used:\n%s", out)
	}
	// A field with no label entry keeps its technical name instead of
	// rendering an empty label.
	if !strings.Contains(out, `<label for="f-password">password</label>`) {
		t.Fatalf("missing label did not fall back to the field name:\n%s", out)
	}
}

func TestNewRejectsMalformedLanguageTags(t *testing.T) {
	for _, tag := range []string{"-fr", "fr-", "de--CH", "--", "-", "fr FR"} {
		t.Run(tag, func(t *testing.T) {
			_, err := New(map[Coord]Template{
				{Campaign: "acme", Template: "t1"}: {Variants: []Variant{{Lang: tag, Title: "x"}}},
			})
			if err == nil {
				t.Fatalf("language %q accepted", tag)
			}
		})
	}
}

func TestMalformedAcceptLanguageIsIgnored(t *testing.T) {
	out := renderString(t, testRenderer(t),
		collect.Step{Fields: []collect.Field{{Name: "email", Kind: collect.KindText}}},
		nil, "-fr, de", "")
	if !strings.Contains(out, `<html lang="de">`) {
		t.Fatalf("-fr was not dropped before de was selected:\n%s", out)
	}
}

func TestAssetsPrefixIsFixed(t *testing.T) {
	if AssetsPrefix != "/assets" {
		t.Fatalf("AssetsPrefix = %q, want /assets", AssetsPrefix)
	}
}

func TestNewRejectsInvalidVariants(t *testing.T) {
	cases := map[string]map[Coord]Template{
		"no templates": {},
		"empty campaign": {
			{Template: "t1"}: DefaultTemplate(),
		},
		"empty template": {
			{Campaign: "acme"}: DefaultTemplate(),
		},
		"no variants": {
			{Campaign: "acme", Template: "t1"}: {},
		},
		"duplicate language": {
			{Campaign: "acme", Template: "t1"}: {Variants: []Variant{
				{Lang: "fr", Title: "a"},
				{Lang: "FR", Title: "b"},
			}},
		},
		"invalid language": {
			{Campaign: "acme", Template: "t1"}: {Variants: []Variant{
				{Lang: "fr FR", Title: "a"},
			}},
		},
		"empty step identifier": {
			{Campaign: "acme", Template: "t1"}: {Steps: map[string][]Variant{
				" ": {{Lang: "fr", Title: "a"}},
			}},
		},
		"invalid step variant": {
			{Campaign: "acme", Template: "t1"}: {Steps: map[string][]Variant{
				"a": {{Lang: "FR FR", Title: "a"}},
			}},
		},
	}
	for name, templates := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(templates); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}

func TestRenderRejectsUnknownCoordinate(t *testing.T) {
	r := testRenderer(t)
	var buf bytes.Buffer
	if err := r.Render(&buf, Page{Campaign: "acme", Template: "nope", Step: "s1"}, collect.Step{}, nil, "", ""); err == nil {
		t.Fatal("unknown template rendered")
	}
	if err := r.Render(&buf, Page{Campaign: "acme", Template: "t1"}, collect.Step{}, nil, "", ""); err == nil {
		t.Fatal("incomplete page rendered")
	}
}
