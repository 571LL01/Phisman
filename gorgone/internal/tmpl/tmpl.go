// Package tmpl renders one collect.Step as a complete, localized HTML page and
// serves the static assets that belong to that template.
//
// The renderer is deliberately a pure function of its inputs: a Step, a Vars
// map and two language hints. It never reads a clock, a random source or a map
// in an order that reaches the output, so the same inputs produce the same
// bytes. That property is what makes an emailed page reproducible and a diff
// between two renderings meaningful.
package tmpl

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/siren-core/gorgone/internal/collect"
)

const (
	// AssetsPrefix is the first path segment of the static asset route. It is a
	// constant because cmd/sirencore validates the beacon prefix against it at
	// boot: two routes sharing a first segment would make ServeMux panic.
	AssetsPrefix = "/assets"

	// DefaultLanguage is the fallback when neither ?l= nor Accept-Language
	// names an existing variant.
	DefaultLanguage = "fr"

	maxVariants = 64
)

// Vars carries contact-provided values into a render. Values are always
// escaped by html/template or by the attribute builder; nothing in this map is
// trusted as markup.
type Vars map[string]string

// lookup resolves a name case-insensitively, preferring the exact key. When
// several keys differ only by case, the lexicographically smallest wins so a
// render never depends on Go's map iteration order.
func (v Vars) lookup(name string) string {
	if value, ok := v[name]; ok {
		return value
	}
	best := ""
	found := false
	for key := range v {
		if !strings.EqualFold(key, name) {
			continue
		}
		if !found || key < best {
			best, found = key, true
		}
	}
	if !found {
		return ""
	}
	return v[best]
}

// Lookup resolves a name case-insensitively. It is the exported form of the
// internal lookup method, used by packages that compose emails from contact vars.
func (v Vars) Lookup(name string) string { return v.lookup(name) }

// Coord identifies one template in the configuration tree.
type Coord struct {
	Campaign string
	Template string
}

// Page identifies the step being rendered. The three values are used to build
// the form action and the asset URL, so they are path-escaped individually.
type Page struct {
	// Campaign is the key used to look up the template and its assets. In a live
	// deployment this is the config campaign key (e.g. "acme").
	Campaign string
	Template string
	Step     string
	// ContactID is carried in the form action as ?rid= so a POST keeps the
	// recipient attribution of the delivery link. Empty means no recipient.
	ContactID string
	// LinkCampaign is the campaign segment written into the form action URL.
	// It is the campaign the visitor's link used (the DB campaign id), which may
	// differ from Campaign (the config key used to find the template). When
	// empty it falls back to Campaign. Keeping them separate is what makes a
	// submission land back on the same campaign the link, click and contact
	// attribution use, instead of on the config key.
	LinkCampaign string
}

func (p Page) coord() Coord {
	return Coord{Campaign: p.Campaign, Template: p.Template}
}

// actionCampaign is the campaign segment for the form action URL: the link
// campaign when set, otherwise the lookup campaign.
func (p Page) actionCampaign() string {
	if p.LinkCampaign != "" {
		return p.LinkCampaign
	}
	return p.Campaign
}

// Variant is one localized presentation. Every human-visible string lives here
// so a new language is data, not a code path.
type Variant struct {
	Lang     string
	Title    string
	Heading  string
	Greeting string
	Intro    string
	Submit   string
	Note     string
	// SummaryField names a contact var that a confirmation step recalls as
	// read-only context. SummaryLabel is the localized heading beside it. The
	// value is looked up in Vars and escaped by html/template; it is never an
	// input, so a confirmation does not duplicate the field it recalls.
	SummaryField string
	SummaryLabel string
	// Labels maps a technical field name to the text the visitor reads. Keys
	// are lowercased at boot, because collect.Field lookup is case-insensitive;
	// a missing entry falls back to the field's own name.
	Labels map[string]string
}

// Template is the presentation half of a step: the variants an operator
// declared and the embedded static files they may reference.
//
// Variants is the default set. Steps overrides it for a named step, which is
// what lets one template ID carry different copy for an identifier screen and
// its OTP screen while sharing the same assets. A template with Steps but no
// Variants is valid: every reachable step must then be declared explicitly.
type Template struct {
	Variants []Variant
	Steps    map[string][]Variant
	Assets   fs.FS
}

// Renderer holds the template registry. It is safe for concurrent use after
// New returns because the maps are never mutated.
type Renderer struct {
	templates map[Coord]Template
	// files holds one http.FileServerFS per template, built once at boot.
	// Rebuilding it per request allocated a handler on every asset GET.
	files map[Coord]http.Handler
}

// New validates the registry and returns a renderer. Validation happens once,
// at boot, so a malformed variant list cannot turn into a 500 on a live
// campaign.
func New(templates map[Coord]Template) (*Renderer, error) {
	if len(templates) == 0 {
		return nil, errors.New("tmpl: no templates")
	}
	out := make(map[Coord]Template, len(templates))
	for coord, t := range templates {
		if coord.Campaign == "" {
			return nil, errors.New("tmpl: template coordinate has an empty campaign")
		}
		if coord.Template == "" {
			return nil, errors.New("tmpl: template coordinate has an empty template")
		}

		// Variants is optional only when the template declares at least one
		// step set. A template with neither is still the old "no variants"
		// boot error, not a render-time surprise.
		var variants []Variant
		if len(t.Variants) > 0 || len(t.Steps) == 0 {
			v, err := normalizeVariants(t.Variants)
			if err != nil {
				return nil, fmt.Errorf("tmpl: %s/%s: %w", coord.Campaign, coord.Template, err)
			}
			variants = v
		}
		t.Variants = variants

		steps := make(map[string][]Variant, len(t.Steps))
		for stepID, set := range t.Steps {
			key := strings.TrimSpace(stepID)
			if key == "" {
				return nil, fmt.Errorf("tmpl: %s/%s: step with an empty identifier", coord.Campaign, coord.Template)
			}
			if _, dup := steps[key]; dup {
				return nil, fmt.Errorf("tmpl: %s/%s: duplicate step %q", coord.Campaign, coord.Template, key)
			}
			v, err := normalizeVariants(set)
			if err != nil {
				return nil, fmt.Errorf("tmpl: %s/%s step %q: %w", coord.Campaign, coord.Template, key, err)
			}
			steps[key] = v
		}
		if len(steps) == 0 {
			steps = nil
		}
		t.Steps = steps
		out[coord] = t
	}
	files := make(map[Coord]http.Handler, len(out))
	for coord, t := range out {
		if t.Assets != nil {
			files[coord] = http.FileServerFS(t.Assets)
		}
	}
	return &Renderer{templates: out, files: files}, nil
}

func normalizeVariants(variants []Variant) ([]Variant, error) {
	if len(variants) == 0 {
		return nil, errors.New("no variants")
	}
	if len(variants) > maxVariants {
		return nil, fmt.Errorf("%d variants; maximum is %d", len(variants), maxVariants)
	}
	seen := make(map[string]struct{}, len(variants))
	out := make([]Variant, 0, len(variants))
	for i, v := range variants {
		lang := strings.ToLower(strings.TrimSpace(v.Lang))
		if !validLang(lang) {
			return nil, fmt.Errorf("variant %d: language %q is not a lowercase tag", i, v.Lang)
		}
		if _, dup := seen[lang]; dup {
			return nil, fmt.Errorf("variant %d: duplicate language %q", i, lang)
		}
		seen[lang] = struct{}{}
		v.Lang = lang

		v.SummaryField = strings.TrimSpace(v.SummaryField)
		v.SummaryLabel = strings.TrimSpace(v.SummaryLabel)
		if (v.SummaryField == "") != (v.SummaryLabel == "") {
			return nil, fmt.Errorf("variant %d: summary field and label must be set together", i)
		}

		labels := make(map[string]string, len(v.Labels))
		for name, label := range v.Labels {
			key := strings.ToLower(strings.TrimSpace(name))
			if key == "" {
				return nil, fmt.Errorf("variant %d: label key is empty", i)
			}
			if _, dup := labels[key]; dup {
				return nil, fmt.Errorf("variant %d: duplicate label %q", i, key)
			}
			labels[key] = strings.TrimSpace(label)
		}
		if len(labels) > 0 {
			v.Labels = labels
		} else {
			v.Labels = nil
		}
		out = append(out, v)
	}
	return out, nil
}

// ValidLanguage reports whether tag is a lowercase, hyphen-separated language
// tag acceptable to a Variant. It is exported for the config layer, which must
// reject a label key that could never select a variant.
func ValidLanguage(tag string) bool { return validLang(tag) }

// validLang accepts a lowercase, hyphen-separated tag with no empty subtag.
// That rejects -fr, fr- and de--CH, which normalizeVariants trims to themselves
// and which would otherwise become selectable variants no Accept-Language
// header can legitimately reach.
func validLang(tag string) bool {
	if tag == "" || len(tag) > 63 {
		return false
	}
	subtag := 0
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c == '-':
			if subtag == 0 {
				return false
			}
			subtag = 0
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			subtag++
		default:
			return false
		}
	}
	return subtag != 0
}

// RenderResult carries the rendered page and the variant that was actually
// selected. The variant's Lang is the BCP 47 tag that was used; it may differ
// from the override when the override is unknown.
type RenderResult struct {
	// Lang is the language tag of the selected variant, normalised to lowercase.
	Lang string
}

// RenderFull renders the step into w and returns the selected variant metadata.
// It is the composition-aware form of Render: a mailer needs to know which
// variant was selected so it can set Content-Language and choose the right
// subject line.
func (r *Renderer) RenderFull(w io.Writer, page Page, step collect.Step, vars Vars, acceptLanguage, override string) (RenderResult, error) {
	if page.Campaign == "" || page.Template == "" || page.Step == "" {
		return RenderResult{}, errors.New("tmpl: page coordinate is incomplete")
	}
	t, ok := r.templates[page.coord()]
	if !ok {
		return RenderResult{}, fmt.Errorf("tmpl: unknown template %q/%q", page.Campaign, page.Template)
	}

	variants := t.Variants
	if set, ok := t.Steps[page.Step]; ok {
		variants = set
	}
	if len(variants) == 0 {
		return RenderResult{}, fmt.Errorf("tmpl: %q/%q has no variants for step %q", page.Campaign, page.Template, page.Step)
	}
	variant := selectVariant(variants, acceptLanguage, override)

	if err := r.renderVariant(w, t, page, step, vars, variant, override); err != nil {
		return RenderResult{}, err
	}
	return RenderResult{Lang: variant.Lang}, nil
}

// Render writes the complete page for step. The response is buffered first, so
// a template execution error cannot leave a half-written 200 on the wire.
//
// override is the raw ?l= value. It is used only when it names an existing
// variant; anything else falls through to the Accept-Language negotiation and
// finally to DefaultLanguage. That order is the whole contract: a query string
// may choose among shipped languages, never invent one.
func (r *Renderer) Render(w io.Writer, page Page, step collect.Step, vars Vars, acceptLanguage, override string) error {
	_, err := r.RenderFull(w, page, step, vars, acceptLanguage, override)
	return err
}

func (r *Renderer) renderVariant(w io.Writer, t Template, page Page, step collect.Step, vars Vars, variant Variant, override string) error {
	fields := make([]fieldView, 0, len(step.RenderFields()))
	for _, f := range step.RenderFields() {
		attrs, err := attributeView(f)
		if err != nil {
			return err
		}
		label := variant.Labels[strings.ToLower(f.Name)]
		if label == "" {
			label = f.Name
		}
		view := fieldView{Name: f.Name, Label: label, ID: "f-" + f.Name, Attrs: attrs}
		// A secret is never written back into the document, and a file input
		// cannot carry a value. Everything else may be prefilled from the
		// contact's vars.
		if !f.DataSecret() && f.Kind != collect.KindFile {
			view.Value = vars.lookup(f.Name)
		}
		fields = append(fields, view)
	}

	// The greeting prefers an explicit name var, then the FirstName key used
	// by the contact import format.
	name := strings.TrimSpace(vars.lookup("name"))
	if name == "" {
		name = strings.TrimSpace(vars.lookup("FirstName"))
	}
	greeting := ""
	if name != "" {
		greeting = strings.TrimSpace(variant.Greeting + " " + name)
	}

	// A confirmation step may recall one visible value, such as the address
	// the flow says it delivered to. An empty value (no recipient, or a var
	// the contact does not have) hides the block rather than showing a label
	// with nothing beside it.
	summaryLabel, summaryValue := "", ""
	if variant.SummaryField != "" {
		summaryValue = strings.TrimSpace(vars.lookup(variant.SummaryField))
		if summaryValue != "" {
			summaryLabel = variant.SummaryLabel
		}
	}

	styleURL := ""
	if t.Assets != nil {
		styleURL = AssetsPrefix + "/" + url.PathEscape(page.Campaign) + "/" + url.PathEscape(page.Template) + "/style.css"
	}

	action := "/c/" + url.PathEscape(page.actionCampaign()) + "/" + url.PathEscape(page.Template) + "/" + url.PathEscape(page.Step)
	if q := actionQuery(page.ContactID, override, variant.Lang); q != "" {
		action += "?" + q
	}

	view := pageView{
		Lang:         variant.Lang,
		Title:        variant.Title,
		Heading:      variant.Heading,
		Greeting:     greeting,
		Intro:        variant.Intro,
		Submit:       variant.Submit,
		Note:         variant.Note,
		Action:       action,
		StyleURL:     styleURL,
		Fields:       fields,
		SummaryLabel: summaryLabel,
		Summary:      summaryValue,
	}

	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, view); err != nil {
		return fmt.Errorf("tmpl: execute page: %w", err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

type fieldView struct {
	Name  string
	Label string
	ID    string
	Attrs []template.HTMLAttr
	Value string
}

type pageView struct {
	Lang     string
	Title    string
	Heading  string
	Greeting string
	Intro    string
	Submit   string
	Note     string
	Action   string
	StyleURL string
	Fields   []fieldView
	// Summary is a single non-editable value recalled from contact vars.
	SummaryLabel string
	Summary      string
}

// allowedAttributes is the closed set collect.Field.Attrs may emit. It is a
// second line of defence: even a future Attrs change that introduces a new
// name cannot silently become trusted markup.
var allowedAttributes = map[string]bool{
	"name":         true,
	"id":           true,
	"type":         true,
	"autocomplete": true,
	"inputmode":    true,
	"spellcheck":   true,
	"maxlength":    true,
	"accept":       true,
	"data-secret":  true,
}

// attributeView serializes Attrs in declaration order.
//
// template.HTMLAttr is used because html/template rewrites a dynamic attribute
// name it does not know (data-secret is one) to ZgotmplZ. The trusted type is
// scoped to one name="value" pair, the name is checked against the allowlist
// above, and the value is html.EscapeString'd before it enters the pair.
func attributeView(f collect.Field) ([]template.HTMLAttr, error) {
	attrs := f.Attrs()
	out := make([]template.HTMLAttr, 0, len(attrs))
	for _, a := range attrs {
		if !allowedAttributes[a.Name] {
			return nil, fmt.Errorf("tmpl: field %q: attribute %q is not allowlisted", f.Name, a.Name)
		}
		out = append(out, template.HTMLAttr(a.Name+`="`+html.EscapeString(a.Value)+`"`))
	}
	return out, nil
}

// actionQuery carries the recipient and language selection through the POST.
// rid is already validated by the caller. l is included only when the override
// actually selected the rendered variant, so an unknown tag that fell through
// to Accept-Language is not reflected into the form action.
func actionQuery(contactID, override, selected string) string {
	q := url.Values{}
	if contactID != "" {
		q.Set("rid", contactID)
	}
	if o := strings.ToLower(strings.TrimSpace(override)); o != "" && o == selected {
		q.Set("l", o)
	}
	if len(q) == 0 {
		return ""
	}
	return q.Encode()
}

// selectVariant applies, in order: a validated ?l= override, the best
// Accept-Language match, then DefaultLanguage, then the first declared variant.
func selectVariant(variants []Variant, acceptLanguage, override string) Variant {
	byLang := make(map[string]Variant, len(variants))
	for _, v := range variants {
		byLang[v.Lang] = v
	}

	if o := strings.ToLower(strings.TrimSpace(override)); o != "" {
		if v, ok := byLang[o]; ok {
			return v
		}
	}

	for _, tag := range parseAcceptLanguage(acceptLanguage) {
		for candidate := tag; candidate != ""; candidate = truncateLang(candidate) {
			if v, ok := byLang[candidate]; ok {
				return v
			}
		}
	}

	if v, ok := byLang[DefaultLanguage]; ok {
		return v
	}
	return variants[0]
}

type langRange struct {
	tag   string
	q     float64
	order int
}

// parseAcceptLanguage returns language ranges in preference order. A malformed
// q value drops that range rather than rejecting the whole header: a broken
// header from an old client must still yield a page.
func parseAcceptLanguage(header string) []string {
	ranges := make([]langRange, 0, 4)
	for order, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ";")
		tag := strings.ToLower(strings.TrimSpace(fields[0]))
		if tag != "*" && !validLang(tag) {
			continue
		}

		q := 1.0
		valid := true
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				valid = false
				break
			}
			q = parsed
		}
		if !valid || q <= 0 {
			continue
		}
		ranges = append(ranges, langRange{tag: tag, q: q, order: order})
	}

	sort.SliceStable(ranges, func(i, j int) bool {
		if ranges[i].q != ranges[j].q {
			return ranges[i].q > ranges[j].q
		}
		return ranges[i].order < ranges[j].order
	})

	out := make([]string, len(ranges))
	for i, r := range ranges {
		out[i] = r.tag
	}
	return out
}

// truncateLang walks a tag towards its base: de-CH-1901 -> de-ch -> de. A tag
// without a hyphen has no broader form.
func truncateLang(tag string) string {
	if i := strings.LastIndexByte(tag, '-'); i > 0 {
		return tag[:i]
	}
	return ""
}
