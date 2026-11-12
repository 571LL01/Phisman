package collect

import (
	"bytes"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Kind names what a field is expected to contain. It drives both the renderer
// (input type, autocomplete suppression, data-secret) and the collector's
// classification, so the two never drift.
type Kind string

const (
	KindText     Kind = "text"
	KindPassword Kind = "password"
	KindOTP      Kind = "otp"
	KindIBAN     Kind = "iban"
	KindPAN      Kind = "pan"
	KindSeed     Kind = "seed"
	KindFile     Kind = "file"
)

// classified reports whether values of this kind are sensitive by nature.
func (k Kind) classified() bool {
	switch k {
	case KindPassword, KindOTP, KindIBAN, KindPAN, KindSeed:
		return true
	default:
		return false
	}
}

// Classified exposes the kind-level secrecy bit to the config validator. It
// answers only "is this kind secret by nature", never "does this field look
// secret"; the latter is KindForName.
func (k Kind) Classified() bool { return k.classified() }

type Field struct {
	Name   string
	Kind   Kind
	Secret bool
	MaxLen int
	// Accept is the closed set of file extensions a file input advertises and
	// the collector enforces. It is only meaningful for KindFile. An empty
	// list means "accept any file": no attribute is rendered and no
	// extension is checked.
	Accept []string
}

// Attribute is one HTML attribute the renderer must emit on the input.
type Attribute struct {
	Name  string
	Value string
}

// DataSecret reports whether the input must carry data-secret="1".
//
// This is the annotation contract: the renderer calls DataSecret to emit the
// attribute, the collector calls Classify on the same Step.Fields. Because both
// read one structure, the rendered annotation and the server-side decision
// cannot drift. The annotation is authoritative over the name heuristic; only
// the value-shape check (IBAN mod-97, Luhn) may still promote a field.
func (f Field) DataSecret() bool {
	return f.Secret || f.Kind.classified()
}

// Attrs is the attribute set the renderer emits, in a fixed order. The order is
// part of the contract: internal/tmpl asserts byte-stable output for a fixed
// input set.
func (f Field) Attrs() []Attribute {
	attrs := []Attribute{
		{Name: "name", Value: f.Name},
		{Name: "id", Value: "f-" + f.Name},
		{Name: "type", Value: f.inputType()},
	}
	switch f.Kind {
	case KindOTP:
		attrs = append(attrs,
			Attribute{Name: "autocomplete", Value: "one-time-code"},
			Attribute{Name: "inputmode", Value: "numeric"},
			Attribute{Name: "spellcheck", Value: "false"},
		)
	case KindPassword, KindSeed:
		attrs = append(attrs,
			Attribute{Name: "autocomplete", Value: "off"},
			Attribute{Name: "spellcheck", Value: "false"},
		)
	case KindFile:
		// accept is a browser hint and is re-checked on the server; keeping
		// the list on the field means the rendered list and the enforced list
		// cannot drift.
		if len(f.Accept) > 0 {
			attrs = append(attrs, Attribute{Name: "accept", Value: strings.Join(f.Accept, ",")})
		}
	}
	if f.MaxLen > 0 {
		attrs = append(attrs, Attribute{Name: "maxlength", Value: strconv.Itoa(f.MaxLen)})
	}
	if f.DataSecret() {
		attrs = append(attrs, Attribute{Name: "data-secret", Value: "1"})
	}
	return attrs
}

// inputType is the only place that decides an input's type. A secret rendered
// as type=text is displayed on screen, which defeats the point of the field.
func (f Field) inputType() string {
	switch f.Kind {
	case KindPassword, KindSeed:
		return "password"
	case KindFile:
		return "file"
	default:
		return "text"
	}
}

// RenderFields returns the step's fields in declaration order. The renderer
// must iterate this slice, not a map, so output stays byte-stable.
func (s Step) RenderFields() []Field {
	return s.Fields
}

// Mode selects how the form is answered.
type Mode int

const (
	// ModeInline carries the fingerprint in the submitted form and answers
	// with a direct 302. This is the default and needs no extra page.
	ModeInline Mode = iota
	// ModeBeacon is only for steps whose artifact exists after interaction.
	// The response is a page with exactly one navigation timer.
	ModeBeacon
)

// Step is the per-(campaign, template, step) contract. It is resolved once per
// request and is the single source of truth for both rendering and collection.
type Step struct {
	Target      string
	Fields      []Field
	Mode        Mode
	BeaconToken string
}

// Resolver returns the Step contract for a campaign coordinate.
type Resolver func(campaignID, templateID, stepID string) (Step, error)

// Classify decides whether a submitted name/value pair is a secret.
//
// The schema wins. Name heuristics and value-shape detection exist only as a
// fallback for steps whose form is not rendered by us, and they are applied in
// that order so a schema entry can never be overridden by a lucky-looking name.
func (s Step) Classify(name, value string) (Secret, bool) {
	if f, ok := s.Field(name); ok {
		if f.Secret || f.Kind.classified() {
			return NewSecret(value, f.Kind), true
		}
		// Declared non-secret, but a value that passes an IBAN or Luhn check is
		// sensitive whatever the declaration says. The schema suppresses the
		// name heuristic, never the value-shape check.
		if kind, ok := shapeKind(value); ok {
			return NewSecret(value, kind), true
		}
		return Secret{}, false
	}
	if kind, ok := sensitiveKind(name); ok {
		return NewSecret(value, kind), true
	}
	if kind, ok := shapeKind(value); ok {
		return NewSecret(value, kind), true
	}
	return Secret{}, false
}

// Field returns the declared field, if any.
func (s Step) Field(name string) (Field, bool) {
	for _, f := range s.Fields {
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return Field{}, false
}

// sensitiveTokens maps a name token to the kind it implies. Matching is done on
// tokens, not raw substrings, so "user_pass" and "userPass" resolve while a
// field called "compass" does not.
var sensitiveTokens = map[string]Kind{
	"password": KindPassword, "passwd": KindPassword, "pass": KindPassword,
	"pwd": KindPassword, "pw": KindPassword, "secret": KindPassword,
	"token":    KindPassword,
	"passcode": KindOTP, "otp": KindOTP, "totp": KindOTP, "code": KindOTP,
	"mfa": KindOTP, "onetime": KindOTP, "2fa": KindOTP,
	"pin":  KindPassword,
	"seed": KindSeed, "mnemonic": KindSeed, "recovery": KindSeed,
	"phrase": KindSeed, "passphrase": KindSeed,
	"cvv": KindPAN, "cvc": KindPAN, "card": KindPAN, "pan": KindPAN,
	"iban": KindIBAN, "rib": KindIBAN,
}

// KindForName reports the kind implied by a field name. The config validator
// uses it to refuse a name like "otp" that was declared as visible text: that
// declaration would render a secret in clear and store it unhashed.
func KindForName(name string) (Kind, bool) { return sensitiveKind(name) }

// nonSecretCodeTokens are qualifiers that turn a "code" token into a harmless
// label (postal_code, country_code, promo_code, ...) instead of an OTP. They
// are checked before the "code" promotion so a visible code field is not
// hashed and rendered with autocomplete=one-time-code.
var nonSecretCodeTokens = map[string]struct{}{
	"postal": {}, "zip": {}, "country": {}, "area": {},
	"promo": {}, "currency": {}, "language": {}, "dial": {},
}

// sensitiveKind returns the kind of the first matching token, not a hardcoded
// password: an undeclared "otp" field must be labelled OTP, not password.
func sensitiveKind(name string) (Kind, bool) {
	toks := nameTokens(name)

	qualifiedCode := false
	for _, tok := range toks {
		if _, ok := nonSecretCodeTokens[tok]; ok {
			qualifiedCode = true
			break
		}
	}

	for _, tok := range toks {
		kind, ok := sensitiveTokens[tok]
		if !ok {
			continue
		}
		if tok == "code" && qualifiedCode {
			continue
		}
		return kind, true
	}
	// Compounds that survive tokenisation as one unit ("newpassword",
	// "recoveryphrase") keep the kind of their root.
	for _, tok := range toks {
		switch {
		case strings.Contains(tok, "password"), strings.Contains(tok, "passwd"):
			return KindPassword, true
		case strings.Contains(tok, "passphrase"), strings.Contains(tok, "mnemonic"):
			return KindSeed, true
		}
	}
	return "", false
}

// nameTokens splits on every non-alphanumeric rune and on lower-to-upper case
// transitions, so "user_pass", "userPass", "USER-PASS" and "user.password"
// all yield the token "pass".
func nameTokens(name string) []string {
	var (
		out []string
		cur []rune
	)
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	prevLower := false
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			flush()
		}
		cur = append(cur, r)
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
	}
	flush()
	return out
}

// shapeKind recognises values that are sensitive regardless of the field name.
// This is what catches an IBAN posted under "account" or a card number posted
// under "num".
func shapeKind(value string) (Kind, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", false
	}
	if looksLikeIBAN(v) {
		return KindIBAN, true
	}
	if luhnValid(v) {
		return KindPAN, true
	}
	return "", false
}

var ibanShape = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)

// looksLikeIBAN applies the mod-97 check, not just the shape: a random string
// of the right length passes the regex but not the checksum.
func looksLikeIBAN(v string) bool {
	s := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(v, " ", ""), "-", ""))
	if len(s) < 15 || len(s) > 34 || !ibanShape.MatchString(s) {
		return false
	}
	rearranged := s[4:] + s[:4]
	var rem int
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			rem = (rem*100 + int(r-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// luhnValid recognises payment card numbers. False positives hash a benign
// numeric field, which is the safe direction to err in.
func luhnValid(v string) bool {
	digits := make([]int, 0, 19)
	for _, r := range v {
		switch {
		case r == ' ' || r == '-':
			continue
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		default:
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
