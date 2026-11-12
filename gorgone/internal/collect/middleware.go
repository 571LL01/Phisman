package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultMaxBody      = 64 << 10
	defaultMaxMultipart = 8 << 20
	multipartMemory     = 1 << 20
	maxFieldCount       = 256
	storeTimeout        = 3 * time.Second
	contactTimeout      = 2 * time.Second

	// FingerprintField is the hidden input the template layer fills at load.
	FingerprintField = "__siren_fp"

	// DefaultBeaconPrefix is the constant first segment used when the config
	// leaves beacon_prefix empty. The route layer must validate against this
	// same value, so it lives beside the code that applies it.
	DefaultBeaconPrefix = "/__siren"
)

type Config struct {
	TrustedProxies  []*net.IPNet
	Resolve         Resolver
	HeaderDeny      []string
	EdgeHeader      string
	Logger          *slog.Logger
	MaxBody         int64
	MaxMultipart    int64
	AllowHTTPTarget bool
	// BeaconPrefix is the constant leading segment of the post-interaction
	// collection path. It is configurable so a deployment can move it without
	// touching Step.BeaconToken, which stays random per campaign.
	BeaconPrefix string
	// ResolveContact reports whether contactID belongs to campaignID. It is
	// optional: without it, artifacts are still captured but carry no
	// contact_id. A lookup error or an unknown contact is logged and leaves
	// the attribution empty; it never rejects the submission.
	ResolveContact func(ctx context.Context, campaignID, contactID string) (bool, error)
}

type Collector struct {
	cfg   Config
	store Store
	now   func() time.Time
}

func New(cfg Config, st Store) (*Collector, error) {
	if cfg.Resolve == nil {
		return nil, errors.New("collect: Config.Resolve is required")
	}
	if st == nil {
		return nil, errors.New("collect: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = defaultMaxBody
	}
	if cfg.MaxMultipart <= 0 {
		cfg.MaxMultipart = defaultMaxMultipart
	}
	if cfg.BeaconPrefix == "" {
		cfg.BeaconPrefix = DefaultBeaconPrefix
	}
	return &Collector{cfg: cfg, store: st, now: time.Now}, nil
}

// Capture records one submission and answers it.
//
// In ModeInline the answer is a direct 302: the fingerprint arrived inside the
// form, so there is nothing left to wait for. ModeBeacon is opt-in and only for
// steps whose artifact exists after interaction.
func (c *Collector) Capture(campaignID, templateID, stepID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// The URL carries rid. Without this header the browser would send it
		// to the real target in the Referer of the 302, disclosing the
		// recipient identifier to the site being simulated.
		w.Header().Set("Referrer-Policy", "no-referrer")

		step, err := c.cfg.Resolve(campaignID, templateID, stepID)
		if err != nil {
			c.cfg.Logger.Error("step resolution failed",
				"campaign", campaignID, "template", templateID, "step", stepID, "err", err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		target, err := ValidateTarget(step.Target, c.cfg.AllowHTTPTarget)
		if err != nil {
			c.cfg.Logger.Error("invalid target", "campaign", campaignID, "err", err)
			http.Error(w, "misconfigured", http.StatusInternalServerError)
			return
		}

		limit := c.cfg.MaxBody
		isMulti := isMultipart(r)
		if isMulti {
			limit = c.cfg.MaxMultipart
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if err := c.parse(r, isMulti); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// ParseMultipartForm spills above multipartMemory to files under
		// TempDir. Without this the campaign fills the disk one upload at a
		// time and nothing ever reclaims it.
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		if len(r.PostForm) > maxFieldCount {
			http.Error(w, "too many fields", http.StatusRequestEntityTooLarge)
			return
		}
		if err := validateUploads(step, r); err != nil {
			c.cfg.Logger.Warn("rejected upload",
				"campaign", campaignID, "template", templateID, "step", stepID, "err", err)
			http.Error(w, "unsupported upload", http.StatusBadRequest)
			return
		}

		a := c.extract(r, campaignID, templateID, stepID, target, step)

		// Detach from client cancellation: closing the tab on submit must not
		// cost the artifact.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), storeTimeout)
		err = c.store.Insert(ctx, a)
		cancel()
		if err != nil {
			// The visitor's experience must not change because our disk is
			// full; the SOC gets the log line instead.
			c.cfg.Logger.Error("artifact persist failed", "artifact", a.ID, "err", err)
		}

		if step.Mode == ModeBeacon {
			c.writeBeacon(w, r, a, step)
			return
		}

		// An in-app target is the next step of the same flow. The static
		// target cannot know the recipient, so carry the resolved rid across;
		// the next page then puts it in its own form action. An unknown rid
		// stays empty and the next page renders anonymously rather than 404.
		redirect := target
		if isInternalTarget(target) && a.ContactID != "" {
			redirect = withQueryParam(redirect, "rid", a.ContactID)
		}
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// withQueryParam adds or replaces one query parameter without dropping the
// target's own query. raw has already passed ValidateTarget, so a parse error
// is unreachable; returning raw keeps the redirect alive if that ever changes.
func withQueryParam(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Collector) parse(r *http.Request, multipart bool) error {
	if multipart {
		return r.ParseMultipartForm(multipartMemory)
	}
	return r.ParseForm()
}

func (c *Collector) extract(r *http.Request, campaignID, templateID, stepID, target string, step Step) *Artifact {
	a := &Artifact{
		ID:         NewID(),
		CampaignID: campaignID,
		TemplateID: templateID,
		Step:       stepID,
		ReceivedAt: c.now().UTC(),
		RemoteIP:   ClientIP(r, c.cfg.TrustedProxies),
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Query:      r.URL.Query(),
		Headers:    c.headers(r.Header),
		Cookies:    requestCookies(r),
		Fields:     make(map[string]string, len(r.PostForm)),
		Secrets:    make(map[string]Secret),
		Target:     target,
	}
	if c.cfg.EdgeHeader != "" {
		a.Edge = strings.TrimSpace(r.Header.Get(c.cfg.EdgeHeader))
	}

	// The template carries rid in the form action's query string. Validate it
	// against this campaign before storing it, but never let a bad or stale
	// recipient link cost the artifact: the submission is the evidence.
	if rid := r.URL.Query().Get("rid"); rid != "" {
		a.ContactID = c.resolveContact(r.Context(), campaignID, rid, a.ID)
	}

	for name, values := range r.PostForm {
		if name == FingerprintField {
			continue
		}
		var v string
		if len(values) > 0 {
			v = values[0]
		}
		if f, ok := step.Field(name); ok && f.MaxLen > 0 {
			v = truncateRunes(v, f.MaxLen)
		}
		if secret, sensitive := step.Classify(name, v); sensitive {
			a.Secrets[name] = secret
			continue
		}
		a.Fields[name] = v
	}

	if raw := r.PostForm.Get(FingerprintField); raw != "" {
		fp, err := ParseFingerprint(raw)
		if err != nil {
			c.cfg.Logger.Warn("dropped malformed fingerprint", "artifact", a.ID, "err", err)
		} else {
			a.Fingerprint = fp
		}
	}

	if r.MultipartForm != nil {
		for name, headers := range r.MultipartForm.File {
			for _, fh := range headers {
				meta, err := describeFile(name, fh)
				if err != nil {
					c.cfg.Logger.Warn("unreadable upload", "field", name, "artifact", a.ID, "err", err)
					continue
				}
				a.Files = append(a.Files, meta)
			}
		}
	}

	return a
}

// resolveContact returns rid only when the configured lookup confirms it
// belongs to campaignID. Missing resolver, lookup error and unknown contact
// all return "" with a log line, so the caller still stores the artifact.
func (c *Collector) resolveContact(ctx context.Context, campaignID, rid, artifactID string) string {
	if c.cfg.ResolveContact == nil {
		return ""
	}
	// Detach like the insert below: a visitor closing the tab must not cancel
	// the lookup and cost the artifact its attribution while the artifact
	// itself survives. The 2 s bound still applies.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), contactTimeout)
	defer cancel()

	ok, err := c.cfg.ResolveContact(ctx, campaignID, rid)
	if err != nil {
		c.cfg.Logger.Warn("contact resolution failed; storing artifact without contact",
			"artifact", artifactID, "campaign", campaignID, "contact", rid, "err", err)
		return ""
	}
	if !ok {
		c.cfg.Logger.Warn("unknown contact on submission; storing artifact without contact",
			"artifact", artifactID, "campaign", campaignID, "contact", rid)
		return ""
	}
	return rid
}

// validateUploads enforces the server half of a file field's accept list. The
// browser applies accept as a picker filter only, so an unsupported extension
// would still reach describeFile without this check. An empty accept list is
// the explicit "accept any file" case and skips the field.
func validateUploads(step Step, r *http.Request) error {
	if r.MultipartForm == nil {
		return nil
	}
	for name, headers := range r.MultipartForm.File {
		f, ok := step.Field(name)
		if !ok || f.Kind != KindFile || len(f.Accept) == 0 {
			continue
		}
		for _, fh := range headers {
			if !acceptedExtension(fh.Filename, f.Accept) {
				return fmt.Errorf("field %q: file %q is not one of %s",
					name, sanitizeFilename(fh.Filename), strings.Join(f.Accept, ", "))
			}
		}
	}
	return nil
}

// acceptedExtension compares the basename's extension case-insensitively
// against the configured list. Path components are stripped exactly as they
// are for the stored name, so "..\\evil\\cert.p12" is still a .p12. The
// configured list is lowercase (enforced at boot), so only the filename's
// extension needs to be lowercased before comparison.
func acceptedExtension(name string, accept []string) bool {
	base := filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	// filepath.Ext preserves the original case ("cert.P12" → ".P12"); lower
	// it so an uppercase client extension matches the lowercase config list.
	ext := strings.ToLower(filepath.Ext(base))
	if ext == "" {
		return false
	}
	for _, want := range accept {
		// want is already lowercase (boot validation), but be defensive.
		if ext == strings.ToLower(want) {
			return true
		}
	}
	return false
}

// describeFile keeps evidence, not payload: a certificate or signature is
// identified by its digest, and the bytes never enter the database.
func describeFile(field string, fh *multipart.FileHeader) (FileMeta, error) {
	f, err := fh.Open()
	if err != nil {
		return FileMeta{}, err
	}
	defer f.Close()

	h := sha256.New()
	// The request body is already capped by MaxBytesReader to MaxBody or
	// MaxMultipart, so reading the part to EOF cannot exceed the budget.
	// Bounding it here again with the package default would silently hash
	// only the prefix when an operator raises MaxMultipart above 8 MiB,
	// storing a digest and a size that do not describe the uploaded file.
	n, err := io.Copy(h, f)
	if err != nil {
		return FileMeta{}, err
	}
	return FileMeta{
		Field:       field,
		Filename:    sanitizeFilename(fh.Filename),
		Size:        n,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		ContentType: fh.Header.Get("Content-Type"),
	}, nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	clean := make([]rune, 0, len(name))
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		clean = append(clean, r)
	}
	if len(clean) > 128 {
		clean = clean[:128]
	}
	return string(clean)
}

func (c *Collector) headers(h http.Header) map[string][]string {
	deny := make(map[string]struct{}, len(c.cfg.HeaderDeny))
	for _, k := range c.cfg.HeaderDeny {
		deny[http.CanonicalHeaderKey(k)] = struct{}{}
	}
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		if _, drop := deny[k]; drop {
			continue
		}
		switch k {
		case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie":
			continue // recorded structurally, not as raw header text
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func requestCookies(r *http.Request) []Cookie {
	cs := r.Cookies()
	if len(cs) == 0 {
		return nil
	}
	out := make([]Cookie, 0, len(cs))
	for _, ck := range cs {
		out = append(out, Cookie{Name: ck.Name, Value: ck.Value})
	}
	return out
}

func isMultipart(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")
}

// truncateRunes cuts to at most max runes on a boundary. Slicing by byte
// length would split a multi-byte sequence and store invalid UTF-8.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}
