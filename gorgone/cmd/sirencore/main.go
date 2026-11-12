package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/siren-core/gorgone/internal/admin"
	"github.com/siren-core/gorgone/internal/charon"
	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/lethe"
	"github.com/siren-core/gorgone/internal/mgmt"
	"github.com/siren-core/gorgone/internal/store"
	"github.com/siren-core/gorgone/internal/tmpl"
)

type stepConfig struct {
	Target string        `json:"target"`
	Mode   string        `json:"mode"`
	Token  string        `json:"beacon_token"`
	Fields []fieldConfig `json:"fields"`
}

type fieldConfig struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Secret bool              `json:"secret"`
	MaxLen int               `json:"max_len"`
	Accept []string          `json:"accept"`
	Labels map[string]string `json:"labels"`
}

type campaignConfig struct {
	Templates map[string]map[string]stepConfig `json:"templates"`
}

type fileConfig struct {
	Listen          string                    `json:"listen"`
	DataDir         string                    `json:"data_dir"`
	BeaconPrefix    string                    `json:"beacon_prefix"`
	AllowHTTPTarget bool                      `json:"allow_http_target"`
	TrustedProxies  []string                  `json:"trusted_proxies"`
	Campaigns       map[string]campaignConfig `json:"campaigns"`
	Admin           *adminFileConfig          `json:"admin"`

	// trusted is derived from TrustedProxies by validate. It is the only form
	// the collector consumes, so the strings are parsed exactly once, at boot.
	trusted []*net.IPNet
}

type options struct {
	configPath  string
	dbPath      string
	rotateKeys  bool
	retireKey   int
	export      string
	since       string
	issueToken  string
	healthcheck bool
}

func main() {
	var opts options
	flag.StringVar(&opts.configPath, "config", "config.json", "deployment config")
	flag.StringVar(&opts.dbPath, "db", "", "sqlite path (default <data_dir>/artifacts.db)")
	flag.BoolVar(&opts.rotateKeys, "rotate-keys", false, "re-seal every row with the active key and exit")
	flag.IntVar(&opts.retireKey, "retire-key", 0, "retire a key id (1..255) after verifying no row carries it")
	flag.StringVar(&opts.export, "export", "", "export one campaign as JSON Lines to stdout and exit")
	flag.StringVar(&opts.since, "since", "", "with -export: RFC 3339 lower bound, exclusive")
	flag.StringVar(&opts.issueToken, "issue-token", "", "issue an export token for a campaign, print it once, and exit")
	flag.BoolVar(&opts.healthcheck, "healthcheck", false, "probe /healthz on the configured listen address and exit 0/1")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// -healthcheck probes /healthz on the listen address and exits without
	// opening the database or loading keys. The Docker healthcheck uses this
	// instead of wget (absent from the scratch image).
	if opts.healthcheck {
		os.Exit(runHealthcheck(opts.configPath))
	}

	if err := run(logger, opts); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(exitCodeFor(err))
	}
}

// exitCodeFor makes the "startup failure is non-zero" contract testable without
// spawning a subprocess. Every boot error is fatal; nothing is a warning.
func exitCodeFor(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func run(logger *slog.Logger, opts options) error {
	// Convert once, before touching config, keys or the database. byte(300)
	// would silently become 44 and retire the wrong key.
	var retireID byte
	if opts.retireKey != 0 {
		id, err := retireKeyID(opts.retireKey)
		if err != nil {
			return err
		}
		retireID = id
	}

	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return err
	}

	// SIREN_DEV=1 disables admin CSRF and may allow an empty admin allowlist.
	// Pairing it with a durable key file would run the development admin posture
	// against production data. Refuse before the key file is read so the failure
	// cannot be mistaken for a key-material problem.
	if admin.DevMode() && os.Getenv("SIREN_KEY_FILE") != "" {
		return errors.New("SIREN_DEV=1 must not be combined with SIREN_KEY_FILE: " +
			"development mode requires the environment keyset (SIREN_DEV_KEYS=1) and a disposable database")
	}

	keys, keyPath, err := loadKeys()
	if err != nil {
		return err
	}
	if keyPath != "" {
		if err := collect.GuardKeyLocation(keyPath, cfg.DataDir); err != nil {
			return err
		}
	}

	dbPath := resolveDBPath(opts.dbPath, cfg.DataDir)
	// The directory that must be private is the one receiving the database.
	// With -db it is not data_dir, so checking data_dir would secure the wrong
	// tree and leave artifacts.db in a world-traversable parent.
	if err := ensureDataDir(filepath.Dir(dbPath)); err != nil {
		return err
	}
	handle, err := sirendb.Open("file:" + dbPath)
	if err != nil {
		return err
	}
	defer handle.Close()

	st, err := collect.NewSQLiteFrom(handle.DB, keys)
	if err != nil {
		return err
	}

	// The operational schema is migrated and version-checked at boot even
	// before its first consumer exists: an older binary must refuse a file
	// written by a newer one. The store is stateless over the shared handle.
	ops, err := store.New(handle.DB)
	if err != nil {
		return err
	}

	switch {
	case opts.rotateKeys:
		return rotate(st, keys, logger)
	case opts.retireKey != 0:
		return retire(st, keys, keyPath, retireID, logger)
	case opts.issueToken != "":
		return issueExportToken(ops, opts.issueToken)
	case opts.export != "":
		return exportCampaign(st, opts.export, opts.since)
	}

	logger.Info("keyset loaded", "active", keys.Active(), "known", keys.IDs())

	// Admin secrets are file-backed and read only in server mode. The CLI
	// branches above must keep working on a host where /run/secrets is not
	// mounted.
	adminCfg, err := loadAdminSecrets(cfg, handle.DB, logger)
	if err != nil {
		return err
	}
	if adminCfg != nil {
		logger.Info("admin interface mounted",
			"allowlist", len(cfg.Admin.Allowlist), "rate_limit", adminCfg.RateLimit,
			"dev_mode", admin.DevMode())
	}

	var mgmtDeps *mgmt.Deps
	if adminCfg != nil {
		d := buildMgmtDeps(adminCfg, ops, st, handle.DB, cfg, logger)
		mgmtDeps = &d
	}

	handler, err := newHandlerWithAdmin(cfg, st, ops, logger, adminCfg, mgmtDeps)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, ln, handler, logger)
}

// runHealthcheck loads only the listen address from config and probes /healthz.
// It returns 0 on a 200 response and 1 on any failure. It is used as the
// Docker HEALTHCHECK CMD so the scratch image does not need an external tool.
func runHealthcheck(configPath string) int {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: load config: %v\n", err)
		return 1
	}
	addr := cfg.Listen
	if addr == "" {
		fmt.Fprintln(os.Stderr, "healthcheck: listen address is empty")
		return 1
	}
	// Resolve 0.0.0.0 to 127.0.0.1 for the probe.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad listen address %q: %v\n", addr, err)
		return 1
	}
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// resolveDBPath picks the SQLite file: an explicit -db wins, otherwise the file
// lives under data_dir.
func resolveDBPath(override, dataDir string) string {
	if override != "" {
		return override
	}
	return filepath.Join(dataDir, "artifacts.db")
}

// ensureDataDir creates the directory that will hold artifacts.db, or verifies
// an existing one. SQLite does not create parent directories, and the database
// contains personal data, so a missing parent must not surface as an obscure
// "unable to open database file" and an existing one must not be world-readable.
func ensureDataDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("data_dir %q is not a directory", path)
		}
		return checkDataDirMode(path, info)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("data_dir %q: %w", path, err)
	}

	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("data_dir %q: %w", path, err)
	}
	if err := enforceDataDirMode(path); err != nil {
		return fmt.Errorf("data_dir %q: %w", path, err)
	}
	info, err = os.Stat(path)
	if err != nil {
		return fmt.Errorf("data_dir %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("data_dir %q is not a directory", path)
	}
	return checkDataDirMode(path, info)
}

// retireKeyID rejects anything that is not a key ID representable in one byte.
func retireKeyID(v int) (byte, error) {
	if v < 1 || v > 255 {
		return 0, fmt.Errorf("retire-key must be between 1 and 255, got %d", v)
	}
	return byte(v), nil
}

func rotate(st collect.Store, keys *collect.KeySet, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	n, err := st.Rotate(ctx)
	if err != nil {
		return err
	}
	logger.Info("rotate complete", "rows", n, "active_key", keys.Active())
	return nil
}

func retire(st collect.Store, keys *collect.KeySet, keyPath string, id byte, logger *slog.Logger) error {
	if keyPath == "" {
		return errors.New("retire requires SIREN_KEY_FILE; the env keyset is dev-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := st.RetireKey(ctx, id); err != nil {
		return err
	}
	next, err := keys.Without(id)
	if err != nil {
		return err
	}
	if err := collect.SaveKeyFile(keyPath, next); err != nil {
		return err
	}
	logger.Info("key retired", "id", id, "remaining", next.IDs())
	return nil
}

func issueExportToken(tokens charon.TokenStore, campaignID string) error {
	token, err := charon.IssueToken(context.Background(), tokens, campaignID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, token)
	return err
}

// exportCampaign writes to stdout as it goes. A decryption failure is returned
// to run, which logs it and exits non-zero; rows already written stay visible
// so the operator can resume with -since.
func exportCampaign(src charon.Source, campaignID, sinceRaw string) error {
	since, err := charon.ParseSince(sinceRaw)
	if err != nil {
		return err
	}
	_, err = charon.Export(context.Background(), src, campaignID, since, os.Stdout, nil)
	return err
}

// contactLoader is the slice of store.Store the render path needs. Keeping it
// narrow lets a consumer provide personalized pages without owning the whole
// operational store. opsStore adds the export token surface charon needs.
type contactLoader interface {
	GetContact(ctx context.Context, campaignID, contactID string) (*store.Contact, error)
}

type opsStore interface {
	contactLoader
	charon.TokenStore
	ListCampaigns(ctx context.Context) ([]store.Campaign, error)
	// RecordEvent persists an open/click tracking event. The render and pixel
	// paths use it to fill the funnel stages that precede a submission.
	RecordEvent(ctx context.Context, in store.EventInput) error
}

// newHandler is the whole routing surface in one place, so a test can exercise
// the wiring without starting a process. validate is idempotent and called here
// as well as from loadConfig so the invariant does not depend on the CLI path.
func newHandler(cfg *fileConfig, st collect.Store, ops opsStore, logger *slog.Logger) (http.Handler, error) {
	return newHandlerWithAdmin(cfg, st, ops, logger, nil, nil)
}

// newHandlerWithAdmin mounts the admin surface when adminCfg is non-nil. When
// mgmtDeps is also non-nil the management UI replaces the read-only dashboard.
// It deliberately does not call adminCfg.Validate: the admin.Guard re-validates
// on every request and returns 500 on a Config that skipped or broke the boot
// gate. Boot validation belongs to loadAdminSecrets.
func newHandlerWithAdmin(cfg *fileConfig, st collect.Store, ops opsStore, logger *slog.Logger, adminCfg *admin.Config, mgmtDeps *mgmt.Deps) (http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if ops == nil {
		return nil, errors.New("contacts store is required")
	}

	resolve := resolver(cfg)
	collector, err := collect.New(collect.Config{
		Resolve:         resolve,
		TrustedProxies:  cfg.trusted,
		EdgeHeader:      "Cf-Ray",
		BeaconPrefix:    cfg.BeaconPrefix,
		AllowHTTPTarget: cfg.AllowHTTPTarget,
		Logger:          logger,
		ResolveContact: func(ctx context.Context, campaignID, contactID string) (bool, error) {
			_, err := ops.GetContact(ctx, campaignID, contactID)
			if errors.Is(err, store.ErrContactNotFound) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			return true, nil
		},
	}, st)
	if err != nil {
		return nil, err
	}

	templates := make(map[tmpl.Coord]tmpl.Template)
	for campaignID, campaign := range cfg.Campaigns {
		for templateID, steps := range campaign.Templates {
			t, err := buildTemplate(templateID, steps)
			if err != nil {
				return nil, fmt.Errorf("campaign %q template %q: %w", campaignID, templateID, err)
			}
			templates[tmpl.Coord{Campaign: campaignID, Template: templateID}] = t
		}
	}
	renderer, err := tmpl.New(templates)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc(collector.BeaconPattern(), collector.BeaconHandler())
	mux.HandleFunc(openPixelPattern(cfg.BeaconPrefix), openPixelHandler(ops, resolve, cfg.trusted, logger))
	mux.Handle(tmpl.AssetsPrefix+"/{campaign}/{template}/{file}", renderer.AssetsHandler())
	mux.Handle(charon.ExportPrefix+"/{campaign}", charon.NewHandler(st, ops, logger))
	mux.HandleFunc("/c/{campaign}/{template}/{step}", func(w http.ResponseWriter, r *http.Request) {
		campaignID := r.PathValue("campaign")
		templateID := r.PathValue("template")
		stepID := r.PathValue("step")

		switch r.Method {
		case http.MethodPost:
			collector.Capture(campaignID, templateID, stepID)(w, r)
		case http.MethodGet:
			step, err := resolve(campaignID, templateID, stepID)
			if err != nil {
				// A GET is a visitor, not an operator. An unknown coordinate
				// must look like every other missing page.
				http.NotFound(w, r)
				return
			}

			// rid is the recipient identifier embedded in the delivered link.
			// Without it the page is still renderable (preview, first visit),
			// but no contact vars are injected. With it, the lookup is scoped
			// to this campaign so an ID from another campaign cannot pull
			// someone else's data into this page.
			rid := r.URL.Query().Get("rid")
			var vars tmpl.Vars
			if rid != "" {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				contact, err := ops.GetContact(ctx, campaignID, rid)
				cancel()
				switch {
				case errors.Is(err, store.ErrContactNotFound), errors.Is(err, store.ErrCampaignNotFound):
					http.NotFound(w, r)
					return
				case err != nil:
					logger.Error("contact lookup failed",
						"campaign", campaignID, "contact", rid, "err", err)
					http.Error(w, "unavailable", http.StatusInternalServerError)
					return
				}
				vars = tmpl.Vars(contact.Vars)

				// A GET with a resolved recipient is a click: the target
				// followed the delivered link and the page loaded. Record it
				// best-effort on a detached context so a visitor who navigates
				// away immediately still counts, and a storage hiccup never
				// changes what the page renders.
				evCtx, evCancel := context.WithTimeout(context.WithoutCancel(r.Context()), trackingTimeout)
				if err := ops.RecordEvent(evCtx, store.EventInput{
					CampaignID: campaignID,
					ContactID:  rid,
					TemplateID: templateID,
					StepID:     stepID,
					Kind:       store.EventClick,
					RemoteIP:   collect.ClientIP(r, cfg.trusted),
					UserAgent:  r.Header.Get("User-Agent"),
				}); err != nil {
					logger.Error("click event persist failed",
						"campaign", campaignID, "contact", rid, "err", err)
				}
				evCancel()
			}

			// The renderer template map is keyed by the config campaign ID
			// (e.g. "acme"), not by the DB campaign UUID in the URL. Translate
			// so the lookup succeeds regardless of which form is in the link.
			renderCampaignID := findConfigCampaignID(cfg, campaignID, templateID)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if err := renderer.Render(w, tmpl.Page{
				Campaign:     renderCampaignID,
				Template:     templateID,
				Step:         stepID,
				ContactID:    rid,
				LinkCampaign: campaignID,
			}, step, vars, r.Header.Get("Accept-Language"), r.URL.Query().Get("l")); err != nil {
				logger.Error("render failed",
					"campaign", campaignID, "template", templateID, "step", stepID, "err", err)
				http.Error(w, "unavailable", http.StatusInternalServerError)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	if adminCfg != nil {
		var adminRouter http.Handler
		if mgmtDeps != nil {
			// Full management UI: combined router handles auth + all /admin/* pages.
			adminRouter = newCombinedAdminRouter(*adminCfg, mgmt.New(*mgmtDeps))
		} else {
			// Fallback: read-only dashboard (used by tests that pass nil mgmtDeps).
			adminRouter = admin.Router(*adminCfg, adminCampaignLister(ops))
		}
		// Register both forms: "/admin" is an exact pattern, "/admin/" a
		// subtree. Guard wraps the router, not the mux, so every admin path
		// goes through one fail-closed check, including unknown /admin/*.
		mux.Handle("/admin", adminRouter)
		mux.Handle("/admin/", adminRouter)
	}
	// ServeMux cleans a literal /assets/c/t/../x with a 307 before the assets
	// handler can see it. The contract is 404, so the guard runs first.
	return rejectAssetsDotSegments(mux), nil
}

// buildTemplate binds a config template to its built-in presentation. An
// unknown ID keeps the generic default template so older deployments keep
// working; a known ID must declare every configured step and every field label
// for every shipped language, because the branded flow cannot silently fall
// back to a technical field name.
func buildTemplate(templateID string, steps map[string]stepConfig) (tmpl.Template, error) {
	def, ok := lethe.Lookup(templateID)
	if !ok {
		return tmpl.DefaultTemplate(), nil
	}

	// A built-in flow uses one step per screen. Repeating a field on a later
	// step would ask the visitor to submit the same value twice and would
	// store the second answer under the same name; the flow contract is that
	// a confirmation step introduces no field from the previous screen.
	if err := rejectRepeatedFields(steps); err != nil {
		return tmpl.Template{}, err
	}

	t := tmpl.Template{
		Assets: def.Assets,
		Steps:  make(map[string][]tmpl.Variant, len(steps)),
	}
	for stepID, sc := range steps {
		variants, ok := def.Steps[stepID]
		if !ok {
			return tmpl.Template{}, fmt.Errorf("no presentation for step %q", stepID)
		}
		merged, err := mergeLabels(variants, sc.Fields)
		if err != nil {
			return tmpl.Template{}, fmt.Errorf("step %q: %w", stepID, err)
		}
		t.Steps[stepID] = merged
	}
	if err := validateSummaries(t.Steps, steps); err != nil {
		return tmpl.Template{}, err
	}
	return t, nil
}

// validateSummaries keeps a confirmation step from recalling a value the flow
// treats as secret. A summary is read-only, but showing an OTP or an IBAN on
// screen would defeat the kind that hashed it.
func validateSummaries(variants map[string][]tmpl.Variant, steps map[string]stepConfig) error {
	declared := make(map[string]fieldConfig)
	for _, sc := range steps {
		for _, f := range sc.Fields {
			declared[strings.ToLower(f.Name)] = f
		}
	}

	for stepID, set := range variants {
		for _, v := range set {
			if v.SummaryField == "" {
				continue
			}
			f, ok := declared[strings.ToLower(v.SummaryField)]
			if !ok {
				return fmt.Errorf("step %q lang %q: summary field %q is not declared in this template", stepID, v.Lang, v.SummaryField)
			}
			if f.Secret || collect.Kind(f.Kind).Classified() {
				return fmt.Errorf("step %q lang %q: summary field %q is secret and cannot be recalled", stepID, v.Lang, v.SummaryField)
			}
		}
	}
	return nil
}

// rejectRepeatedFields refuses a field name that appears on two steps of the
// same built-in template. Step IDs are sorted so the error names the same pair
// on every boot when a config declares the mistake more than once.
func rejectRepeatedFields(steps map[string]stepConfig) error {
	ids := make([]string, 0, len(steps))
	for id := range steps {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	seen := make(map[string]string)
	for _, id := range ids {
		for _, f := range steps[id].Fields {
			key := strings.ToLower(f.Name)
			if prev, dup := seen[key]; dup {
				return fmt.Errorf("field %q is declared in steps %q and %q", f.Name, prev, id)
			}
			seen[key] = id
		}
	}
	return nil
}

// mergeLabels copies the template variants and attaches the operator's label
// for each field. A label language the template does not ship is a typo, not a
// harmless extra: it would never be selected, so boot refuses it.
func mergeLabels(variants []tmpl.Variant, fields []fieldConfig) ([]tmpl.Variant, error) {
	shipped := make(map[string]struct{}, len(variants))
	for _, v := range variants {
		shipped[v.Lang] = struct{}{}
	}
	for _, f := range fields {
		for lang := range f.Labels {
			if _, ok := shipped[lang]; !ok {
				return nil, fmt.Errorf("field %q: label language %q is not shipped by this template", f.Name, lang)
			}
		}
	}

	out := make([]tmpl.Variant, 0, len(variants))
	for _, v := range variants {
		labels := make(map[string]string, len(v.Labels)+len(fields))
		for name, text := range v.Labels {
			labels[name] = text
		}
		for _, f := range fields {
			label := f.Labels[v.Lang]
			if label == "" {
				return nil, fmt.Errorf("field %q: missing label for variant %q", f.Name, v.Lang)
			}
			labels[strings.ToLower(f.Name)] = label
		}
		v.Labels = labels
		out = append(out, v)
	}
	return out, nil
}

// rejectAssetsDotSegments turns every upward path under the assets route into a
// 404, including one encoded as ..%2f that decodes to a dot segment.
func rejectAssetsDotSegments(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, tmpl.AssetsPrefix+"/") && hasDotSegment(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hasDotSegment(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// healthHandler is a liveness probe: it proves the process and mux are serving,
// not that SQLite is writable. A failing disk must not restart-loop the edge.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// serve runs until the context is cancelled, then shuts down gracefully.
// Accepting a listener rather than an address is what makes it testable on an
// ephemeral port.
func serve(ctx context.Context, ln net.Listener, h http.Handler, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	logger.Info("listening", "addr", ln.Addr().String())

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

func loadConfig(path string) (*fileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Strict decoding is part of the config contract: a mistyped
	// "trusted_proxies" would otherwise leave the list empty and silently
	// disable origin resolution, which is the exact bug this field fixes.
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var cfg fileConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("config: multiple JSON values")
		}
		return nil, fmt.Errorf("config: trailing data: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate closes every string field that the resolver would otherwise trust
// blindly. A typo must stop the process, not fall back to a permissive default.
func (c *fileConfig) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if len(c.Campaigns) == 0 {
		return errors.New("campaigns is required")
	}
	if err := validateBeaconPrefix(c.BeaconPrefix); err != nil {
		return err
	}
	if err := validateAssetsRoute(c.BeaconPrefix); err != nil {
		return err
	}
	if err := validateExportRoute(c.BeaconPrefix); err != nil {
		return err
	}
	if err := c.Admin.validate(); err != nil {
		return err
	}

	trusted, bad := collect.ParseCIDRs(c.TrustedProxies)
	if len(bad) > 0 {
		return fmt.Errorf("trusted_proxies: %w", errors.Join(bad...))
	}
	c.trusted = trusted

	// Beacon tokens are URL path segments and identify a step in the beacon
	// route. Two steps sharing one token would make the endpoint ambiguous.
	tokens := make(map[string]string)

	for campaignID, campaign := range c.Campaigns {
		for templateID, steps := range campaign.Templates {
			for stepID, sc := range steps {
				where := fmt.Sprintf("campaign %q template %q step %q", campaignID, templateID, stepID)

				target, err := collect.ValidateTarget(sc.Target, c.AllowHTTPTarget)
				if err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
				sc.Target = target

				switch sc.Mode {
				case "", "inline":
					sc.Mode = "inline"
				case "beacon":
					if sc.Token == "" {
						return fmt.Errorf("%s: beacon_token is required in beacon mode", where)
					}
					if len(sc.Token) > 64 {
						return fmt.Errorf("%s: beacon_token exceeds 64 bytes", where)
					}
					if url.PathEscape(sc.Token) != sc.Token {
						return fmt.Errorf("%s: beacon_token must be a single URL path segment", where)
					}
					if prev, dup := tokens[sc.Token]; dup {
						return fmt.Errorf("%s: beacon_token %q is already used by %s", where, sc.Token, prev)
					}
					tokens[sc.Token] = where
				default:
					return fmt.Errorf("%s: mode %q is not one of inline, beacon", where, sc.Mode)
				}

				seen := make(map[string]string, len(sc.Fields))
				for i := range sc.Fields {
					f := &sc.Fields[i]
					if strings.TrimSpace(f.Name) == "" {
						return fmt.Errorf("%s: field %d: name is required", where, i)
					}
					if !validFieldName(f.Name) {
						return fmt.Errorf("%s: field %q: name must match [A-Za-z0-9_.-]+", where, f.Name)
					}
					// extract drops this exact name before classification, so
					// a declared field with it is rendered but never stored.
					// Field lookup is case-insensitive, so reserve every case.
					if strings.EqualFold(f.Name, collect.FingerprintField) {
						return fmt.Errorf("%s: field %q is reserved for the fingerprint", where, f.Name)
					}
					// Step.Field compares with EqualFold, so "Email" and
					// "email" address the same runtime field. Duplicate
					// detection must use the same equivalence.
					key := strings.ToLower(f.Name)
					if prev, dup := seen[key]; dup {
						return fmt.Errorf("%s: duplicate field %q (also declared as %q)", where, f.Name, prev)
					}
					seen[key] = f.Name
					if f.MaxLen < 0 {
						return fmt.Errorf("%s: field %q: max_len must not be negative", where, f.Name)
					}
					// A seed is a recovery phrase: a truncated phrase cannot
					// restore the wallet. The body limit still bounds it, but
					// no rune count may silently cut it.
					if collect.Kind(f.Kind) == collect.KindSeed && f.MaxLen > 0 {
						return fmt.Errorf("%s: field %q: kind seed must not set max_len; a truncated phrase is unrecoverable", where, f.Name)
					}
					if !validKind(f.Kind) {
						return fmt.Errorf("%s: field %q: kind %q is not one of text, password, otp, iban, pan, seed, file",
							where, f.Name, f.Kind)
					}
					if len(f.Accept) > 0 {
						if collect.Kind(f.Kind) != collect.KindFile {
							return fmt.Errorf("%s: field %q: accept is only valid for a file field", where, f.Name)
						}
						accept := make([]string, 0, len(f.Accept))
						seenAccept := make(map[string]struct{}, len(f.Accept))
						for _, raw := range f.Accept {
							// Normalize to lowercase: config tokens are compared
							// to strings.ToLower(filepath.Ext(filename)) at
							// capture time, so ".JPG" and ".jpg" are equivalent.
							// Normalizing here rather than rejecting lets
							// operators write either case without a boot error.
							ext := strings.ToLower(strings.TrimSpace(raw))
							if !validAcceptExtension(ext) {
								return fmt.Errorf("%s: field %q: accept %q is not an extension like .p12", where, f.Name, raw)
							}
							if _, dup := seenAccept[ext]; dup {
								return fmt.Errorf("%s: field %q: accept %q is listed twice", where, f.Name, ext)
							}
							seenAccept[ext] = struct{}{}
							accept = append(accept, ext)
						}
						if len(accept) > 16 {
							return fmt.Errorf("%s: field %q: accept has %d extensions; maximum is 16", where, f.Name, len(accept))
						}
						f.Accept = accept
					}
					// data-secret is emitted from the kind, never from a
					// template annotation. A manual secret flag is only
					// legitimate when it agrees with a classified kind.
					if f.Secret && !collect.Kind(f.Kind).Classified() {
						return fmt.Errorf("%s: field %q: secret requires a classified kind, got %q", where, f.Name, f.Kind)
					}
					// A field named otp/password/token declared as visible
					// text would render in clear and be stored unhashed. The
					// name heuristic is the only signal left, so boot refuses
					// the contradiction instead of trusting the declaration.
					if collect.Kind(f.Kind) == collect.KindText {
						if kind, ok := collect.KindForName(f.Name); ok {
							return fmt.Errorf("%s: field %q: name implies the secret kind %q; declare kind %q instead of text",
								where, f.Name, kind, kind)
						}
					}

					if len(f.Labels) > 0 {
						labels := make(map[string]string, len(f.Labels))
						for lang, text := range f.Labels {
							tag := strings.ToLower(strings.TrimSpace(lang))
							if !tmpl.ValidLanguage(tag) {
								return fmt.Errorf("%s: field %q: label language %q is not a lowercase tag", where, f.Name, lang)
							}
							if _, dup := labels[tag]; dup {
								return fmt.Errorf("%s: field %q: duplicate label language %q", where, f.Name, tag)
							}
							text = strings.TrimSpace(text)
							if text == "" {
								return fmt.Errorf("%s: field %q: label %q is empty", where, f.Name, tag)
							}
							labels[tag] = text
						}
						f.Labels = labels
					}
				}

				steps[stepID] = sc
			}
		}
	}
	return nil
}

func validKind(k string) bool {
	switch collect.Kind(k) {
	case collect.KindText, collect.KindPassword, collect.KindOTP,
		collect.KindIBAN, collect.KindPAN, collect.KindSeed, collect.KindFile:
		return true
	default:
		return false
	}
}

// validAcceptExtension accepts a dotted file extension, never a MIME type or a
// path: the value is rendered into an attribute and compared to filepath.Ext.
func validAcceptExtension(ext string) bool {
	if len(ext) < 2 || len(ext) > 16 || ext[0] != '.' {
		return false
	}
	for i := 1; i < len(ext); i++ {
		c := ext[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// validFieldName restricts a field name to the ASCII class that is safe in
// every place it is reused: Attrs emits id="f-"+Name, the renderer escapes it
// as an attribute value and as text, and operators query it from CSS or JS.
// Space, quotes, angle brackets, %, brackets and non-ASCII all break one of
// those consumers, so they are refused at boot instead of at render time.
func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// validateBeaconPrefix constrains the constant segment used in both the mux
// pattern and the generated beacon URL. An empty value is allowed: collect.New
// applies /__siren. Anything else must be one safe segment, otherwise ServeMux
// parses it as a host, panics on the capture-route conflict, or the emitted URL
// never matches the registered pattern.
func validateBeaconPrefix(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("beacon_prefix %q must begin with /", p)
	}
	if strings.HasSuffix(p, "/") {
		return fmt.Errorf("beacon_prefix %q must not end with /", p)
	}
	seg := p[1:]
	if seg == "" || strings.Contains(seg, "/") {
		return fmt.Errorf("beacon_prefix %q must be a single path segment", p)
	}
	// ServeMux cleans dot segments before matching, so /./... or /../...
	// registers a route no request can ever reach.
	if seg == "." || seg == ".." {
		return fmt.Errorf("beacon_prefix %q must not contain dot segments", p)
	}
	if p == "/c" {
		return errors.New(`beacon_prefix must not be "/c": it conflicts with the capture route`)
	}
	if url.PathEscape(seg) != seg {
		return fmt.Errorf("beacon_prefix %q contains characters that are not safe in a path segment", p)
	}
	return nil
}

// validateAssetsRoute keeps the constant /assets route disjoint from the route
// roots it could collide with. The capture route /c is already refused by
// validateBeaconPrefix; this adds the assets segment and resolves the empty
// prefix to the value collect.New will actually register.
func validateAssetsRoute(beaconPrefix string) error {
	if tmpl.AssetsPrefix == "/c" {
		return errors.New("assets route conflicts with the capture route")
	}
	effective := beaconPrefix
	if effective == "" {
		effective = collect.DefaultBeaconPrefix
	}
	if effective == tmpl.AssetsPrefix {
		return fmt.Errorf("beacon_prefix %q conflicts with the assets route %q", effective, tmpl.AssetsPrefix)
	}
	return nil
}

// validateExportRoute keeps the /export route disjoint from the beacon prefix
// and from /c. The assets check already covers /c for the beacon, but
// beacon_prefix "/export" would silently shadow the export handler in ServeMux
// because a longer pattern wins.
func validateExportRoute(beaconPrefix string) error {
	effective := beaconPrefix
	if effective == "" {
		effective = collect.DefaultBeaconPrefix
	}
	if effective == charon.ExportPrefix {
		return fmt.Errorf("beacon_prefix %q conflicts with the export route %q", effective, charon.ExportPrefix)
	}
	return nil
}

// loadKeys prefers SIREN_KEY_FILE, which lives outside data_dir. The
// environment keyset is accepted only when SIREN_DEV_KEYS=1, so a production
// deployment cannot end up with the key in the process environment by
// accident.
func loadKeys() (*collect.KeySet, string, error) {
	if path := os.Getenv("SIREN_KEY_FILE"); path != "" {
		ks, err := collect.LoadKeyFile(path)
		return ks, path, err
	}
	if os.Getenv("SIREN_DEV_KEYS") != "1" {
		return nil, "", errors.New("SIREN_KEY_FILE is required (SIREN_DEV_KEYS=1 enables the env keyset, dev only)")
	}
	spec := os.Getenv("SIREN_ARTIFACT_KEYS")
	if spec == "" {
		return nil, "", errors.New("SIREN_DEV_KEYS=1 but SIREN_ARTIFACT_KEYS is empty")
	}
	active := byte(1)
	if v := os.Getenv("SIREN_ARTIFACT_ACTIVE_KEY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 255 {
			return nil, "", errors.New("invalid SIREN_ARTIFACT_ACTIVE_KEY")
		}
		active = byte(n)
	}
	ks, err := collect.ParseKeySet(spec, active)
	return ks, "", err
}

// findConfigCampaign returns the config campaign key that owns templateID.
// It first tries a direct match on campaignID, then searches all campaigns.
// This lets phishing links use the DB campaign UUID while still resolving
// templates defined under a human-readable config key (e.g. "acme").
func findConfigCampaign(cfg *fileConfig, campaignID, templateID string) (campaignConfig, bool) {
	if c, ok := cfg.Campaigns[campaignID]; ok {
		return c, true
	}
	for _, c := range cfg.Campaigns {
		if _, ok := c.Templates[templateID]; ok {
			return c, true
		}
	}
	return campaignConfig{}, false
}

// findConfigCampaignID returns the config key string for use with the renderer.
func findConfigCampaignID(cfg *fileConfig, campaignID, templateID string) string {
	if _, ok := cfg.Campaigns[campaignID]; ok {
		return campaignID
	}
	for cfgID, c := range cfg.Campaigns {
		if _, ok := c.Templates[templateID]; ok {
			return cfgID
		}
	}
	return campaignID
}

func resolver(cfg *fileConfig) collect.Resolver {
	return func(campaignID, templateID, stepID string) (collect.Step, error) {
		c, ok := findConfigCampaign(cfg, campaignID, templateID)
		if !ok {
			return collect.Step{}, errors.New("unknown campaign")
		}
		steps, ok := c.Templates[templateID]
		if !ok {
			return collect.Step{}, errors.New("unknown template")
		}
		sc, ok := steps[stepID]
		if !ok {
			return collect.Step{}, errors.New("unknown step")
		}
		step := collect.Step{Target: sc.Target, Mode: collect.ModeInline}
		if sc.Mode == "beacon" {
			step.Mode = collect.ModeBeacon
			step.BeaconToken = sc.Token
		}
		for _, f := range sc.Fields {
			step.Fields = append(step.Fields, collect.Field{
				Name:   f.Name,
				Kind:   collect.Kind(f.Kind),
				Secret: f.Secret,
				MaxLen: f.MaxLen,
				Accept: append([]string(nil), f.Accept...),
			})
		}
		return step, nil
	}
}
