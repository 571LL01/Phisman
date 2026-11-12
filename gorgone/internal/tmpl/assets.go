package tmpl

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// embeddedAssetTime is fixed because embed.FS files carry no modification
// time. It makes Last-Modified deterministic across requests and restarts; a
// deployment can override it at link time with its release timestamp.
var embeddedAssetTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

//go:embed assets/default
var defaultAssets embed.FS

// DefaultTemplate is the built-in presentation used until a later layer loads
// operator-authored variants. The Variants slice is rebuilt on every call so a
// caller cannot mutate another template's data.
func DefaultTemplate() Template {
	sub, err := fs.Sub(defaultAssets, "assets/default")
	if err != nil {
		// The path is a compile-time constant and //go:embed guarantees it.
		panic("tmpl: embedded default assets: " + err.Error())
	}
	return Template{
		Variants: defaultVariants(),
		Assets:   sub,
	}
}

func defaultVariants() []Variant {
	return []Variant{
		{
			Lang:     "fr",
			Title:    "Connexion sécurisée",
			Heading:  "Connexion",
			Greeting: "Bonjour",
			Intro:    "Veuillez confirmer vos informations pour continuer.",
			Submit:   "Continuer",
			Note:     "Vos informations sont chiffrées.",
		},
		{
			Lang:     "de",
			Title:    "Sichere Anmeldung",
			Heading:  "Anmeldung",
			Greeting: "Hallo",
			Intro:    "Bitte bestätigen Sie Ihre Angaben, um fortzufahren.",
			Submit:   "Weiter",
			Note:     "Ihre Angaben sind verschlüsselt.",
		},
	}
}

// AssetsHandler serves /assets/{campaign}/{template}/{file}.
//
// The handler is registered behind cmd/sirencore's dot-segment guard because
// ServeMux cleans a literal /assets/c/t/../x with a 307 before any handler can
// see it; the gate requires a 404. This handler still re-validates the file
// segment, so an encoded traversal that reaches PathValue is rejected too.
func (r *Renderer) AssetsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		coord := Coord{
			Campaign: req.PathValue("campaign"),
			Template: req.PathValue("template"),
		}
		t, ok := r.templates[coord]
		if !ok || t.Assets == nil {
			http.NotFound(w, req)
			return
		}
		files, ok := r.files[coord]
		if !ok {
			http.NotFound(w, req)
			return
		}

		name := req.PathValue("file")
		if !validAssetName(name) {
			http.NotFound(w, req)
			return
		}

		f, err := t.Assets.Open(name)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		info, err := f.Stat()
		if err != nil || info.IsDir() {
			f.Close()
			http.NotFound(w, req)
			return
		}
		// The digest must be computed before FileServerFS writes headers. It is
		// a content hash, so two requests for the same file always agree.
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			http.NotFound(w, req)
			return
		}
		sum := sha256.Sum256(data)

		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
		w.Header().Set("Last-Modified", embeddedAssetTime.UTC().Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// FileServerFS resolves the name against Path, so the clone carries a
		// root-relative path inside the per-template FS. RawPath is cleared to
		// keep the decoded, already validated name authoritative.
		clone := req.Clone(req.Context())
		u := *req.URL
		u.Path = "/" + name
		u.RawPath = ""
		clone.URL = &u
		files.ServeHTTP(w, clone)
	})
}

// validAssetName accepts exactly one flat file name inside the template FS.
// path separators, dot segments and empty names are refused before Open, so
// http.FileServerFS never sees a traversal attempt.
func validAssetName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if path.Base(name) != name || !fs.ValidPath(name) {
		return false
	}
	return true
}
