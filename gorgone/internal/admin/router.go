package admin

import (
	"net/http"
	"strings"
)

// Guard is the single fail-closed middleware wrapped around every /admin/*
// route. The order is deliberate:
//
//  1. Config invariant → 500. A handler built from a Config that skipped
//     Validate (or a config whose secret file disappeared at runtime) must
//     never serve with CSRF silently disabled.
//  2. IP allowlist → 403. This runs before any session lookup, form parsing,
//     password verification or rate-limit bookkeeping, so an outside IP cannot
//     learn whether a password or token is valid.
//  3. CSRF on every mutating method → 403, including POST /admin/logout.
//     Logging out is a state change; a cross-origin form must not be able to
//     trigger it. GET/HEAD are exempt because they do not mutate.
//  4. next.
func Guard(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := cfg.Validate(); err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("admin: refusing to serve with invalid config", "err", err)
				}
				http.Error(w, "internal configuration error", http.StatusInternalServerError)
				return
			}

			ip := clientIP(r, cfg)
			if !inAllowlist(ip, cfg.Allowlist) {
				cfg.Logger.Warn("admin: IP not in allowlist", "ip", ip, "path", r.URL.Path)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			if isMutating(r.Method) && len(cfg.CSRFSecret) > 0 {
				if err := r.ParseForm(); err != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				if !checkCSRF(r, cfg.CSRFSecret, cfg.SecureCookies) {
					cfg.Logger.Warn("admin: CSRF token mismatch", "ip", ip, "path", r.URL.Path)
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Router mounts the whole admin surface behind Guard. The binary registers it
// on both /admin and /admin/ so the guard also covers the slash-less form.
func Router(cfg Config, list CampaignLister) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin/":
			if r.Method != http.MethodGet {
				methodNotAllowed(w, "GET")
				return
			}
			RequireSession(cfg)(DashboardHandler(cfg, list)).ServeHTTP(w, r)

		case "/admin/login":
			switch r.Method {
			case http.MethodGet:
				LoginPageHandler(cfg)(w, r)
			case http.MethodPost:
				LoginHandler(cfg)(w, r)
			default:
				methodNotAllowed(w, "GET, POST")
			}

		case "/admin/logout":
			if r.Method != http.MethodPost {
				methodNotAllowed(w, "POST")
				return
			}
			LogoutHandler(cfg)(w, r)

		default:
			http.NotFound(w, r)
		}
	})
	return Guard(cfg)(inner)
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// campaignStateLabel translates the store state into the operator-facing label.
// Unknown states are shown verbatim rather than hidden, so a corrupt row is
// visible instead of silently disappearing from the dashboard.
func campaignStateLabel(state string) string {
	switch strings.ToLower(state) {
	case "draft":
		return "Brouillon"
	case "armed":
		return "Armée"
	case "running":
		return "En cours"
	case "closed":
		return "Clôturée"
	default:
		return state
	}
}
