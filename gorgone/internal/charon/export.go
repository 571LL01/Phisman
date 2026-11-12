package charon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
)

// Source streams decrypted artifacts. collect.Store implements it.
type Source interface {
	Export(ctx context.Context, campaignID string, since time.Time, fn func(*collect.Artifact) error) error
}

// Export streams one campaign to w. It returns whether at least one line was
// written, which lets an HTTP caller choose between a clean 500 and an error
// line after a partial stream. flush is called after each line and may be nil.
func Export(ctx context.Context, src Source, campaignID string, since time.Time, w io.Writer, flush func()) (bool, error) {
	wrote := false
	err := src.Export(ctx, campaignID, since, func(a *collect.Artifact) error {
		raw, err := encodeLine(a)
		if err != nil {
			return &ArtifactError{ID: a.ID, Err: err}
		}
		if _, err := w.Write(raw); err != nil {
			return &ArtifactError{ID: a.ID, Err: err}
		}
		wrote = true
		if flush != nil {
			flush()
		}
		return nil
	})
	return wrote, err
}

// ParseSince accepts an RFC 3339 timestamp, with or without fractional seconds.
// An empty value means "from the beginning". Strictness is intentional: a
// silently ignored typo would replay far more rows than the operator expects.
func ParseSince(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("charon: since: %w", err)
	}
	return t.UTC(), nil
}

func writeErrorLine(w io.Writer, msg, id string) error {
	raw, err := json.Marshal(newErrorLine(msg, id))
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// Handler serves GET /export/{campaign}. It authenticates before touching the
// artifact table, then writes and flushes one line per artifact.
//
// At most two exports may run concurrently. The shared SQLite handle has four
// connections; the collector needs at least two for simultaneous submissions,
// so more than two parallel exports would starve it.
type Handler struct {
	src    Source
	tokens TokenStore
	sem    chan struct{} // capacity 2
	logger interface {
		Error(msg string, args ...any)
	}
}

// NewHandler wires the export surface.
func NewHandler(src Source, tokens TokenStore, logger interface {
	Error(msg string, args ...any)
}) *Handler {
	return &Handler{src: src, tokens: tokens, sem: make(chan struct{}, 2), logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	campaignID := r.PathValue("campaign")
	if campaignID == "" {
		http.Error(w, errNoCampaign.Error(), http.StatusNotFound)
		return
	}

	since, err := ParseSince(r.URL.Query().Get("since"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	hash, err := h.tokens.GetExportTokenHash(ctx, campaignID)
	if err != nil {
		h.logger.Error("export campaign lookup failed", "campaign", campaignID, "err", err)
		http.Error(w, "unknown campaign", http.StatusNotFound)
		return
	}
	if status, msg := authorize(r, hash); status != 0 {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="charon"`)
		}
		http.Error(w, msg, status)
		return
	}

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Acquire the slot before writing any headers, so a 503 can still be sent
	// if all export connections are occupied.
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		http.Error(w, "export capacity reached; retry later", http.StatusServiceUnavailable)
		return
	}

	controller := http.NewResponseController(w)
	wrote, err := Export(ctx, h.src, campaignID, since, w, func() {
		_ = controller.Flush()
	})
	if err == nil {
		return
	}

	h.logger.Error("export failed", "campaign", campaignID, "err", err)
	if !wrote {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Headers and earlier artifact lines are already on the wire. The error
	// line is the only way left to signal the consumer that the stream stopped
	// early. It carries "type":"error" so the consumer can distinguish it from
	// a normal artifact line without relying on absent keys.
	var artifactErr *ArtifactError
	id := ""
	if errors.As(err, &artifactErr) {
		id = artifactErr.ID
	}
	_ = writeErrorLine(w, err.Error(), id)
}
