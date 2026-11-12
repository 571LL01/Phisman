package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	"github.com/siren-core/gorgone/internal/store"
)

// trackingTimeout bounds the attribution lookup and the event write. A visitor
// (or a mail client prefetcher) must never wait on our database for their
// image, and closing the connection must not cost us the event.
const trackingTimeout = 2 * time.Second

// pixelGIF is a 1x1 fully transparent GIF89a. It is the smallest image an MUA
// will fetch; the bytes are a constant so the handler never re-encodes.
var pixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // "GIF89a"
	0x01, 0x00, 0x01, 0x00, // 1x1
	0x80, 0x00, 0x00, // global color table, 2 entries
	0x00, 0x00, 0x00, // color 0 (transparent)
	0xff, 0xff, 0xff, // color 1
	0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // graphic control: transparent index 0
	0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // image descriptor 1x1
	0x02, 0x02, 0x44, 0x01, 0x00, // LZW image data
	0x3b, // trailer
}

// openPixelPattern is the mux pattern for the open-tracking pixel. It mirrors
// the phishing page coordinate (/c/{campaign}/{template}/{step}) under the
// beacon prefix, with a leading "o" segment. Four path segments keep it
// unambiguous against the 3-segment post-interaction beacon pattern
// ({prefix}/{token}/fp/{id}), so registering both never conflicts.
func openPixelPattern(beaconPrefix string) string {
	return effectiveBeaconPrefix(beaconPrefix) + "/o/{campaign}/{template}/{step}"
}

// effectiveBeaconPrefix resolves the empty config value to the same default
// collect.New applies, so the registered route and the URL built into emails
// always agree.
func effectiveBeaconPrefix(beaconPrefix string) string {
	if beaconPrefix == "" {
		return collect.DefaultBeaconPrefix
	}
	return beaconPrefix
}

// openPixelHandler records an "open" event for the recipient in ?rid= and then
// always returns the transparent pixel, whether or not attribution succeeded.
// A missing, stale or cross-campaign rid is silently not recorded: the image is
// still served so the email renders normally.
func openPixelHandler(ops opsStore, resolve collect.Resolver, trusted []*net.IPNet, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer writePixel(w)

		campaignID := r.PathValue("campaign")
		templateID := r.PathValue("template")
		stepID := r.PathValue("step")
		rid := r.URL.Query().Get("rid")
		if rid == "" {
			return
		}
		// An unknown coordinate is a forged or stale pixel; serve the image but
		// keep the funnel clean of events that name no real step.
		if _, err := resolve(campaignID, templateID, stepID); err != nil {
			return
		}

		// Detach from the client: a prefetcher that drops the connection the
		// instant it has the bytes must not cancel the write.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), trackingTimeout)
		defer cancel()

		if _, err := ops.GetContact(ctx, campaignID, rid); err != nil {
			// Unknown or cross-campaign rid: not an error worth a line, it is a
			// normal consequence of an old or probed link.
			return
		}
		if err := ops.RecordEvent(ctx, store.EventInput{
			CampaignID: campaignID,
			ContactID:  rid,
			TemplateID: templateID,
			StepID:     stepID,
			Kind:       store.EventOpen,
			RemoteIP:   collect.ClientIP(r, trusted),
			UserAgent:  r.Header.Get("User-Agent"),
		}); err != nil {
			logger.Error("open event persist failed",
				"campaign", campaignID, "contact", rid, "err", err)
		}
	}
}

// writePixel emits the transparent GIF with caching disabled so every open is
// a fresh request rather than a cache hit.
func writePixel(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "image/gif")
	h.Set("Content-Length", strconv.Itoa(len(pixelGIF)))
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pixelGIF)
}
