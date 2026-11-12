package collect

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
)

// BeaconPattern is the mux pattern for the post-interaction endpoint. The
// token segment is per campaign, so the only constant in the path is the
// configured prefix; nothing else can be blocklisted across deployments.
func (c *Collector) BeaconPattern() string {
	return c.cfg.BeaconPrefix + "/{token}/fp/{id}"
}

// beaconTemplate is used only for ModeBeacon. Navigation waits for the beacon
// and is bounded by a 900 ms ceiling; nothing leaves the page before the
// request settles or the ceiling is reached.
//
// The no-JS path is a <noscript> refresh, so when scripting runs the meta
// element does not exist and the two can never race.
var beaconTemplate = template.Must(template.New("beacon").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Redirecting</title>
</head>
<body>
<noscript><meta http-equiv="refresh" content="0;url={{.Target}}"></noscript>
<script>
(function () {
  "use strict";
  var endpoint = {{.Endpoint}};
  var target = {{.Target}};
  var settled = false;
  var ceiling = setTimeout(leave, 900);

  function leave() {
    if (settled) { return; }
    settled = true;
    clearTimeout(ceiling);
    location.replace(target);
  }

  function fnv(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return ("00000000" + h.toString(16)).slice(-8);
  }

  function canvasHash() {
    try {
      var c = document.createElement("canvas");
      c.width = 240; c.height = 60;
      var x = c.getContext("2d");
      x.textBaseline = "top"; x.font = "14px Arial";
      x.fillStyle = "#f60"; x.fillRect(0, 0, 240, 60);
      x.fillStyle = "#069"; x.fillText("siren-0123456789", 2, 2);
      return fnv(c.toDataURL());
    } catch (e) { return ""; }
  }

  function webglHash() {
    try {
      var c = document.createElement("canvas");
      var g = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!g) { return ""; }
      var d = g.getExtension("WEBGL_debug_renderer_info");
      var r = d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER);
      var v = d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR);
      return fnv(String(r) + "|" + String(v));
    } catch (e) { return ""; }
  }

  var payload = {
    user_agent: navigator.userAgent,
    language: navigator.language,
    languages: navigator.languages ? Array.prototype.slice.call(navigator.languages) : [],
    timezone: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return ""; } })(),
    timezone_offset: new Date().getTimezoneOffset(),
    screen: screen.width + "x" + screen.height + "x" + screen.availHeight,
    color_depth: screen.colorDepth,
    pixel_ratio: window.devicePixelRatio || 1,
    platform: navigator.platform,
    hardware_concurrency: navigator.hardwareConcurrency || 0,
    device_memory: navigator.deviceMemory || 0,
    touch_points: navigator.maxTouchPoints || 0,
    webdriver: !!navigator.webdriver,
    canvas_hash: canvasHash(),
    webgl_hash: webglHash()
  };

  try {
    fetch(endpoint, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      keepalive: true
    }).then(leave, leave);
  } catch (e) {
    leave();
  }
})();
</script>
</body>
</html>
`))

type beaconData struct {
	Endpoint string
	Target   string
}

func (c *Collector) writeBeacon(w http.ResponseWriter, r *http.Request, a *Artifact, step Step) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	_ = beaconTemplate.Execute(w, beaconData{
		Endpoint: c.cfg.BeaconPrefix + "/" + step.BeaconToken + "/fp/" + a.ID,
		Target:   a.Target,
	})
}

// BeaconHandler merges a post-interaction fingerprint into an existing
// artifact. The token is validated against the step contract, so a valid ID
// alone is not enough to write.
func (c *Collector) BeaconHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := r.PathValue("token")
		id := r.PathValue("id")
		if !validArtifactID(id) || token == "" || len(token) > 64 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxFingerprintBytes)
		var fp Fingerprint
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fp); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), storeTimeout)
		defer cancel()

		a, err := c.store.Get(ctx, id)
		if errors.Is(err, ErrArtifactNotFound) {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		if err != nil {
			c.cfg.Logger.Error("beacon load failed", "artifact", id, "err", err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		step, err := c.cfg.Resolve(a.CampaignID, a.TemplateID, a.Step)
		if err != nil {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		// A beacon must only merge into a step that opted into beacon mode.
		// Otherwise an inline step would accept a second write path.
		if step.Mode != ModeBeacon {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if subtle.ConstantTimeCompare([]byte(step.BeaconToken), []byte(token)) != 1 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		fp.CollectedAt = c.now().UTC()
		if len(fp.Languages) > 16 {
			fp.Languages = fp.Languages[:16]
		}
		if err := c.store.AttachFingerprint(ctx, id, &fp); err != nil {
			c.cfg.Logger.Error("beacon merge failed", "artifact", id, "err", err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func validArtifactID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
