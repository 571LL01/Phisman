package collect

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Fingerprint is the client-side half of an artifact. Everything it carries is
// derivable at page load, so it travels inside the submission itself as a
// hidden field and never needs an interstitial.
type Fingerprint struct {
	UserAgent           string    `json:"user_agent,omitempty"`
	Language            string    `json:"language,omitempty"`
	Languages           []string  `json:"languages,omitempty"`
	Timezone            string    `json:"timezone,omitempty"`
	TimezoneOffset      int       `json:"timezone_offset,omitempty"`
	Screen              string    `json:"screen,omitempty"`
	ColorDepth          int       `json:"color_depth,omitempty"`
	PixelRatio          float64   `json:"pixel_ratio,omitempty"`
	Platform            string    `json:"platform,omitempty"`
	HardwareConcurrency int       `json:"hardware_concurrency,omitempty"`
	DeviceMemory        float64   `json:"device_memory,omitempty"`
	TouchPoints         int       `json:"touch_points,omitempty"`
	WebDriver           bool      `json:"webdriver,omitempty"`
	CanvasHash          string    `json:"canvas_hash,omitempty"`
	WebGLHash           string    `json:"webgl_hash,omitempty"`
	CollectedAt         time.Time `json:"collected_at"`
}

const maxFingerprintBytes = 8 << 10

// ParseFingerprint decodes the hidden field emitted by the template layer.
// A malformed value is dropped rather than rejecting the submission: losing
// the fingerprint is recoverable, losing the credential is not.
func ParseFingerprint(field string) (*Fingerprint, error) {
	raw, err := base64.RawURLEncoding.DecodeString(field)
	if err != nil {
		return nil, errors.New("collect: fingerprint is not base64url")
	}
	if len(raw) > maxFingerprintBytes {
		return nil, errors.New("collect: fingerprint too large")
	}
	var fp Fingerprint
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fp); err != nil {
		return nil, err
	}
	if len(fp.Languages) > 16 {
		fp.Languages = fp.Languages[:16]
	}
	fp.CollectedAt = time.Now().UTC()
	return &fp, nil
}

// Secret is the only form in which a sensitive submitted value is allowed to
// reach storage. The clear value lives for the duration of the request handler.
type Secret struct {
	SHA256  string `json:"sha256"`
	Length  int    `json:"length"`
	Present bool   `json:"present"`
	Kind    Kind   `json:"kind,omitempty"`
}

func NewSecret(v string, k Kind) Secret {
	sum := sha256.Sum256([]byte(v))
	return Secret{
		SHA256:  hex.EncodeToString(sum[:]),
		Length:  len(v),
		Present: v != "",
		Kind:    k,
	}
}

// Cookie is a request cookie as presented by the client. Values stay
// reversible because replaying a session token is the point of collection.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FileMeta is all that is retained of an upload. The bytes themselves are
// hashed and discarded: a signed certificate is evidence, not a file store.
type FileMeta struct {
	Field       string `json:"field"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type,omitempty"`
}

type Artifact struct {
	ID         string `json:"id"`
	CampaignID string `json:"campaign_id"`
	TemplateID string `json:"template_id"`
	Step       string `json:"step"`
	// ContactID is the recipient the delivery link identified with ?rid=.
	// It is empty when the rid is absent, unknown, or belongs to another
	// campaign: attribution is evidence, not a reason to drop a submission.
	// The Charon export (step 6) must carry this field.
	ContactID  string    `json:"contact_id,omitempty"`
	ReceivedAt time.Time `json:"received_at"`

	RemoteIP string `json:"remote_ip"`
	Edge     string `json:"edge,omitempty"`

	Method  string              `json:"method"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Query   map[string][]string `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Cookies []Cookie            `json:"cookies,omitempty"`

	Fields  map[string]string `json:"fields,omitempty"`
	Secrets map[string]Secret `json:"secrets,omitempty"`
	Files   []FileMeta        `json:"files,omitempty"`

	Target      string       `json:"target"`
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("collect: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
