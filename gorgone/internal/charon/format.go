// Package charon exports a campaign's collected artifacts as a JSON Lines
// stream. The stream is the boundary between collection and analysis: it is
// decrypted, ordered, authenticated per campaign and never accumulated.
//
// # Stream protocol
//
// Every line is a JSON object. Artifact lines carry "id", "campaign_id",
// "template_id", "step", "contact_id", "received_at", "remote_ip", "fields",
// "secrets", "files", "target" and "fingerprint". A consumer must treat any
// line that carries a top-level "type":"error" key as a stream-abort marker:
// the preceding lines are complete, but the stream stopped before the row
// named by "id". The consumer should resume the export with
// ?since=<last_good_received_at> after the corrupt row is repaired.
package charon

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
)

// ExportPrefix is the fixed root of the export route. It lives beside the
// code that registers it so the validation guard and the mux pattern cannot
// drift.
const ExportPrefix = "/export"

// ContentType is the only representation charon emits. NDJSON lets an operator
// pipe a campaign straight into a line-oriented consumer while the export is
// still running.
const ContentType = "application/x-ndjson"

// Line is the export contract. Every key is emitted on every line, including
// contact_id when empty and fingerprint when null, so a consumer can rely on
// the shape without a schema guess.
//
// "type" is always "artifact". A consumer that checks this field first does not
// need to infer the line kind from the absence of "type":"error".
//
// Maps are encoded by encoding/json in sorted key order; the field order below
// is the line order. Both are part of the byte-stable contract.
type Line struct {
	Type        string                    `json:"type"` // always "artifact"
	ID          string                    `json:"id"`
	CampaignID  string                    `json:"campaign_id"`
	TemplateID  string                    `json:"template_id"`
	Step        string                    `json:"step"`
	ContactID   string                    `json:"contact_id"`
	ReceivedAt  string                    `json:"received_at"`
	RemoteIP    string                    `json:"remote_ip"`
	Fields      map[string]string         `json:"fields"`
	Secrets     map[string]collect.Secret `json:"secrets"`
	Files       []collect.FileMeta        `json:"files"`
	Target      string                    `json:"target"`
	Fingerprint *collect.Fingerprint      `json:"fingerprint"`
}

// errorLine is a stream-abort marker. The "type":"error" key is not present on
// any artifact line, so a consumer can distinguish it from a normal artifact
// without reading "id" or "campaign_id". It carries the artifact id that
// triggered the failure so the operator can repair that row and resume from
// ?since=<last_good_received_at>.
type errorLine struct {
	Type  string `json:"type"` // always "error"
	Error string `json:"error"`
	ID    string `json:"id,omitempty"`
}

func newErrorLine(msg, id string) errorLine {
	return errorLine{Type: "error", Error: msg, ID: id}
}

func newLine(a *collect.Artifact) Line {
	fields := a.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	secrets := a.Secrets
	if secrets == nil {
		secrets = map[string]collect.Secret{}
	}
	files := a.Files
	if files == nil {
		files = []collect.FileMeta{}
	}
	return Line{
		Type:        "artifact",
		ID:          a.ID,
		CampaignID:  a.CampaignID,
		TemplateID:  a.TemplateID,
		Step:        a.Step,
		ContactID:   a.ContactID,
		ReceivedAt:  a.ReceivedAt.UTC().Format(time.RFC3339Nano),
		RemoteIP:    a.RemoteIP,
		Fields:      fields,
		Secrets:     secrets,
		Files:       files,
		Target:      a.Target,
		Fingerprint: a.Fingerprint,
	}
}

// ArtifactError ties a failure to the artifact being written, so a partial
// stream can name the row a consumer must repair.
type ArtifactError struct {
	ID  string
	Err error
}

func (e *ArtifactError) Error() string {
	return fmt.Sprintf("charon: artifact %s: %v", e.ID, e.Err)
}

func (e *ArtifactError) Unwrap() error { return e.Err }

// encodeLine marshals exactly one line plus its newline in one Write, so the
// stream has one write and one flush per artifact.
func encodeLine(a *collect.Artifact) ([]byte, error) {
	raw, err := json.Marshal(newLine(a))
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
