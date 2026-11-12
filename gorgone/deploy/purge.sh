#!/usr/bin/env bash
# purge.sh — export and optionally destroy a SIREN-CORE deployment.
#
# Usage:
#   purge.sh keep    <campaign-id> <export-token> <container> [since]
#   purge.sh rotate  <campaign-id> <export-token> <container> [since]
#
# keep   — Export artifacts to a timestamped file, leave the server running.
# rotate — Export, verify export completeness, then destroy the container and
#           its volume, and restart on a new hostname.
#
# Arguments:
#   campaign-id    Campaign to export (e.g. "acme").
#   export-token   Bearer token for /export (from `sirencore -issue-token`).
#   container      Docker container name (e.g. "siren-core").
#   since          Optional RFC 3339 lower bound for the export (exclusive).
#
# Exit codes:
#   0  Success.
#   1  Missing arguments or missing required command.
#   2  Export produced an empty file.
#   3  Export file is incomplete: truncated stream, invalid JSON, or
#      type:error line detected.
#   4  Container / docker error.
#
# Optional environment variables:
#   EXPORT_DIR     Directory for the timestamped export file (default ./exports).
#   COMPOSE_FILE   Path to docker-compose.yml (default deploy/docker-compose.yml).
#   CURL_MAX_TIME  Maximum time in seconds for the export curl call (default 300).
#
# Requirements: bash >= 4, curl, docker, jq.

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit "${2:-1}"; }

usage() {
  cat >&2 <<'EOF'
Usage:
  purge.sh keep   <campaign-id> <export-token> <container> [since]
  purge.sh rotate <campaign-id> <export-token> <container> [since]
EOF
  exit 1
}

require() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
  done
}

# ── argument parsing ──────────────────────────────────────────────────────────

[[ $# -lt 4 ]] && usage
MODE="$1"
CAMPAIGN="$2"
TOKEN="$3"
CONTAINER="$4"
SINCE="${5:-}"

[[ "$MODE" == "keep" || "$MODE" == "rotate" ]] || usage

# Fix 4: python3 removed from requirements. URL-encoding handled by curl
# --data-urlencode, which is available in all curl >= 7.18.0 (2008).
require curl docker jq

# ── detect server address ─────────────────────────────────────────────────────

ADDR="$(docker inspect --format \
  '{{range $p, $cfg := .NetworkSettings.Ports}}{{if $cfg}}{{(index $cfg 0).HostIp}}:{{(index $cfg 0).HostPort}}{{end}}{{end}}' \
  "$CONTAINER" 2>/dev/null | head -1)"
ADDR="${ADDR:-127.0.0.1:8080}"
BASE_URL="http://${ADDR}"

# Fix 1 (rotate only): capture the volume name NOW, while the container is still
# running and docker inspect can find it. After `docker rm` the container
# metadata is gone and inspect returns nothing, leaving VOLUME empty and the
# volume on disk permanently.
if [[ "$MODE" == "rotate" ]]; then
  VOLUME="$(docker inspect \
    --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}' \
    "$CONTAINER" 2>/dev/null || true)"
  if [[ -z "$VOLUME" ]]; then
    echo "WARN: could not detect named volume for '${CONTAINER}'; volume will not be removed." >&2
  fi
fi

# ── export ────────────────────────────────────────────────────────────────────

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EXPORT_DIR="${EXPORT_DIR:-./exports}"
mkdir -p "$EXPORT_DIR"
EXPORT_FILE="${EXPORT_DIR}/${CAMPAIGN}-${TIMESTAMP}.ndjson"
# Temporary file for non-200 response bodies so they never land in EXPORT_FILE.
ERR_FILE="${EXPORT_DIR}/${CAMPAIGN}-${TIMESTAMP}.err"

echo "→ Exporting campaign '${CAMPAIGN}' to ${EXPORT_FILE} …"

# Fix 4: build the URL with curl --get --data-urlencode so the since timestamp
# is correctly percent-encoded without requiring python3.
# Fix 3: --max-time caps a blocked export so the script cannot hang indefinitely.
CURL_MAX_TIME="${CURL_MAX_TIME:-300}"
CURL_ARGS=(
  --silent --show-error
  --max-time "$CURL_MAX_TIME"
  --header "Authorization: Bearer ${TOKEN}"
)

if [[ -n "$SINCE" ]]; then
  # --get turns the request into GET, --data-urlencode encodes the value.
  HTTP_STATUS="$(curl "${CURL_ARGS[@]}" \
    --get --data-urlencode "since=${SINCE}" \
    --output "$EXPORT_FILE" \
    --write-out "%{http_code}" \
    "${BASE_URL}/export/${CAMPAIGN}")" || \
    die "curl failed (max-time ${CURL_MAX_TIME}s) — export aborted; server not touched" 4
else
  HTTP_STATUS="$(curl "${CURL_ARGS[@]}" \
    --output "$EXPORT_FILE" \
    --write-out "%{http_code}" \
    "${BASE_URL}/export/${CAMPAIGN}")" || \
    die "curl failed (max-time ${CURL_MAX_TIME}s) — export aborted; server not touched" 4
fi

# Mineur: on non-200 the body (error message) landed in EXPORT_FILE.
# Move it to the .err file so the .ndjson path stays clean.
if [[ "$HTTP_STATUS" != "200" ]]; then
  mv "$EXPORT_FILE" "$ERR_FILE" 2>/dev/null || true
  die "export returned HTTP $HTTP_STATUS — server not touched (body: $ERR_FILE)" 4
fi

# ── verify export completeness ────────────────────────────────────────────────

echo "→ Verifying export …"

if [[ ! -s "$EXPORT_FILE" ]]; then
  rm -f "$EXPORT_FILE"
  die "export file is empty (no artifacts or export failed silently)" 2
fi

# 1. Last byte must be 0x0a: a truncated stream ends mid-line.
LAST_BYTE="$(tail -c 1 "$EXPORT_FILE" | xxd -p 2>/dev/null || printf '')"
if [[ "$LAST_BYTE" != "0a" ]]; then
  die "export file does not end with a newline — stream truncated (file: $EXPORT_FILE)" 3
fi

# 2. Every line must parse as JSON.
INVALID_LINES=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! printf '%s' "$line" | jq . >/dev/null 2>&1; then
    echo "WARN: invalid JSON line: ${line:0:120}" >&2
    INVALID_LINES=$((INVALID_LINES + 1))
  fi
done < "$EXPORT_FILE"

if [[ "$INVALID_LINES" -gt 0 ]]; then
  die "export file contains $INVALID_LINES invalid JSON lines (file: $EXPORT_FILE)" 3
fi

# Fix 2: a type:error line is valid JSON terminated by a newline, so the two
# checks above pass. Scan for it explicitly: its presence means the server hit
# a decryption error mid-stream and the export is incomplete.
ERROR_LINE="$(jq -r 'select(.type == "error") | .id // "(no id)"' "$EXPORT_FILE" 2>/dev/null | head -1)"
if [[ -n "$ERROR_LINE" ]]; then
  die "export stream was aborted by the server (type:error on artifact ${ERROR_LINE}); " \
      "repair or skip that row and re-export with --since (file: $EXPORT_FILE)" 3
fi

LINE_COUNT="$(wc -l < "$EXPORT_FILE")"
echo "✓ Export verified: ${LINE_COUNT} artifact lines, file ${EXPORT_FILE}"

# ── mode: keep ───────────────────────────────────────────────────────────────

if [[ "$MODE" == "keep" ]]; then
  echo "✓ Mode 'keep': server left running.  Export at ${EXPORT_FILE}"
  exit 0
fi

# ── mode: rotate ──────────────────────────────────────────────────────────────

echo "→ Mode 'rotate': destroying container and volume …"

docker stop "$CONTAINER" 2>/dev/null || true
docker rm   "$CONTAINER" 2>/dev/null || true

# VOLUME was captured before stop (Fix 1).
if [[ -n "${VOLUME:-}" ]]; then
  echo "→ Removing volume '${VOLUME}' …"
  docker volume rm "$VOLUME" || \
    echo "WARN: could not remove volume '${VOLUME}' — remove it manually." >&2
fi

echo "✓ Container and volume removed."

NEW_NAME="${CONTAINER}-$(date -u +%s)"
echo "→ Starting new container '${NEW_NAME}' …"

COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.yml}"
if [[ -f "$COMPOSE_FILE" ]]; then
  SIREN_CONTAINER_NAME="$NEW_NAME" docker compose -f "$COMPOSE_FILE" up -d sirencore
else
  echo "WARN: no compose file at ${COMPOSE_FILE} — restart manually: ${NEW_NAME}" >&2
fi

echo "✓ Rotate complete.  New container: ${NEW_NAME}  Export: ${EXPORT_FILE}"
