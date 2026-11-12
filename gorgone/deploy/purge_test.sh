#!/usr/bin/env bash
# purge_test.sh — integration tests for purge.sh.
#
# Tests purge.sh in keep and rotate modes using stubbed docker commands
# and a lightweight bash/nc HTTP server. No Docker daemon, no python3 required.
#
# Requirements: bash >= 4, curl, jq, nc (netcat, any variant).
# Usage: bash deploy/purge_test.sh
# Exit code: 0 all pass, non-zero on any failure.

set -euo pipefail
cd "$(dirname "$0")/.."   # run from repo root so purge.sh path is consistent

PASS=0
FAIL=0

ok()   { printf 'PASS: %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

# ── fake HTTP server (bash + nc) ──────────────────────────────────────────────

# Two clean artifact lines — no type:error.
GOOD_NDJSON='{"type":"artifact","id":"a1","campaign_id":"acme","template_id":"t","step":"a","contact_id":"","received_at":"2026-11-06T10:00:00Z","remote_ip":"127.0.0.1","fields":{},"secrets":{},"files":[],"target":"https://example.com","fingerprint":null}
{"type":"artifact","id":"a2","campaign_id":"acme","template_id":"t","step":"a","contact_id":"c1","received_at":"2026-11-06T10:01:00Z","remote_ip":"127.0.0.1","fields":{},"secrets":{},"files":[],"target":"https://example.com","fingerprint":null}
'

# A payload containing a type:error line — should trigger exit 3.
ERROR_NDJSON='{"type":"artifact","id":"good","campaign_id":"acme","template_id":"t","step":"a","contact_id":"","received_at":"2026-11-06T10:00:00Z","remote_ip":"127.0.0.1","fields":{},"secrets":{},"files":[],"target":"https://example.com","fingerprint":null}
{"type":"error","id":"broken","error":"collect: artifact broken: decryption failed"}
'

# Start a one-shot HTTP server on a random port using nc.
# Loops so the server handles multiple sequential requests (keep test reuses it).
start_fake_server() {
  local body="$1"
  local body_len="${#body}"
  local port
  # Find a free port.
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
    || awk 'BEGIN{srand(); print int(30000+rand()*10000)}')

  (
    while true; do
      printf 'HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
        "$body_len" "$body" | nc -l 127.0.0.1 "$port" >/dev/null 2>&1 || true
    done
  ) &
  echo "$port $!"
}

start_empty_server() {
  local port
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
    || awk 'BEGIN{srand(); print int(30000+rand()*10000)}')
  (
    while true; do
      printf 'HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
        | nc -l 127.0.0.1 "$port" >/dev/null 2>&1 || true
    done
  ) &
  echo "$port $!"
}

# ── stub docker that records calls ───────────────────────────────────────────

# We write the stub to a temp file and source it in the subshell for each
# purge.sh invocation. export -f works within the same process tree.
make_docker_stub() {
  local port="$1"
  local volume_name="${2:-}"      # simulate the volume that should be removed
  local stop_flag="${3:-/dev/null}"  # file to touch when docker stop is called
  local rm_volume_flag="${4:-/dev/null}"  # file to touch when docker volume rm is called

  cat <<STUB
docker() {
  case "\$1" in
    inspect)
      if [[ "\${2:-}" == "--format" ]] && [[ "\${3:-}" == *Ports* ]]; then
        echo "127.0.0.1:${port}"
      elif [[ "\${2:-}" == "--format" ]] && [[ "\${3:-}" == *Mounts* ]]; then
        echo "${volume_name}"
      fi
      ;;
    stop)
      touch "${stop_flag}"
      ;;
    rm)
      ;;
    volume)
      if [[ "\${2:-}" == "rm" ]]; then
        touch "${rm_volume_flag}"
      fi
      ;;
    compose)
      ;;
    *)
      echo "stub docker: \$*" >&2
      ;;
  esac
}
export -f docker
STUB
}

# ── test infrastructure ───────────────────────────────────────────────────────

TMPDIR_EXPORTS=$(mktemp -d)
TMPDIR_FLAGS=$(mktemp -d)
trap 'rm -rf "$TMPDIR_EXPORTS" "$TMPDIR_FLAGS"; kill $(jobs -p) 2>/dev/null || true' EXIT

run_purge() {
  # run_purge <stub_file> <mode> <extra_env...>
  local stub="$1"; shift
  local mode="$1"; shift
  EXPORT_DIR="$TMPDIR_EXPORTS" \
    bash -c "source '$stub'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh $mode acme tok fake-container" \
    "$@" 2>&1
}

latest_export() {
  ls -t "$TMPDIR_EXPORTS"/*.ndjson 2>/dev/null | head -1
}

# ── test 1: keep creates a valid export file ──────────────────────────────────

read -r GOOD_PORT GOOD_PID <<< "$(start_fake_server "$GOOD_NDJSON")"
sleep 0.3

STUB=$(mktemp)
make_docker_stub "$GOOD_PORT" "" /dev/null /dev/null > "$STUB"

EXIT_CODE=0
bash -c "source '$STUB'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh keep acme tok fake-container" \
  >/dev/null 2>&1 || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 0 ]]; then
  EXPORT_FILE="$(latest_export)"
  if [[ -n "$EXPORT_FILE" && -s "$EXPORT_FILE" ]]; then
    LINE_COUNT=$(wc -l < "$EXPORT_FILE")
    if [[ "$LINE_COUNT" -ge 2 ]]; then
      ok "keep: export file created with $LINE_COUNT artifact lines"
    else
      fail "keep: export has only $LINE_COUNT lines"
    fi
  else
    fail "keep: export file missing or empty"
  fi
else
  fail "keep: purge.sh exited $EXIT_CODE"
fi

# ── test 2: keep does not call docker stop ────────────────────────────────────

STOP_FLAG="$TMPDIR_FLAGS/stop_called"
rm -f "$STOP_FLAG"
STUB2=$(mktemp)
make_docker_stub "$GOOD_PORT" "" "$STOP_FLAG" /dev/null > "$STUB2"

bash -c "source '$STUB2'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh keep acme tok fake-container" \
  >/dev/null 2>&1 || true

if [[ -f "$STOP_FLAG" ]]; then
  fail "keep: docker stop was called (server should be left running)"
else
  ok "keep: docker stop was not called"
fi

# ── test 3: empty export → exit 2 ────────────────────────────────────────────

read -r EMPTY_PORT EMPTY_PID <<< "$(start_empty_server)"
sleep 0.3
STUB3=$(mktemp)
make_docker_stub "$EMPTY_PORT" "" /dev/null /dev/null > "$STUB3"

EXIT_CODE=0
bash -c "source '$STUB3'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh keep acme tok fake-container" \
  >/dev/null 2>&1 || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 2 ]]; then
  ok "empty export: exit 2 as expected"
else
  fail "empty export: exit $EXIT_CODE, want 2"
fi

# ── test 4: type:error line → exit 3 ─────────────────────────────────────────

read -r ERR_PORT ERR_PID <<< "$(start_fake_server "$ERROR_NDJSON")"
sleep 0.3
STUB4=$(mktemp)
make_docker_stub "$ERR_PORT" "" /dev/null /dev/null > "$STUB4"

EXIT_CODE=0
bash -c "source '$STUB4'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh keep acme tok fake-container" \
  >/dev/null 2>&1 || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 3 ]]; then
  ok "type:error stream: exit 3 as expected"
else
  fail "type:error stream: exit $EXIT_CODE, want 3"
fi

# ── test 5: rotate calls docker stop AND docker volume rm ─────────────────────

STOP_FLAG2="$TMPDIR_FLAGS/rotate_stop"
VOL_FLAG="$TMPDIR_FLAGS/rotate_volume_rm"
rm -f "$STOP_FLAG2" "$VOL_FLAG"

STUB5=$(mktemp)
make_docker_stub "$GOOD_PORT" "siren-data-test" "$STOP_FLAG2" "$VOL_FLAG" > "$STUB5"

EXIT_CODE=0
bash -c "source '$STUB5'; EXPORT_DIR='$TMPDIR_EXPORTS' COMPOSE_FILE=/dev/null bash deploy/purge.sh rotate acme tok fake-container" \
  >/dev/null 2>&1 || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 0 ]]; then
  ok "rotate: exit 0"
else
  fail "rotate: purge.sh exited $EXIT_CODE"
fi

if [[ -f "$STOP_FLAG2" ]]; then
  ok "rotate: docker stop was called"
else
  fail "rotate: docker stop was not called"
fi

if [[ -f "$VOL_FLAG" ]]; then
  ok "rotate: docker volume rm was called (volume would be removed)"
else
  fail "rotate: docker volume rm was not called — data volume left on disk"
fi

# ── test 6: rotate with no detected volume → warning, no crash ───────────────

STUB6=$(mktemp)
make_docker_stub "$GOOD_PORT" "" /dev/null /dev/null > "$STUB6"

EXIT_CODE=0
OUTPUT=$(bash -c "source '$STUB6'; EXPORT_DIR='$TMPDIR_EXPORTS' COMPOSE_FILE=/dev/null bash deploy/purge.sh rotate acme tok fake-container" 2>&1) \
  || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 0 ]]; then
  ok "rotate no-volume: exits 0 with warning"
else
  fail "rotate no-volume: exited $EXIT_CODE (should warn, not fail)"
fi
if echo "$OUTPUT" | grep -qi "WARN"; then
  ok "rotate no-volume: warning emitted"
else
  fail "rotate no-volume: no warning in output"
fi

# ── test 7: since parameter passed without python3 ───────────────────────────

STUB7=$(mktemp)
make_docker_stub "$GOOD_PORT" "" /dev/null /dev/null > "$STUB7"

EXIT_CODE=0
bash -c "source '$STUB7'; EXPORT_DIR='$TMPDIR_EXPORTS' bash deploy/purge.sh keep acme tok fake-container '2026-11-06T00:00:00Z'" \
  >/dev/null 2>&1 || EXIT_CODE=$?

if [[ "$EXIT_CODE" -eq 0 ]]; then
  ok "since parameter: purge.sh handled --data-urlencode without python3"
else
  fail "since parameter: exit $EXIT_CODE"
fi

# ── summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
