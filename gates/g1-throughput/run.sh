#!/usr/bin/env bash
# G1 — networked throughput + RSS budget (docs/engineering/05-quality-gates.md §2).
#
# Boots archiv-agent validate-only on an ephemeral-ish port under `/usr/bin/time`
# (to capture peak RSS), dumps a real OTLP payload via the perf harness, runs the
# k6 open-loop load, then asserts: sustained EPS >= 10,000 and peak RSS <= 50 MB.
#
# Requires: cargo, k6 on PATH. Synthetic data only (docs/engineering/02 §6).
set -euo pipefail
cd "$(dirname "$0")/../.."   # -> agent/

PORT="${ARCHIV_PORT:-4318}"
URL="http://127.0.0.1:${PORT}"
PAYLOAD="${ARCHIV_OTLP_FILE:-/tmp/archiv-otlp.bin}"
RECORDS="${ARCHIV_RECORDS:-10}"
RSS_BUDGET_KB=$((50 * 1024))
TIME_LOG="$(mktemp)"
CONFIG="$(mktemp -t archiv-g1-config).yaml"

command -v k6 >/dev/null || { echo "G1: k6 not found on PATH — install k6 to run this gate." >&2; exit 2; }

echo "==> build (release)"
cargo build --release --bin archiv-agent --example perf

echo "==> dump OTLP corpus -> $PAYLOAD"
ARCHIV_PERF_DUMP="$PAYLOAD" ARCHIV_PERF_RECORDS="$RECORDS" cargo run --release --example perf >/dev/null

# validate-only config (no export endpoint): isolates the ingest+govern path.
cat >"$CONFIG" <<YAML
ingest:
  http_endpoint: "127.0.0.1:${PORT}"
  grpc_endpoint: "127.0.0.1:0"
sampling:
  default_target: 25
redaction:
  regex_rules:
    - { name: email, pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', mask: "[EMAIL]", fields: [body] }
YAML

echo "==> start agent (under /usr/bin/time for peak RSS)"
# macOS `/usr/bin/time -l` and GNU `/usr/bin/time -v` both print peak RSS; we grep both.
ARCHIV_CONFIG="$CONFIG" /usr/bin/time -l target/release/archiv-agent 2>"$TIME_LOG" &
TIME_PID=$!
# stop_agent: SIGTERM the agent *child* of /usr/bin/time — not the `time` wrapper itself.
# Killing `time` orphans the agent and discards its peak-RSS report; signalling the child
# lets `time` reap it, flush the `-l`/`-v` rusage line to $TIME_LOG, and exit so `wait` returns.
stop_agent() { pkill -TERM -P "$TIME_PID" 2>/dev/null || kill -TERM "$TIME_PID" 2>/dev/null || true; }
trap 'stop_agent; rm -f "$CONFIG"' EXIT

echo "==> wait for readiness"
for _ in $(seq 1 50); do
  if curl -fsS -o /dev/null "$URL/v1/logs" -X POST --data-binary @"$PAYLOAD" \
       -H 'content-type: application/x-protobuf' 2>/dev/null; then break; fi
  sleep 0.1
done

echo "==> k6 warm-up + load"
ARCHIV_AGENT_URL="$URL" ARCHIV_OTLP_FILE="$PAYLOAD" ARCHIV_RECORDS="$RECORDS" \
  k6 run --summary-export=/tmp/archiv-g1-summary.json gates/g1-throughput/load.js

echo "==> stop agent"
stop_agent
wait "$TIME_PID" 2>/dev/null || true

# ---- assertions -------------------------------------------------------------
EPS=$(python3 - <<'PY'
import json
s = json.load(open('/tmp/archiv-g1-summary.json'))
m = s.get('metrics', {})
ev = m.get('archiv_events', {})
# k6 exposes a Counter's rate as 'count'/duration; use the derived 'rate' if present.
rate = ev.get('rate') or 0.0
print(int(rate))
PY
)

# peak RSS: macOS reports bytes ("maximum resident set size"), GNU reports KB.
RSS_KB=$(awk '
  /maximum resident set size/ { print int($1/1024); found=1 }      # macOS: bytes
  /Maximum resident set size/ { print int($6); found=1 }           # GNU: kbytes (field 6)
  END { if (!found) print -1 }
' "$TIME_LOG" | head -1)

echo "----------------------------------------"
echo "G1 result: ~${EPS} EPS (SLA >= 10000), peak RSS ${RSS_KB} KB (budget ${RSS_BUDGET_KB} KB)"
rc=0
[ "${EPS:-0}" -ge 10000 ] || { echo "G1 FAIL: throughput below SLA"; rc=1; }
if [ "${RSS_KB:-−1}" -ge 0 ]; then
  [ "$RSS_KB" -le "$RSS_BUDGET_KB" ] || { echo "G1 FAIL: RSS over budget"; rc=1; }
else
  echo "G1 WARN: could not parse peak RSS from /usr/bin/time output"
fi
[ "$rc" -eq 0 ] && echo "G1 PASS"
exit "$rc"
