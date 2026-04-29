#!/usr/bin/env bash
# mqtt_soak — run mqtt_demo against Mosquitto in a tight loop.
# Logs RSS, completion count, every failure with full stderr.
#
# Usage: mqtt_soak.sh [iterations] [interval_sec]

set -uo pipefail

ITERATIONS="${1:-2000}"
INTERVAL_SEC="${2:-0}"

REPO=/Users/mathis/work/transports-spark
DEMO_BIN=$REPO/crates/examples/bin/mqtt_demo
SOAK_LOG=$REPO/overnight/mqtt_soak.log
RSS_LOG=$REPO/overnight/mqtt_rss.log
ANOMALY_LOG=$REPO/overnight/mqtt_soak_anomalies.log

# Make sure the demo binary exists.
if [[ ! -x "$DEMO_BIN" ]]; then
  echo "FATAL: $DEMO_BIN not found or not executable" >&2
  exit 2
fi

# Ensure Mosquitto is running.
if ! docker ps --format '{{.Names}}' | grep -qx mqtt-soak-mosq; then
  docker run -d --rm --name mqtt-soak-mosq -p 1883:1883 \
    eclipse-mosquitto mosquitto -c /mosquitto-no-auth.conf >/dev/null
  sleep 2
fi

echo "# mqtt_soak: $ITERATIONS iterations, interval=${INTERVAL_SEC}s" > "$SOAK_LOG"
echo "# started $(date -u +%FT%TZ)" >> "$SOAK_LOG"
: > "$RSS_LOG"
: > "$ANOMALY_LOG"

OK=0
FAIL=0
START=$(date +%s)

for ((i=1; i<=ITERATIONS; i++)); do
  # Capture exit code and stderr per iteration.
  if OUT=$("$DEMO_BIN" 2>&1); then
    OK=$((OK+1))
  else
    FAIL=$((FAIL+1))
    {
      echo "=== iter $i FAIL $(date -u +%FT%TZ)"
      echo "$OUT"
      echo
    } >> "$ANOMALY_LOG"
  fi

  # RSS sample (resident set size, KB on Linux/macOS).
  # Track Mosquitto's container RSS, since the demo binary itself
  # is short-lived per iteration.
  if (( i % 50 == 0 )); then
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))
    MOSQ_RSS=$(docker stats --no-stream --format '{{.MemUsage}}' mqtt-soak-mosq 2>/dev/null | awk -F'/' '{gsub(/ /,"",$1); print $1}')
    LINE="iter=$i elapsed=${ELAPSED}s ok=$OK fail=$FAIL mosq_mem=$MOSQ_RSS"
    echo "$LINE" | tee -a "$SOAK_LOG"
    echo "$LINE" >> "$RSS_LOG"
  fi

  if [[ "$INTERVAL_SEC" != "0" ]]; then
    sleep "$INTERVAL_SEC"
  fi
done

NOW=$(date +%s)
ELAPSED=$((NOW - START))
{
  echo "=== final ==="
  echo "elapsed=${ELAPSED}s ok=$OK fail=$FAIL"
} | tee -a "$SOAK_LOG"
