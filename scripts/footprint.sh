#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Measure what one connector costs, so the numbers in the README's footprint
# section can be reproduced on any machine: binary size, resident memory at
# idle and under load, and throughput for a feed of N records signed and
# published to a bus.
#
# It builds ajar-generic, writes N newline-JSON records and a mapping for them,
# runs the connector on the file transport with the metrics endpoint open, and
# polls /metrics until every record is published. The bus receives the events,
# so a NATS server must be reachable; the dev stack's is the default.
#
# Usage:  scripts/footprint.sh [records] [nats_url]
#         defaults: 300000 nats://127.0.0.1:4222
# Needs:  cargo, python3, curl, and a bus at nats_url.
set -euo pipefail

records="${1:-300000}"
nats_url="${2:-nats://127.0.0.1:4222}"
health="127.0.0.1:9199"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill "${pid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

echo "building ajar-generic (release)..."
cargo build --release --quiet --manifest-path "$root/rust/connectors/Cargo.toml" -p ajar-generic
bin="$root/rust/connectors/target/release/ajar-generic"

python3 - "$records" > "$work/feed.ndjson" <<'EOF'
import random, sys
n = int(sys.argv[1])
for i in range(n):
    print('{"ts":"2026-01-01T00:00:00Z","id":"t-%d","lat":%.5f,"lon":%.5f,"alt":%.1f}'
          % (i % 5000, random.uniform(-60, 60), random.uniform(-180, 180), random.uniform(0, 10000)))
EOF

head -c 32 /dev/urandom > "$work/footprint.seed"
cat > "$work/footprint.toml" <<EOF
source_id = "footprint-1"
nats_url = "$nats_url"
subject_prefix = "ajar.ingest"
signing_key_path = "$work/footprint.seed"

[transport]
kind = "file"
path = "$work/feed.ndjson"
from_start = true

[mapping]
format = "json"
entity_type = "mim:object"
timestamp_field = "ts"
timestamp_format = "rfc3339"
lat_field = "lat"
lon_field = "lon"
[mapping.metadata]
id = "source_uid"
alt = "alt"
EOF

rss_mb() { ps -o rss= -p "$1" | awk '{ printf "%.1f", $1 / 1024 }'; }
published() { curl -s "http://$health/metrics" | awk '/^connector_published_total/ { print $2 }'; }

AJAR_HEALTH_ADDR="$health" "$bin" "$work/footprint.toml" >/dev/null 2>&1 &
pid=$!
start=$(python3 -c 'import time; print(time.time())')
for _ in $(seq 1 2400); do
  n="$(published || true)"
  if [[ "${n:-0}" -ge "$records" ]]; then break; fi
  sleep 0.25
done
end=$(python3 -c 'import time; print(time.time())')
rss_load="$(rss_mb "$pid")"
if [[ "${n:-0}" -lt "$records" ]]; then
  echo "error: only ${n:-0} of $records published after 10 minutes; is a bus listening at $nats_url?" >&2
  exit 1
fi
sleep 2
rss_idle="$(rss_mb "$pid")"
kill "$pid"; wait "$pid" 2>/dev/null || true

secs=$(python3 -c "print(round($end - $start, 1))")
rate=$(python3 -c "print(int($records / max($end - $start, 0.001)))")
size=$(awk -v b="$(wc -c < "$bin")" 'BEGIN { printf "%.1f", b / 1048576 }')

echo "footprint of ajar-generic, $records records on the file transport to $nats_url"
echo "  binary (release)        ${size} MB"
echo "  resident memory, load   ${rss_load} MB"
echo "  resident memory, idle   ${rss_idle} MB"
echo "  all records published   ${secs} s"
echo "  throughput              ${rate} events/s"
