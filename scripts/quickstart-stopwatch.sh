#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The quickstart stopwatch: a stranger, this checkout, and the README's
# prebuilt-connector path (section 4) - measured, from nothing to the first
# governed event verified and stored by the sink. CI fails if the path breaks
# or the clock passes the budget; the seconds are the number we publish.
#
# Every command here mirrors a documented step; if the docs drift, this
# breaks, which is the point.
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET_SECS="${BUDGET_SECS:-900}"   # the promise: under 15 minutes
PORT="${STOPWATCH_NATS_PORT:-42111}"
UDP_PORT=42112
WORK="$(mktemp -d)"
trap 'pkill -P $$ 2>/dev/null || true; rm -rf "$WORK"' EXIT

t0=$(date +%s)

# README section 4, step 4: build the connector (plus the sink that stands in
# for Core locally, and the doctor the troubleshooting section names).
cargo build --release --manifest-path rust/connectors/Cargo.toml \
  -p ajar-ais-nmea -p ajar-sink -p ajar-doctor
BIN=rust/connectors/target/release

# Section 4, step 2: copy the example config; step 3: edit four values.
cp rust/connectors/ais-nmea/ais-nmea.example.toml "$WORK/ais.toml"
python3 - "$WORK" "$PORT" "$UDP_PORT" <<'PY'
import re, sys
work, port, udp = sys.argv[1], sys.argv[2], sys.argv[3]
p = f"{work}/ais.toml"
s = open(p).read()
s = re.sub(r'source_id = "[^"]*"', 'source_id = "stranger-1"', s, count=1)
s = re.sub(r'nats_url = "[^"]*"', f'nats_url = "nats://127.0.0.1:{port}"', s, count=1)
s = re.sub(r'signing_key_path = "[^"]*"', f'signing_key_path = "{work}/keys/stranger-1.seed"', s, count=1)
# Switch the active transport the way a human edits it: the two value
# lines, in place (a UDP listener stands in for the ship feed here).
s = re.sub(r'kind = "tcp-client"', 'kind = "udp"', s, count=1)
s = re.sub(r'connect = "[^"]*"', f'bind = "127.0.0.1:{udp}"', s, count=1)
open(p, "w").write(s)
PY

# Section 9 stand-in: a local broker and the sink registering the minted key.
nats-server -p "$PORT" &>/dev/null &
"$BIN/ajar-sink" mint stranger-1 "$WORK/keys"
cat > "$WORK/sink.toml" <<SINK
nats_url = "nats://127.0.0.1:$PORT"
subject = "ajar.ingest.>"
database = "$WORK/sink.db"
sources_dir = "$WORK/keys"
SINK
"$BIN/ajar-sink" run "$WORK/sink.toml" &>"$WORK/sink.log" &
disown -a

# Section 7f: the doctor signs off the setup before the connector runs.
"$BIN/ajar-doctor" "$WORK/ais.toml" --sources-dir "$WORK/keys" --timeout-secs 5

# Run the connector and feed it one real AIS sentence over UDP.
"$BIN/ajar-ais-nmea" "$WORK/ais.toml" &>"$WORK/connector.log" &
disown -a
sleep 1
python3 - "$UDP_PORT" <<'PY'
import socket, sys, time
sent = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(20):
    sock.sendto(sent, ("127.0.0.1", int(sys.argv[1])))
    time.sleep(0.5)
PY

# The finish line: the sink holds a verified, stored, governed event.
deadline=$(( $(date +%s) + 60 ))
while true; do
  if "$BIN/ajar-sink" stats "$WORK/sink.toml" 2>/dev/null | grep -q "stranger-1"; then
    break
  fi
  [ "$(date +%s)" -lt "$deadline" ] || {
    echo "::error::no governed event arrived"; cat "$WORK/connector.log" "$WORK/sink.log"; exit 1;
  }
  sleep 1
done

secs=$(( $(date +%s) - t0 ))
echo "first governed event in ${secs}s (budget ${BUDGET_SECS}s)"
echo "quickstart stopwatch: first governed event in ${secs}s (budget ${BUDGET_SECS}s)" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
[ "$secs" -le "$BUDGET_SECS" ] || { echo "::error::quickstart took ${secs}s, budget is ${BUDGET_SECS}s"; exit 1; }
