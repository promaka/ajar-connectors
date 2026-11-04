<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connector (Python)

The Python SDK for building byte-compatible connectors to Ajar. Types are
generated from the same vendored `event.proto` as the Rust/Go/C++ SDKs, so this
SDK reproduces the **same** golden vectors.

## Try the template in 10 seconds

```bash
cd python
pip install -e .                     # or: pip install protobuf cryptography
echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
  | PYTHONPATH=. python examples/connector_template.py --dry-run
# -> 019e... -> ajar.ingest.demo-connector (196 sealed bytes)  [dry-run]
```

You just built and signed a canonical Ajar event. To make it yours, edit the one
function marked `EDIT` in [examples/connector_template.py](examples/connector_template.py).

To run it for real, with a key from `scripts/gen-connector-key.sh`:

```bash
AJAR_SIGNING_SEED=connector.seed AJAR_SOURCE_ID=acme-radar-1 \
NATS_URL=nats://nats.example:4222 PYTHONPATH=. python examples/connector_template.py
```

## Use it in code

```python
from ajar_connector import EventBuilder, canonical_bytes, seal, SigningKey

event = (
    EventBuilder("acme-radar-1", "mim:aircraft")
    .new_id().now()
    .location(26.4, 50.9, 11000.0)
    .confidence(0.94)
    .build()
)
sealed = seal(canonical_bytes(event), SigningKey.from_seed(my_seed))  # 64-byte sig ++ canonical
```

## Run the checks

```bash
cd python
python -m pytest                                   # unit tests
PYTHONPATH=. python conformance/golden_vectors.py   # the byte-compat gate
```

## Streaming example

```bash
pip install -e ".[examples]"                        # adds nats-py
PYTHONPATH=. python examples/synthetic_radar.py      # publish to a local Core
PYTHONPATH=. python examples/synthetic_radar.py --dry-run --ticks 3   # no infra
```

Both examples read `NATS_URL`, `AJAR_SOURCE_ID`, `AJAR_INGEST_PREFIX` and
`AJAR_SIGNING_SEED`. The template also reads `AJAR_TLS_CA`, `AJAR_TLS_CERT`,
`AJAR_TLS_KEY` for mutual TLS and `AJAR_HEALTH_ADDR` for `/healthz` and `/metrics`.
With `AJAR_SIGNING_SEED` unset, the radar mints a throwaway key for that run, so a
registry that has never seen the key refuses its events.

See the full [onboarding guide](../ONBOARDING.md) for data flow, deployment
topology, key generation, and troubleshooting.

> The conformance gate and `--dry-run` need only `protobuf` + `cryptography`.
> `nats-py` is an `examples` extra, kept out of the SDK's core dependencies.
