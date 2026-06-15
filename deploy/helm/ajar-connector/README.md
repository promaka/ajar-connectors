<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connector Helm chart

Deploys **a connector** into Kubernetes — for clusters at a C2/hub or a
forward outpost. The chart is **generic**: you bring your built connector image
and its config; the chart wires up the signing key (from a Secret) and the
standard environment the SDK reads (`AJAR_SOURCE_ID`, `AJAR_INGEST_PREFIX`,
`NATS_URL`, `AJAR_SIGNING_SEED`).

> It does **not** deploy NATS or Ajar Core — those are operator/core-side.

## Quick start

```bash
# 1. Put your connector's 32-byte seed in a Secret (from scripts/gen-connector-key.sh):
kubectl create secret generic acme-radar-seed --from-file=seed=acme-radar.seed

# 2. Install, pointing at your image, source id, and NATS endpoint:
helm install acme-radar deploy/helm/ajar-connector \
  --set image.repository=registry.you.mil/acme-radar \
  --set image.tag=1.0.0 \
  --set connector.sourceId=acme-radar-1 \
  --set connector.natsUrl=tls://nats.you.mil:4222 \
  --set signingSeed.existingSecret=acme-radar-seed
```

The connector reads the seed as a file (`AJAR_SIGNING_SEED` points at the mounted
path), exactly as the SDK's connector template does — so a connector image built
from the template works with no changes.

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `image.repository` | `""` | **required** — your connector image |
| `image.tag` | `latest` | |
| `connector.sourceId` | `demo-connector` | must equal the `AJAR_SOURCE_ID` Ajar registered |
| `connector.ingestPrefix` | `ajar.ingest` | subject is `<prefix>.<sourceId>` |
| `connector.natsUrl` | `nats://nats:4222` | the endpoint Ajar gave you |
| `signingSeed.existingSecret` | `""` | **recommended** — Secret holding the 32-byte seed |
| `signingSeed.secretKey` | `seed` | key within that Secret |
| `signingSeed.mountPath` | `/etc/ajar/seed` | where it's mounted; `AJAR_SIGNING_SEED` points here |
| `signingSeed.create` / `valueBase64` | `false` / `""` | **dev only** — create the Secret inline; never in prod |
| `extraEnv` / `extraVolumes` / `extraVolumeMounts` | `[]` | escape hatches (e.g. mounting a NATS `.creds` for TLS auth) |

Hardened pod/container security contexts are on by default (non-root,
read-only root FS, all capabilities dropped); relax them per your image.

## Guard rails

The chart refuses to render an unsafe/incomplete release:
- missing `image.repository` → templating error,
- no signing key (`existingSecret` unset and `create` false) → templating error.

## Notes

- **Transport credentials / TLS:** if your NATS needs a `.creds` file or CA,
  mount it via `extraVolumes` / `extraVolumeMounts` and reference it from your
  connector image. The chart keeps the seed wiring opinionated and everything
  else as escape hatches.
- This chart packages a connector for k8s; the same connector binary also runs
  fine as a plain process or systemd unit at the edge — see the
  [onboarding guide](../../../ONBOARDING.md).
