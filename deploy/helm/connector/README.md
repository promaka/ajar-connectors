<!-- SPDX-License-Identifier: Apache-2.0 -->
# connector Helm chart

Deploys **a connector** into Kubernetes — the same clean way Core deploys (pairs
with the Core chart in `promaka/ajar`, `deploy/helm/ajar`; same conventions).
For clusters at a C2/hub or a forward outpost. The chart is **generic**: you
name a published connector (or bring your own image) and supply its TOML config. The chart renders the config into a
ConfigMap and passes its path as the connector's first argument, mounts the
signing key from a Secret, and sets the TLS and health environment the runtime
reads (`AJAR_TLS_CA` / `AJAR_TLS_CERT` / `AJAR_TLS_KEY`, `AJAR_HEALTH_ADDR`).

Identity, transport and key path come from the TOML, not the environment — set
`connector.config` to the contents of the connector's `<name>.example.toml`. A
release with neither `connector.config` nor `connector.existingConfigMap` is
rejected at template time rather than crash-looping in the cluster.

> It does **not** deploy NATS or Ajar Core — those are operator/core-side.

> **Registry access.** The published connector images are private. Your cluster
> needs a pull secret with `read:packages` for `ghcr.io/promaka`, referenced via
> `imagePullSecrets`, or the pods will fail to pull with `unauthorized`.

A reference connector image (multi-stage, distroless non-root) is at
[`deploy/docker/Dockerfile`](../../docker/Dockerfile).

## Quick start

```bash
# 1. Put your connector's 32-byte seed in a Secret (from scripts/gen-connector-key.sh):
kubectl create secret generic acme-radar-seed --from-file=seed=acme-radar.seed

# 2. Install, pointing at your image, source id, and NATS endpoint:
helm install acme-radar deploy/helm/connector \
  --set image.repository=registry.you.mil/acme-radar \
  --set image.tag=1.0.0 \
  --set connector.sourceId=acme-radar-1 \
  --set connector.natsUrl=nats://ajar-ajar-nats:4222 \
  --set signingSeed.existingSecret=acme-radar-seed
```

The connector reads the seed as a file (`AJAR_SIGNING_SEED` points at the mounted
path), exactly as the SDK's connector template / reference image does — so an
image built from `deploy/docker/Dockerfile` works with no changes.

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `image.repository` | `""` | **required** — your connector image |
| `image.tag` / `image.digest` | `latest` / `""` | set `digest` to pin by digest (recommended for prod) |
| `connector.sourceId` | `demo-connector` | must equal the `AJAR_SOURCE_ID` Ajar registered |
| `connector.ingestPrefix` | `ajar.ingest` | subject is `<prefix>.<sourceId>` |
| `connector.natsUrl` | `nats://ajar-ajar-nats:4222` | in-cluster NATS, or an external `tls://…` host |
| `signingSeed.existingSecret` | `""` | **recommended** — Secret holding the 32-byte seed |
| `signingSeed.secretKey` / `mountPath` | `seed` / `/etc/ajar/seed` | `AJAR_SIGNING_SEED` points at the mount |
| `signingSeed.create` / `valueBase64` | `false` / `""` | **dev only** — create the Secret inline; never in prod |
| `tls.existingSecret` / `mountPath` | `""` / `/etc/ajar/tls` | mounts mTLS certs + sets `AJAR_TLS_CERT/KEY/CA` |
| `networkPolicy.enabled` / `natsPort` | `false` / `4222` | egress-only-to-NATS (+ DNS), mirroring Core |
| `extraEnv` / `extraVolumes` / `extraVolumeMounts` | `[]` | escape hatches |

## Security posture (matches Core)

- `podSecurityContext`: `runAsNonRoot: true`, **`runAsUser: 65532`**
  (required — distroless's `nonroot` is a non-numeric user, so without an
  explicit numeric uid the pod fails `CreateContainerConfigError`),
  `seccompProfile: RuntimeDefault`.
- `securityContext`: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem:
  true`, all capabilities dropped.
- Optional `networkPolicy.enabled` restricts egress to NATS + DNS only.

## Guard rails

The chart refuses to render an unsafe/incomplete release:
- missing `image.repository` → templating error,
- no signing key (`existingSecret` unset and `create` false) → templating error.

## Notes

- **Production mTLS to NATS:** set `tls.existingSecret` to a Secret with
  `tls.crt` / `tls.key` / `ca.crt`; the chart mounts them and exports
  `AJAR_TLS_CERT` / `AJAR_TLS_KEY` / `AJAR_TLS_CA` for the connector to use.
- This chart packages a connector for k8s; the same connector binary also runs
  fine as a plain process or systemd unit at the edge — see the
  [onboarding guide](../../../ONBOARDING.md).
