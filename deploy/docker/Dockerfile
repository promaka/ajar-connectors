# SPDX-License-Identifier: Apache-2.0
#
# Reference connector image — multi-stage, distroless, non-root. As written it
# builds the Rust `synthetic-radar` example; for your own connector, change the
# build target and the copied binary name. The runtime pairs with the chart's
# securityContext (runAsUser: 65532 — distroless nonroot's numeric uid).
#
# Build from the REPO ROOT:
#   docker build -f deploy/docker/Dockerfile -t registry.you.mil/acme-radar:1.0.0 .

FROM rust:1.96-bookworm AS build
WORKDIR /build
COPY rust ./rust
COPY vendor ./vendor
# synthetic-radar lives in the examples workspace; ajar-connector's build.rs uses
# a vendored protoc, so no system protoc is needed.
RUN cargo build --release --manifest-path rust/examples/Cargo.toml -p synthetic-radar

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="ajar connector (reference image)" \
      org.opencontainers.image.description="REFERENCE / EXAMPLE ONLY — builds the synthetic-radar example. Not for production; build your own connector image from your code." \
      org.opencontainers.image.source="https://github.com/promaka/ajar-connectors" \
      org.opencontainers.image.licenses="Apache-2.0" \
      ajar.reference-only="true"
COPY --from=build /build/rust/examples/target/release/synthetic-radar /usr/local/bin/connector
USER nonroot
ENTRYPOINT ["/usr/local/bin/connector"]
