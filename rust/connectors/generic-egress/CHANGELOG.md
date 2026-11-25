<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: generic-egress

Changes to this one package, released on its own as the tag `generic-egress-vX.Y.Z`.
The format is based on Keep a Changelog (https://keepachangelog.com). The
version follows semver, and the entity types and attributes it emits count as
its public interface: renaming or removing one is a major bump (see
CONTRIBUTING.md, "Releases").

## [Unreleased]

### Added

- `template`: a JSON body in the consumer's own shape, with `"${path}"`
  placeholders and `number` and `text` filters, as an alternative to
  `[mapping]`. A template must place the event id, the policy tags and, unless
  `unmapped = "refuse"`, the unmapped content.
- `[deliver.oauth]`: OAuth 2.0 client credentials for the consumer's API, with
  the token refreshed before it expires and after a 401.
- `rest-tracks.example.toml`.

### Changed

- The last failed delivery attempt is not followed by a wait.
- Breaking: the config uses the shape every egress connector shares, which
  `ajar-connectors join` writes. `subject` is renamed `egress_subject`,
  `[deliver] url` moves to the top-level `target`, and `egress_verifying_key`
  is a path to a file of hex only, no longer the key inline or as raw bytes.

## [0.6.7] - 2026-11-02

### Changed

- Code and documentation clean-up: source comments trimmed, the README rewritten as
  the single user-facing document. Some log lines and error messages are reworded.
  Emitted entity types, attributes and config keys are unchanged.

## [0.6.6] - 2026-10-27

### Changed

- First release on its own, as the tag `generic-egress-v0.6.6`: its own image,
  tarball and GitHub release. The image carries the `ajar.connector.version` and
  `ajar.contract` labels. No functional change since 0.6.5.

## [0.6.5] - 2026-10-24

The last release of the whole suite at one version. History up to here is in
the [repository changelog](../../../CHANGELOG.md).
