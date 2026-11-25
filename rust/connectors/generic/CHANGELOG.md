<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: generic

Changes to this one package, released on its own as the tag `generic-vX.Y.Z`.
The format is based on Keep a Changelog (https://keepachangelog.com). The
version follows semver, and the entity types and attributes it emits count as
its public interface: renaming or removing one is a major bump (see
CONTRIBUTING.md, "Releases").

## [Unreleased]

## [0.7.0] - 2026-11-25

### Added

- JSON pointers (RFC 6901) as field settings, so nested fields such as
  `"/position/lat"` can be mapped.
- `[mapping.values.<attribute>]` tables that translate a feed's codes into an
  attribute's vocabulary. Table values are checked against the ontology at startup.
- `entity_type_field` with `[mapping.entity_types]`, so one feed can emit
  several entity types; `entity_type` is the fallback.
- The `rest-poll` transport is built in by default, with POST bodies, OAuth
  client credentials and `records` to split a JSON array response into one
  frame per record. The binary grows by about 1.7 MB; `--no-default-features`
  leaves it out.
- `rest-tracks.example.toml`.

### Changed

- An unknown key in `[mapping]` is refused at startup instead of ignored.

## [0.6.7] - 2026-11-02

### Changed

- Code and documentation clean-up: source comments trimmed, the README rewritten as
  the single user-facing document. Some log lines and error messages are reworded.
  Emitted entity types, attributes and config keys are unchanged.

## [0.6.6] - 2026-10-27

### Changed

- First release on its own, as the tag `generic-v0.6.6`: its own image, tarball
  and GitHub release. The image carries the `ajar.connector.version` and
  `ajar.contract` labels. No functional change since 0.6.5.

## [0.6.5] - 2026-10-24

The last release of the whole suite at one version. History up to here is in
the [repository changelog](../../../CHANGELOG.md).
