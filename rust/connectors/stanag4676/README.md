<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-stanag4676: STANAG 4676 (NATO ISR Tracking) ingress

Ingress for STANAG 4676, the NATO ISR Tracking Standard (AEDP-12 Edition B).
A tracker associates observations into tracks with a stable id; this
connector turns its `nitsRoot` track messages into signed canonical Ajar
events, one per track point. It complements [`gmti`](../gmti): GMTI gives
untracked detections with a fresh id every dwell, 4676 gives tracks whose id
persists.

## Input

One whole `nitsRoot` XML message per frame. The decoder streams the XML and
matches on local element names only, so any namespace prefix (`ns2:`, a
default namespace, none) decodes the same way.

| Fact | Where it lives |
|---|---|
| Track id | `track/uid`, Base64 of a raw 16-byte UUID |
| Position | `tp/.../dynamics/pos`, in the coordinate system named by the `cs` attribute of `<dynamics>`. For `cs="WGS_84"`: `lat lon height`, degrees and metres |
| Velocity | `dynamics/vel`, same coordinate system. For WGS-84 the horizontal components are degrees per second and the third is metres per second up |
| Time | `message/baseTime` plus `tp/relTime` times `message/relTimeIncrement` (seconds); the point has no timestamp of its own |
| Status | `segment/status`, applied to every point in the segment |
| Identity, domain | `track/object/id1241/identity` and `environment` (STANAG 1241) |
| Class | `objectClass/code` (APP-6) |
| Label | `ConfidentialityInformation/Classification` and `PolicyIdentifier` (STANAG 4774) |
| Version | `nitsRoot/nitsVersion` |

Only the `uid` directly under `track` is the track id; the `uid` under
`segment` and `tp` is not read. A message with no tracks, such as a
detection-only message, yields no events; use [`gmti`](../gmti) for
detections.

Framing: a stream transport with `framing = "length-delimited"`, as in the
example config, takes any XML. A line transport (`file`, `dir`, `stdin`,
`exec`) works only when the producer writes each message on one line;
pretty-printed XML does not frame on lines.

## Output

Entity type `mim:object`, one event per track point. `[entity_map]` can map
an environment to a specific type (see Configuration).

**Identity.** The decoded track UUID, hyphenated, is `source_uid` and the
governed identity (`alt_id`, with `alt_id_standard` `STANAG4676`). It is
stable for the same object across messages. A `uid` that is not valid Base64
or shorter than 16 bytes gives no identity.

**Location.** Only for a WGS-84 position with at least latitude and longitude.
The altitude is the third value. When a point carries
several `<dynamics>` blocks, the WGS-84 one wins; otherwise the first.
Another coordinate system (ECEF, local Cartesian) is not projected: the event
has no location and carries `coordinate_system` and `position_raw` metadata.

**Time.** Reconstructed from the message base time as above, else receipt
time.

| Attribute | Unit | Source |
|---|---|---|
| `speed` | m/s, two decimals | WGS-84 horizontal velocity on a spherical Earth (radius 6 371 000 m) |
| `course` | degrees true, one decimal, 0 to 360 | direction of that velocity |
| `vertical_rate` | m/s, two decimals | third WGS-84 velocity component |
| `hostility` | MIM `HostilityCodeType` | STANAG 1241 identity, see below |
| `environment` | `AIR`, `LAND`, `SURFACE`, `SUBSURFACE`, `SPACE`, `UNKNOWN` | STANAG 1241 environment |
| `alt_id`, `alt_id_standard` | text | track UUID, `STANAG4676` |

Speed, course and vertical rate need a WGS-84 position and velocity.

**Hostility.** Every event carries one:

| STANAG 1241 identity | `hostility` |
|---|---|
| `FRIEND` | `Friend` |
| `ASSUMED_FRIEND` | `AssumedFriend` |
| `HOSTILE` | `Hostile` |
| `SUSPECT` | `Suspect` |
| `NEUTRAL` | `Neutral` |
| absent, `UNKNOWN` or anything else | `default_hostility`, else `Unknown` |

**Environment.** A domain, not a classification: AIR can be an aircraft, a
missile, a balloon or a bird, so the type stays `mim:object` and the domain
rides as the `environment` attribute. STANAG 1241's `SUB-SURFACE` becomes
`SUBSURFACE`. An absent environment is `UNKNOWN`. An unrecognised token is
`UNKNOWN`, with the wire value in `environment_source` metadata. On an
`[entity_map]` type that does not govern `environment`, such as
`mim:aircraft`, the value goes to metadata instead.

| Metadata | Content |
|---|---|
| `source_uid` | track UUID |
| `identity` | the STANAG 1241 identity, verbatim |
| `object_class` | APP-6 code from `objectClass/code` |
| `track_status` | `new`, `update`, `coast`, `drop`, `truth` or `unknown` from `INITIATING`, `MAINTAINING`, `SEARCHING`, `TERMINATED`, `GROUND_TRUTH` or anything else |
| `s4676_status` | the segment status, verbatim |
| `rel_time` | the point's native `relTime` |
| `vel_lat_dps`, `vel_lon_dps` | native WGS-84 velocity, degrees per second |
| `nits_version` | `nitsVersion` |
| `nits_classification`, `nits_policy_identifier` | the STANAG 4774 label, verbatim |
| `environment_source` | unrecognised environment token |
| `coordinate_system`, `position_raw` | non-WGS-84 `cs` and position values |

`object_class` and `track_status` go to metadata because no type in the
vendored ontology governs them yet; they become attributes on a type that
does.

**Policy tags.** The STANAG 4774 label becomes the policy tags Core reads.
`NATO SECRET` gives `class:secret` and `policy:NATO`; a stated
`PolicyIdentifier` sets the policy. A non-empty label that does not normalise
is tagged `class:top-secret`.

**Payload.** The whole `<track>` element, start tag to end tag, verbatim.
Every point of a track carries the same element.

## Configuration

Start from [`stanag4676.example.toml`](stanag4676.example.toml). The
connector has no `[options]`.

- `default_hostility`: the hostility for a track whose identity is absent or
  not one of the five mapped values. Unset, `Unknown`.
- `[entity_map]`: environment to entity type, for example
  `AIR = "mim:aircraft"`. A key may be the wire token (`SUB-SURFACE`) or the
  normalised code (`SUBSURFACE`). Unmapped environments stay `mim:object`.

## Behaviour

- A track's `object` block follows its points in document order, so points
  are buffered and emitted when `</track>` closes. A track that never closes
  emits nothing.
- Messages are independent; nothing is correlated across frames.
- A garbled `pos` or `vel` (any token not a number) is ignored, so the point
  has no fix rather than a shifted one.
- Malformed XML rejects the whole frame, including tracks before the fault.

## Limits

- Non-WGS-84 coordinate systems are kept in metadata, not projected.
- `objectClass` is not mapped to a MIM type; that needs an APP-6 to MIM
  mapping.
- Self-closing elements (`<dynamics cs="..."/>`) carry no position and are
  ignored.

## Run

```sh
cp stanag4676.example.toml stanag4676.toml   # edit source_id, key path, [transport]
ajar-stanag4676 ./stanag4676.toml
ajar-stanag4676 --profile ./stanag4676.toml  # print the profile the operator registers
```

## Conformance

`cargo test -p ajar-stanag4676` decodes a WGS-84 air track whose identity
follows its points, reconstructs the point time, maps the confidentiality
label to policy tags, checks the event against Core's content contract and
the seal against the published contract key, and fuzzes the decoder with
arbitrary and track-shaped input. The field model is cross-checked against
the `bradh/jim` Edition B reference implementation and its sample messages;
the test fixtures here are written for these tests.
