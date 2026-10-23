<!-- SPDX-License-Identifier: Apache-2.0 -->
# Provenance of the vendored SAPIENT schema

The `.proto` files under `sapient_msg/` are the published BSI Flex 335
(SAPIENT) protobuf definitions, copied verbatim from the Defence Science and
Technology Laboratory's public repository:

| | |
|---|---|
| Source | https://github.com/dstl/SAPIENT-Proto-Files |
| Commit | `244a741c13bcee628f84944aef91e4a66854bd7d` |
| Contents | `bsi_flex_335_v1_0/`, `bsi_flex_335_v2_0/`, `proto_options.proto` |
| Licence | Apache License 2.0, Crown copyright 2023; see `LICENCE.txt` beside this file |

They are compiled at build time by `../build.rs` with the vendored protoc and
prost, and are not edited here. To take a newer release of the schema, replace
the directories wholesale, record the new commit above, and run the wire
crate's tests: the pinned-encoding test fails if a message's bytes change.
