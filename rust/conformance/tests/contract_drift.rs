// SPDX-License-Identifier: Apache-2.0
//! Pins the SHA-256 of `vendor/contract/event.proto`; update the pin only with a re-sync from Core.

use sha2::{Digest, Sha256};

/// SHA-256 of `vendor/contract/event.proto` as last synced from Core. A stale copy
/// leaves the generated SDK a field behind, and Core rejects the events it produces.
const EXPECTED_CONTRACT_SHA256: &str =
    "e219d057e7c843a29bf7f042b91135590af2dadead61c1d91f649bceabae8a1c";

#[test]
fn vendored_contract_matches_pinned_hash() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contract/event.proto"
    );
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let actual = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        actual, EXPECTED_CONTRACT_SHA256,
        "contract drifted: re-sync from core and update the pin"
    );
}
