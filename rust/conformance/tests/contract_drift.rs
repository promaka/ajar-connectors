// SPDX-License-Identifier: Apache-2.0
//! Contract-drift guard.
//!
//! `vendor/contract/event.proto` is a vendored copy of Ajar Core's event
//! contract. If Core adds or changes a field and this copy is not re-synced, the
//! generated SDK silently falls a field behind — and real Core rejects the
//! events the SDK produces (this is exactly how `metadata = 12` was missed).
//!
//! This test pins the SHA-256 of the vendored proto. Any edit fails it, forcing a
//! deliberate re-sync from Core and an update to the pin — the contract can never
//! drift unnoticed.

use sha2::{Digest, Sha256};

/// SHA-256 of `vendor/contract/event.proto`, last synced from Core. Update this
/// only together with a re-sync of the proto itself.
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
        "contract drifted — re-sync from core and update the pin"
    );
}
