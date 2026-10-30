// SPDX-License-Identifier: Apache-2.0
//! What `ajar-up` says for a missing packet and for a file that is not one.

#[test]
fn missing_packet_says_what_a_packet_is() {
    let dir = tempfile::tempdir().unwrap();
    let Err(err) = ajar_up::packet::open(&dir.path().join("nothere.tar"), &dir.path().join("w"))
    else {
        panic!("a missing packet must be refused");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("nothere.tar"), "{msg}");
    assert!(msg.contains("your operator sent"), "{msg}");
}

#[test]
fn non_tar_is_named_not_a_packet() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.tar");
    std::fs::write(&junk, b"this is not a tar archive\n").unwrap();
    let Err(err) = ajar_up::packet::open(&junk, &dir.path().join("w")) else {
        panic!("junk must be refused");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("is not a packet"), "{msg}");
    assert!(msg.contains("ajar onboard"), "{msg}");
}
