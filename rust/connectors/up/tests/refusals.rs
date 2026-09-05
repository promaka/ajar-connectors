// SPDX-License-Identifier: Apache-2.0
//! The first two things a stranger can get wrong with `ajar-up`, and what they
//! read: a path that does not exist, and a file that is not a packet at all.

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ajar-up-refusal-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_missing_packet_says_what_a_packet_is() {
    let dir = scratch("missing");
    let Err(err) = ajar_up::packet::open(&dir.join("nothere.tar"), &dir.join("w")) else {
        panic!("a missing packet must be refused");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("nothere.tar"), "{msg}");
    assert!(msg.contains("your operator sent"), "{msg}");
}

#[test]
fn a_file_that_is_not_a_tar_is_named_as_not_a_packet() {
    let dir = scratch("junk");
    let junk = dir.join("junk.tar");
    std::fs::write(&junk, b"this is not a tar archive\n").unwrap();
    let Err(err) = ajar_up::packet::open(&junk, &dir.join("w")) else {
        panic!("junk must be refused");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("is not a packet"), "{msg}");
    assert!(msg.contains("ajar onboard"), "{msg}");
}
