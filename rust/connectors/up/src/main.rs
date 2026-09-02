// SPDX-License-Identifier: Apache-2.0
//! CLI for ajar-up. Exit 0 on success, 1 on failure, 2 on usage.

use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "usage: ajar-up <packet.tar> [--dir <workdir>] [--signing-key <seed>]\n\
         \x20                        [--no-exec] [--to-tak <host:port>] [--to-http <url>]\n\
         \x20                        [--timeout-secs <n>]\n\
         \n\
         One command from your operator's packet to flowing events. Verifies the\n\
         packet signature and checksums, places credentials, writes the config,\n\
         runs the doctor preflight, and starts the right connector (producer\n\
         packets) or a verified tap on governed egress (consumer packets).\n\
         \n\
         --signing-key   your registered seed (vendor-holds-key flow)\n\
         --no-exec       prepare and preflight, print the run command, do not start\n\
         --check         verify and validate the packet, then exit 0 (both roles)\n\
         --to-tak        write a ready TAK egress config instead of the tap\n\
         --to-http       write a ready HTTP egress config instead of the tap\n\
         --dir           where the packet unpacks (default: alongside the packet)"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut packet_path: Option<PathBuf> = None;
    let mut dir: Option<PathBuf> = None;
    let mut signing_key: Option<PathBuf> = None;
    let mut no_exec = false;
    let mut check = false;
    let mut to_tak: Option<String> = None;
    let mut to_http: Option<String> = None;
    let mut timeout_secs: u64 = 5;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dir" => dir = it.next().map(PathBuf::from).or_else(|| usage()),
            "--signing-key" => signing_key = it.next().map(PathBuf::from).or_else(|| usage()),
            "--no-exec" => no_exec = true,
            "--check" => check = true,
            "--to-tak" => to_tak = it.next().or_else(|| usage()),
            "--to-http" => to_http = it.next().or_else(|| usage()),
            "--timeout-secs" => match it.next().and_then(|v| v.parse().ok()) {
                Some(v) => timeout_secs = v,
                None => usage(),
            },
            "-h" | "--help" => usage(),
            other if packet_path.is_none() && !other.starts_with('-') => {
                packet_path = Some(PathBuf::from(other))
            }
            _ => usage(),
        }
    }
    let Some(packet_path) = packet_path else {
        usage()
    };
    let dir = dir.unwrap_or_else(|| {
        let stem = packet_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "packet".into());
        packet_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(stem)
    });

    let result = async {
        let packet = ajar_up::packet::open(&packet_path, &dir)?;
        match packet.role() {
            "producer" => {
                let r = ajar_up::producer::run(
                    &packet,
                    &ajar_up::producer::Options {
                        signing_key,
                        // --check is verify+place+configure+preflight, then exit:
                        // exactly what --no-exec does, minus printing the command
                        // as the point.
                        no_exec: no_exec || check,
                        timeout_secs,
                    },
                )
                .await;
                if r.is_ok() && check {
                    println!(
                        "check passed: producer packet for {}",
                        packet.manifest.source_id
                    );
                }
                r
            }
            "consumer" => {
                if check {
                    let r = ajar_up::consumer::check(&packet);
                    if r.is_ok() {
                        println!(
                            "check passed: consumer packet for {}",
                            packet.manifest.source_id
                        );
                    }
                    r
                } else {
                    ajar_up::consumer::run(&packet, &ajar_up::consumer::Options { to_tak, to_http })
                        .await
                }
            }
            other => anyhow::bail!(
                "this packet\'s role is {other:?}, which this ajar-up does not know; \
                 update ajar-up"
            ),
        }
    }
    .await;

    if let Err(e) = result {
        eprintln!("ajar-up: {e:#}");
        std::process::exit(1);
    }
}
