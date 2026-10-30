// SPDX-License-Identifier: Apache-2.0
//! The native-feed transport checks: a multicast join, a serial device, a DDS
//! domain, a pcap capture.

use std::time::Duration;

use ajar_connector_common as common;

use crate::report::Finding;

pub(crate) fn check(
    out: &mut Vec<Finding>,
    transport: Option<&common::Transport>,
    timeout: Duration,
) {
    match transport {
        Some(common::Transport::UdpMulticast {
            bind,
            group,
            interface,
        }) => {
            // SO_REUSE makes the join safe next to a running connector, and it
            // runs the connector's own interface selection.
            match common::udp::open(bind, Some(group), interface.as_deref()) {
                Ok(src) => out.push(Finding::ok("transport", {
                    use common::FrameSource as _;
                    format!("multicast join works ({})", src.describe())
                })),
                Err(e) => out.push(Finding::fail(
                    "transport",
                    format!("{e:#}"),
                    "The connector will fail the same way. On a dual-homed box, set \
                     transport.interface to the IP of the NIC on the surveillance \
                     network (or put that IP in bind), so the group is joined where \
                     the traffic actually is.",
                )),
            }
        }
        #[cfg(feature = "serial")]
        Some(common::Transport::Serial { device, baud }) => check_serial_device(out, device, *baud),
        #[cfg(feature = "dds")]
        Some(common::Transport::Dds(opts)) => match common::dds::probe(opts, timeout) {
            Ok(probe) => out.push(dds_verdict(opts, &probe, timeout)),
            Err(e) => out.push(Finding::fail(
                "transport",
                format!("{e:#}"),
                "The connector will fail the same way. Check the domain id and, on a \
                 dual-NIC box, set transport.interface_ip to the address of the NIC \
                 on the DDS network.",
            )),
        },
        Some(common::Transport::PcapReplay { path, port, .. }) => {
            match std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("reading capture {path}: {e}"))
                .and_then(|data| common::replay::parse_pcap(&data, *port))
            {
                Ok(cap) => out.push(Finding::ok(
                    "transport",
                    format!(
                        "capture {path} parses: {} datagrams to replay ({} skipped as noise)",
                        cap.datagrams.len(),
                        cap.skipped
                    ),
                )),
                Err(e) => out.push(Finding::fail(
                    "transport",
                    format!("{e:#}"),
                    "The connector will refuse the same capture. The error above names \
                     the fix (a pcapng needs converting; an empty result usually means \
                     the port filter does not match what was recorded).",
                )),
            }
        }
        _ => {}
    }
}

#[cfg(feature = "serial")]
fn check_serial_device(out: &mut Vec<Finding>, device: &str, baud: u32) {
    if std::fs::metadata(device).is_err() {
        out.push(Finding::fail(
            "transport",
            format!("serial device {device} does not exist"),
            "Nothing is at that path: check the adapter is plugged in and the port \
             name (ls /dev/tty*; a USB adapter is usually /dev/ttyUSB0 or \
             /dev/ttyACM0, and the name can shift when replugged).",
        ));
        return;
    }
    // Non-blocking: a tty open without O_NONBLOCK can hang on carrier-detect.
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(target_os = "linux")]
        const O_NONBLOCK: i32 = 0o4000;
        #[cfg(not(target_os = "linux"))]
        const O_NONBLOCK: i32 = 0x0004;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(device)
    };
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new().read(true).open(device);
    match opened {
        Ok(_) => out.push(Finding::ok(
            "transport",
            format!("serial device {device} present and readable ({baud} baud configured)"),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => out.push(Finding::fail(
            "transport",
            format!("serial device {device} exists but this user cannot read it"),
            "Add the connector's service user to the port's group (usually \
             `usermod -aG dialout <user>`, then log in again), or fix the \
             device permissions. The connector would retry forever and \
             publish nothing.",
        )),
        Err(e) => out.push(Finding::fail(
            "transport",
            format!("serial device {device}: {e}"),
            "The device exists but cannot be opened; check nothing else holds \
             it exclusively and that it is a real serial port.",
        )),
    }
}

/// DDS is silent when a subscription does not pair (topic, type name,
/// partition or QoS differ), so the verdict reads what the bounded probe saw.
#[cfg(feature = "dds")]
fn dds_verdict(opts: &common::dds::Options, probe: &common::dds::Probe, wait: Duration) -> Finding {
    let secs = wait.as_secs();
    let same_topic: Vec<&(String, String)> = probe
        .publishers
        .iter()
        .filter(|(name, _)| name == &opts.topic)
        .collect();
    let exact = same_topic.iter().any(|(_, ty)| ty == &opts.type_name);
    let other_type = same_topic
        .iter()
        .find(|(_, ty)| ty != &opts.type_name)
        .map(|(_, ty)| ty.clone());
    match (probe.matched, probe.first_sample_len) {
        (true, Some(n)) => Finding::ok(
            "transport",
            format!("dds publisher matched on {opts}; first sample {n} bytes"),
        ),
        // This stack matches on topic name alone, so a publisher of the same
        // topic under another type name looks matched and silent; its own
        // announcement says why.
        (true, None) if !exact && other_type.is_some() => type_mismatch(opts, other_type),
        (true, None) => Finding::warn(
            "transport",
            format!("dds publisher matched on {opts} but sent nothing in {secs} s"),
            "A matched publisher that stays silent is usually idle (a radar between \
             detections, a status topic that reports on change), or it keeps history \
             only for readers that joined earlier. Wait for the source to emit, or \
             ask its owner how often it publishes.",
        ),
        (false, _) if exact => Finding::fail(
            "transport",
            format!("a publisher of {opts} exists but did not pair with this reader"),
            "Same topic, same type, no match: the QoS disagrees or the publisher is in a \
             named partition. If reliability = \"reliable\" is set, the publisher is \
             best-effort: use \"best-effort\", which pairs with either. This transport \
             joins the default partition only.",
        ),
        (false, _) if other_type.is_some() => type_mismatch(opts, other_type),
        (false, _) if probe.publishers.is_empty() => Finding::fail(
            "transport",
            format!("no dds publisher matched on {opts}"),
            format!(
                "No publisher of anything was seen in {secs} s: nothing DDS is reachable \
                 from this box on domain {}. Check the domain id, that the DDS LAN is \
                 the one this box is on (transport.interface_ip on a dual-NIC box), and \
                 that multicast is not filtered.",
                opts.domain
            ),
        ),
        (false, _) => {
            let mut names: Vec<&str> = probe.publishers.iter().map(|(n, _)| n.as_str()).collect();
            names.dedup();
            Finding::fail(
                "transport",
                format!("no dds publisher matched on {opts}"),
                format!(
                    "The domain is reachable (publishing: {}) but nothing publishes {:?}. \
                     Check the topic name; the doctor lists what it can hear.",
                    names.join(", "),
                    opts.topic
                ),
            )
        }
    }
}

#[cfg(feature = "dds")]
fn type_mismatch(opts: &common::dds::Options, other_type: Option<String>) -> Finding {
    let other = other_type.unwrap_or_default();
    Finding::fail(
        "transport",
        format!(
            "dds topic {:?} is published under type name {other:?}, not {:?}",
            opts.topic, opts.type_name
        ),
        format!("DDS pairs only on an exact type name. Set type_name = {other:?}."),
    )
}

#[cfg(all(test, feature = "dds"))]
mod dds_verdict_tests {
    use super::*;
    use crate::report::Status;
    use common::dds::{Options, Probe};
    use common::{DdsPayload, DdsReliability};

    const WAIT: Duration = Duration::from_secs(5);

    fn opts() -> Options {
        Options {
            domain: 0,
            topic: "RadarAsterix".into(),
            type_name: "Radar::AsterixBlock".into(),
            reliability: DdsReliability::BestEffort,
            payload: DdsPayload::Octets,
            interface_ip: None,
        }
    }

    fn probe(matched: bool, sample: Option<usize>, publishers: &[(&str, &str)]) -> Probe {
        Probe {
            matched,
            first_sample_len: sample,
            publishers: publishers
                .iter()
                .map(|(t, ty)| (t.to_string(), ty.to_string()))
                .collect(),
        }
    }

    #[test]
    fn matched_publisher_with_sample_passes() {
        let f = dds_verdict(
            &opts(),
            &probe(true, Some(28), &[("RadarAsterix", "Radar::AsterixBlock")]),
            WAIT,
        );
        assert_eq!(f.status, Status::Ok);
        assert!(f.detail.contains("28 bytes"), "{}", f.detail);
    }

    #[test]
    fn matched_topic_under_other_type_names_it() {
        let f = dds_verdict(
            &opts(),
            &probe(true, None, &[("RadarAsterix", "Other::Type")]),
            WAIT,
        );
        assert_eq!(f.status, Status::Fail);
        assert!(
            f.fix
                .as_deref()
                .unwrap_or("")
                .contains("type_name = \"Other::Type\""),
            "{:?}",
            f.fix
        );
    }

    #[test]
    fn unmatched_topic_under_other_type_names_it() {
        let f = dds_verdict(
            &opts(),
            &probe(false, None, &[("RadarAsterix", "Other::Type")]),
            WAIT,
        );
        assert_eq!(f.status, Status::Fail);
        assert!(f.detail.contains("Other::Type"), "{}", f.detail);
    }

    #[test]
    fn idle_matched_publisher_is_a_warning() {
        let f = dds_verdict(
            &opts(),
            &probe(true, None, &[("RadarAsterix", "Radar::AsterixBlock")]),
            WAIT,
        );
        assert_eq!(f.status, Status::Warn);
        assert!(f.detail.contains("5 s"), "{}", f.detail);
        assert!(
            f.fix.as_deref().unwrap_or("").contains("idle"),
            "{:?}",
            f.fix
        );
    }

    #[test]
    fn unpaired_exact_match_points_at_qos_and_partition() {
        let mut o = opts();
        o.reliability = DdsReliability::Reliable;
        let f = dds_verdict(
            &o,
            &probe(false, None, &[("RadarAsterix", "Radar::AsterixBlock")]),
            WAIT,
        );
        assert_eq!(f.status, Status::Fail);
        let fix = f.fix.unwrap_or_default();
        assert!(
            fix.contains("best-effort") && fix.contains("partition"),
            "{fix}"
        );
    }

    #[test]
    fn silent_domain_points_at_the_network() {
        let f = dds_verdict(&opts(), &probe(false, None, &[]), WAIT);
        assert_eq!(f.status, Status::Fail);
        let fix = f.fix.unwrap_or_default();
        assert!(
            fix.contains("interface_ip") && fix.contains("multicast"),
            "{fix}"
        );
        assert!(!fix.contains("topic name"), "{fix}");
    }

    #[test]
    fn reachable_domain_lists_what_it_heard() {
        let f = dds_verdict(
            &opts(),
            &probe(
                false,
                None,
                &[
                    ("Other", "X::Y"),
                    ("rt/chatter", "std_msgs::msg::dds_::String_"),
                ],
            ),
            WAIT,
        );
        assert_eq!(f.status, Status::Fail);
        let fix = f.fix.unwrap_or_default();
        assert!(fix.contains("rt/chatter") && fix.contains("Other"), "{fix}");
        assert!(fix.contains("\"RadarAsterix\""), "{fix}");
    }
}
