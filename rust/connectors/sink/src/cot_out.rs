// SPDX-License-Identifier: Apache-2.0
//! Render verified events as Cursor-on-Target onto mesh SA multicast, so a TAK
//! client on the same network shows the picture with no server and no setup.
//!
//! This is the demo's eyes, not an egress path. Production egress is Ajar Core
//! rendering governed CoT for `ajar-tak-egress` to relay to a TAK Server; this
//! renders only what THIS sink has verified, addressed to ATAK's default mesh
//! SA group (239.2.3.1:6969), and is off unless configured. Best-effort by
//! design: a send failure is counted, never fatal, and never touches the store.

use std::net::UdpSocket;

use ajar_connector::Event;

/// ATAK's default mesh SA multicast group.
pub const DEFAULT_GROUP: &str = "239.2.3.1:6969";

/// How long a rendered track stays fresh on the map. Publishers in the demo
/// re-report well inside this, so markers move rather than blink.
const STALE_SECONDS: i64 = 60;

pub struct CotOut {
    socket: UdpSocket,
    group: String,
}

impl CotOut {
    /// `interface` pins which network the picture goes out on — the address of
    /// the interface your TAK clients share. Multicast otherwise leaves on the
    /// OS default route, which on a multi-homed host is routinely the wrong one
    /// and fails silently: sends succeed, nothing arrives.
    pub fn open(group: &str, interface: Option<&str>) -> anyhow::Result<CotOut> {
        // socket2 for the interface pin; std's UdpSocket has no such knob.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_multicast_loop_v4(true)?;
        if let Some(addr) = interface {
            let ip: std::net::Ipv4Addr = addr
                .parse()
                .map_err(|_| anyhow::anyhow!("cot interface {addr:?} is not an IPv4 address"))?;
            socket.set_multicast_if_v4(&ip)?;
        }
        socket.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
        Ok(CotOut {
            socket: socket.into(),
            group: group.to_string(),
        })
    }

    /// Render and send one verified event. Events with no location are skipped:
    /// CoT is a map protocol, and a point at (0,0) is a lie, not a default.
    pub fn send(&self, event: &Event) -> anyhow::Result<bool> {
        let Some(xml) = render(event) else {
            return Ok(false);
        };
        self.socket.send_to(xml.as_bytes(), &self.group)?;
        Ok(true)
    }
}

fn attribute<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event
        .attributes
        .iter()
        .find(|a| a.key == key)
        .map(|a| a.value.as_str())
}

fn metadata<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event
        .metadata
        .iter()
        .find(|m| m.key == key)
        .map(|m| m.value.as_str())
}

/// MIM 5.3 hostility -> CoT affiliation character (the ingress mapping, run in
/// reverse; tak-cot's table is the source of truth for the forward direction).
fn affiliation(event: &Event) -> &'static str {
    match attribute(event, "hostility") {
        Some("Friend") => "f",
        Some("AssumedFriend") => "a",
        Some("Hostile") => "h",
        Some("Suspect") => "s",
        Some("Neutral") => "n",
        Some("Pending") => "p",
        Some("Joker") => "j",
        Some("Faker") => "k",
        _ => "u",
    }
}

/// Battle dimension: the environment attribute decides when present, the entity
/// type otherwise, and unknown stays unknown rather than guessing air.
fn dimension(event: &Event) -> &'static str {
    match attribute(event, "environment") {
        Some("AIR") => "A",
        Some("LAND") => "G",
        Some("SURFACE") => "S",
        Some("SUBSURFACE") => "U",
        Some("SPACE") => "P",
        Some(_) => "X",
        None => match event.entity_type.as_str() {
            "mim:aircraft" => "A",
            "mim:vessel" => "S",
            "mim:land-vehicle" => "G",
            _ => "X",
        },
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// One SA event, or None when there is no position to put on a map. The uid is
/// the stable track identity (source_uid, else the native id, else the event
/// id), so a moving track updates one marker instead of piling up contacts.
fn render(event: &Event) -> Option<String> {
    let loc = event.location.as_ref()?;
    let uid = metadata(event, "source_uid")
        .or_else(|| metadata(event, "native_id"))
        .unwrap_or(&event.id);
    let callsign = attribute(event, "callsign").unwrap_or(uid);
    let start = &event.timestamp;
    let stale = stale_after(start).unwrap_or_else(|| start.clone());

    Some(format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<event version="2.0" uid="{uid}" type="a-{aff}-{dim}" "#,
            r#"time="{time}" start="{time}" stale="{stale}" how="m-g">"#,
            r#"<point lat="{lat}" lon="{lon}" hae="{hae}" ce="9999999" le="9999999"/>"#,
            r#"<detail><contact callsign="{callsign}"/></detail>"#,
            r#"</event>"#
        ),
        uid = escape(uid),
        aff = affiliation(event),
        dim = dimension(event),
        time = escape(start),
        stale = escape(&stale),
        lat = loc.latitude,
        lon = loc.longitude,
        hae = loc.altitude_m,
        callsign = escape(callsign),
    ))
}

/// `timestamp + STALE_SECONDS`, computed on the RFC 3339 string the event
/// already carries so no clock library enters the crate.
fn stale_after(rfc3339: &str) -> Option<String> {
    // Seconds field is at a fixed offset in "YYYY-MM-DDTHH:MM:SS...".
    let (date, time) = rfc3339.split_once('T')?;
    let hms: Vec<&str> = time.trim_end_matches('Z').splitn(3, ':').collect();
    if hms.len() != 3 {
        return None;
    }
    let (h, m) = (hms[0].parse::<i64>().ok()?, hms[1].parse::<i64>().ok()?);
    let s = hms[2].split(['.', '+']).next()?.parse::<i64>().ok()?;
    let total = h * 3600 + m * 60 + s + STALE_SECONDS;
    // A stale time past midnight clamps to end of day: one shortened marker
    // lifetime at day rollover is invisible in a demo, and this stays arithmetic
    // on the string rather than a calendar dependency.
    let total = total.min(24 * 3600 - 1);
    Some(format!(
        "{date}T{:02}:{:02}:{:02}Z",
        total / 3600,
        (total % 3600) / 60,
        total % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    fn event(entity: &str) -> EventBuilder {
        EventBuilder::new("demo-radar", entity)
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(25.27, 51.52, 10600.0)
    }

    #[test]
    fn renders_a_friendly_aircraft_as_a_f_a() {
        let ev = event("mim:aircraft")
            .attribute("callsign", "AJX-01")
            .attribute("hostility", "Friend")
            .metadata("source_uid", "4CA2D6")
            .build()
            .unwrap();
        let xml = render(&ev).unwrap();
        assert!(xml.contains(r#"type="a-f-A""#), "{xml}");
        assert!(xml.contains(r#"uid="4CA2D6""#));
        assert!(xml.contains(r#"callsign="AJX-01""#));
        assert!(xml.contains(r#"stale="2026-06-10T08:01:00Z""#));
    }

    #[test]
    fn environment_beats_the_entity_type_for_the_dimension() {
        let ev = event("mim:object")
            .attribute("environment", "SUBSURFACE")
            .build()
            .unwrap();
        assert!(render(&ev).unwrap().contains(r#"type="a-u-U""#));
    }

    #[test]
    fn an_event_without_a_location_is_not_rendered() {
        let ev = EventBuilder::new("demo-radar", "mim:aircraft")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .build()
            .unwrap();
        assert!(render(&ev).is_none());
    }

    #[test]
    fn xml_content_is_escaped() {
        let ev = event("mim:vessel")
            .attribute("callsign", r#"a<b>&"c"#)
            .build()
            .unwrap();
        let xml = render(&ev).unwrap();
        assert!(xml.contains("a&lt;b&gt;&amp;&quot;c"));
        assert!(!xml.contains(r#"a<b"#));
    }

    #[test]
    fn every_hostility_maps_to_its_affiliation() {
        for (h, want) in [
            ("Friend", "a-f-"),
            ("AssumedFriend", "a-a-"),
            ("Hostile", "a-h-"),
            ("Suspect", "a-s-"),
            ("Neutral", "a-n-"),
            ("Pending", "a-p-"),
            ("Joker", "a-j-"),
            ("Faker", "a-k-"),
            ("Unknown", "a-u-"),
        ] {
            let ev = event("mim:aircraft")
                .attribute("hostility", h)
                .build()
                .unwrap();
            assert!(render(&ev).unwrap().contains(want), "{h}");
        }
    }
}
