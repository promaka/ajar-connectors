// SPDX-License-Identifier: Apache-2.0
//! Render verified events as Cursor-on-Target onto mesh SA multicast, so a TAK
//! client on the same network shows the picture with no server. A demo view, off
//! unless configured; production egress is Ajar Core with `ajar-tak-egress`.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use ajar_connector::Event;
use anyhow::Context;

/// ATAK's default mesh SA multicast group.
pub const DEFAULT_GROUP: &str = "239.2.3.1:6969";

/// How long a rendered track stays on the map without a new report.
const STALE_S: i64 = 60;

pub struct CotOut {
    socket: UdpSocket,
    group: String,
}

impl CotOut {
    /// `interface` is the IPv4 address of the interface the TAK clients share.
    /// Without it multicast leaves on the OS default route, which on a
    /// multi-homed host may be another network.
    pub fn open(group: &str, interface: Option<&str>) -> anyhow::Result<CotOut> {
        // socket2 for the interface pin; std's UdpSocket has no such knob.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_multicast_loop_v4(true)?;
        if let Some(addr) = interface {
            let ip: Ipv4Addr = addr
                .parse()
                .with_context(|| format!("cot interface {addr:?} is not an IPv4 address"))?;
            socket.set_multicast_if_v4(&ip)?;
        }
        socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
        Ok(CotOut {
            socket: socket.into(),
            group: group.to_string(),
        })
    }

    /// Render and send one verified event; an event with no location is skipped.
    pub fn send(&self, event: &Event) -> std::io::Result<()> {
        if let Some(xml) = render(event) {
            self.socket.send_to(xml.as_bytes(), &self.group)?;
        }
        Ok(())
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

/// MIM 5.3 hostility to CoT affiliation, the reverse of tak-cot's mapping.
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

/// Battle dimension from the environment attribute, else the entity type.
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
            "mim:vessel" | "mim:surface-vessel" => "S",
            "mim:subsurface-vessel" => "U",
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

/// One SA event, or None without a location. The uid is the track identity
/// (source_uid, else native_id, else the event id), so a moving track updates
/// one marker.
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

/// `timestamp + STALE_S`, as arithmetic on the RFC 3339 time of day.
fn stale_after(rfc3339: &str) -> Option<String> {
    let (date, time) = rfc3339.split_once('T')?;
    let mut hms = time.trim_end_matches('Z').splitn(3, ':');
    let (Some(h), Some(m), Some(s)) = (hms.next(), hms.next(), hms.next()) else {
        return None;
    };
    let (h, m) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
    let s = s.split(['.', '+']).next()?.parse::<i64>().ok()?;
    // Clamped to the end of the day, so a marker near midnight goes stale early.
    let total = (h * 3600 + m * 60 + s + STALE_S).min(24 * 3600 - 1);
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
    fn friendly_aircraft_renders_as_a_f_a() {
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
    fn environment_overrides_entity_type() {
        let ev = event("mim:object")
            .attribute("environment", "SUBSURFACE")
            .build()
            .unwrap();
        assert!(render(&ev).unwrap().contains(r#"type="a-u-U""#));
    }

    #[test]
    fn event_without_location_is_not_rendered() {
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
    fn hostility_maps_to_affiliation() {
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
