<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-feed-synthetic

One scenario, seven sensors, each on its real wire format. Use it to build a
fusion consumer before equipment arrives, or to commission connectors before
real feeds are switched in. Every feed is read by the real connector, so
replacing a generator with the actual sensor changes nothing else.

All sensors render one shared scenario: the same vessel is seen by AIS and by
radar, the same aircraft by ADS-B and by a system track, an emitter on the
vessel by an ESM receiver, and the uncrewed aircraft by its autopilot and by a
counter-UAS radar speaking SAPIENT. Each generator is tested against the
decoder that reads it. Cadences follow each protocol, e.g. an AIS static report
every six minutes (ITU-R M.1371) and a radar heartbeat once per rotation.

Each sensor reports only what it carries, so association has real work to do:
AIS has an identity and no accuracy, radar has accuracy and no identity, CoT has
an identity and no kinematics, and ESM has a bearing and no position. Only
MAVLink reports every accuracy attribute. The CAT010 plot carries no identity,
so it stays a `mim:object`. Every object runs a racetrack inside the radar's
window off a coastal site in the Solent approaches, so the association cases
hold for as long as the feed runs.

The times on the wire lag by each sensor's latency. CoT, ESM and SAPIENT events
take their timestamp from the wire. The radar, AIS, ADS-B and MAVLink connectors
stamp the time of receipt. A CAT062 track keeps the radar's observation time in
`time_of_day_s`; this feed's CAT010 plot has no time of day.

## Run

```text
ajar-feed-synthetic all                 # every sensor on its default port
ajar-feed-synthetic ais adsb            # a subset
ajar-feed-synthetic --dry-run --ticks 2 # print two ticks, open nothing
```

Without `--ticks`, the generator (dry run included) runs until stopped.

| Option | Effect |
|---|---|
| `--bind IP` | Moves every TCP server and multicast send onto one interface. Multicast otherwise leaves on the default route, which on a dual-homed box may be the wrong network |
| `--mavlink-to HOST:PORT` | Retargets the MAVLink unicast feed |
| `--ais-static-every SECS` | Shortens the AIS static-report cadence for a commissioning run |
| `--ticks N` | Stops after N ticks |
| `--dry-run` | Prints what would go on the wire instead of sending it |

## Where each feed goes

| Sensor | Wire | Connector | Transport |
|---|---|---|---|
| asterix | UDP multicast 232.1.1.1:8600 | asterix | udp-multicast |
| cot | UDP multicast 239.2.3.1:6969 | tak-cot | udp-multicast |
| mavlink | UDP to 127.0.0.1:14550 | mavlink | udp |
| adsb | TCP server on :30003 | adsb | tcp-client, line |
| ais | TCP server on :30160 | ais-nmea | tcp-client, line |
| esm | TCP server on :30155 | generic | tcp-client, line |
| sapient | TCP server on :30335 | sapient | tcp-client, length-u32le (subscriber role) |

Give every connector that reads this feed `[marking] caveats = ["EXERCISE"]`,
so each track says it is synthetic inside its signature.

## ESM feed

One JSON line per intercept, mapped by
[`esm-synthetic.example.toml`](../generic/esm-synthetic.example.toml).
`carried_by` names the emitter's platform, the vessel, by MMSI under the `AIS`
standard. `observed_by` names the receiver, co-located with the coastal radar,
by `SAC:SIC` under the `ASTERIX` standard, because a fixed site has no other
code in the [standards list](../../../docs/mapping-to-mim.md). They arrive as
the attributes `carried_by_alt_id` and `observed_by_alt_id`, each with its
`_standard` pair. `bearing_deg` is true, clockwise from north, from the receiver
to the emitter. A bearing is not a fix, so the event has no location. The
metadata keys `truth_lat` and `truth_lon` hold the position the bearing points
at, for checking an association.
