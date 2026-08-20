<!-- SPDX-License-Identifier: Apache-2.0 -->
# Mapping your feed to MIM

What you map, where you map it, and what the valid targets are.

The SDK does **not** do this for you. It builds canonical bytes, signs them and
enforces structure. Deciding that your `TrackType=3` is a `mim:aircraft`, and that
your speed is in knots and must be metres per second, is yours. Nothing catches a
mistake: a wrong type or a misspelled attribute compiles, seals and publishes, and
Ajar discards it without an error.

---

## 1. Where you map

Four decisions, once per record. Everything else the SDK fills in.

This is a complete file. It compiles against the installed SDK and runs.

```cpp
#include <ajar/connector.hpp>
#include <array>
#include <cstdio>
#include <string>

// ---- YOUR record, whatever your feed already produces ----------------------
struct Track {
  int         type_code;   // your classification: 3 = air, 7 = surface
  std::string track_id;    // your native identifier
  double      lat, lon;
  double      alt_ft;      // feet
  double      speed_kn;    // knots
  double      course_deg;
  int         iff;         // 1 friend, 2 hostile, 0 unknown
  std::string raw_frame;   // the bytes you received
};

// ---- The only code you write ------------------------------------------------
// Attribute values are strings. std::to_string(231.5) gives "231.500000",
// so format explicitly and keep the precision you mean.
static std::string fmt(double v, int dp = 2) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%.*f", dp, v);
  return buf;
}

static const char* entity_type_for(const Track& t) {
  switch (t.type_code) {
    case 3:  return "mim:aircraft";
    case 7:  return "mim:vessel";
    default: return "mim:object";      // class unknown: do not guess
  }
}

static const char* hostility_for(const Track& t) {
  switch (t.iff) {
    case 1:  return "Friend";          // exact case
    case 2:  return "Hostile";
    default: return "Unknown";
  }
}

// ---- Emit -------------------------------------------------------------------
ajar::Event to_event(const Track& t) {
  return ajar::EventBuilder("matrixspace-1",       // your registered source_id
                            entity_type_for(t))    // MIM class for THIS record
      .new_id()
      .now()
      .location(t.lat, t.lon, t.alt_ft * 0.3048)      // feet -> METRES
      .attribute("speed",       fmt(t.speed_kn * 0.514444))  // knots -> m/s
      .attribute("course",      fmt(t.course_deg, 1))
      .attribute("hostility",   hostility_for(t))
      .attribute("environment", "AIR")
      .metadata("native_id",    t.track_id)           // never the event id
      .metadata("speed_kn",     fmt(t.speed_kn, 1))   // keep the original
      .metadata("altitude_ft",  fmt(t.alt_ft, 0))
      .payload(t.raw_frame)                           // verbatim
      .build();
}
```

Then per record:

```cpp
auto sealed = ajar::seal(ajar::canonical_bytes(to_event(t)), key);
publish("ajar.ingest.matrixspace-1", sealed);   // your NATS client
```

### What that produces

Input `Track{3, "MS-4471", 25.2707, 51.5240, 34000 ft, 450 kn, 271.5, iff=1}`:

```
entity_type mim:aircraft  attrs 4  meta 3  sealed 331 bytes
  attr course = 271.5
  attr environment = AIR
  attr hostility = Friend
  attr speed = 231.50
```

Note the attributes come back **sorted by key**, not in the order you wrote them.
The builder does that for you; canonical bytes require it.

| Your field | Becomes | Why |
|---|---|---|
| `type_code = 3` | `entity_type = mim:aircraft` | your classification, mapped |
| `alt_ft = 34000` | `location` altitude `10363.2` | metres, not an attribute |
| `speed_kn = 450` | `speed = 231.50` + `speed_kn = 450.0` | m/s governed, native kept |
| `iff = 1` | `hostility = Friend` | exact case |
| `track_id` | `metadata.native_id` | never the event id |
| `raw_frame` | `payload` | verbatim, nothing lost |

### The same thing in Python

```python
from ajar_connector import EventBuilder, canonical_bytes, seal, SigningKey

ENTITY    = {3: "mim:aircraft", 7: "mim:vessel"}   # yours -> MIM
HOSTILITY = {1: "Friend", 2: "Hostile"}            # exact case

def to_event(t):
    return (EventBuilder("matrixspace-1", ENTITY.get(t["type_code"], "mim:object"))
            .new_id().now()
            .location(t["lat"], t["lon"], t["alt_ft"] * 0.3048)      # feet -> metres
            .attribute("speed", f"{t['speed_kn'] * 0.514444:.2f}")   # knots -> m/s
            .attribute("course", f"{t['course_deg']:.1f}")
            .attribute("hostility", HOSTILITY.get(t["iff"], "Unknown"))
            .attribute("environment", "AIR")
            .metadata("native_id", t["track_id"])                    # never the id
            .metadata("speed_kn", f"{t['speed_kn']:.1f}")            # keep native
            .payload(t["raw_frame"])
            .build())

sealed = seal(canonical_bytes(to_event(track)), key)
```

Same input, same result: `speed = 231.50`, `hostility = Friend`, attributes
sorted.

---

## 2. What to map to: entity types

The class of the thing being reported. What the shipped connectors emit:

| `entity_type` | Use for |
|---|---|
| `mim:aircraft` | anything airborne with a track |
| `mim:vessel` | surface maritime contacts |
| `mim:sensor` | the sensor or platform itself |
| `mim:object` | a detection whose class you do not know |
| `mim:land-vehicle` | ground vehicles |
| `mim:person`, `mim:unit`, `mim:facility`, `mim:weapon`, `mim:feature` | see the vendored ontology for the full 17 |

**If your source reports a domain rather than a classification, use `mim:object`**
and put the domain in the `environment` attribute. A radar that says "something in
the air" has not told you it is an aircraft.

Anything you need that is not a MIM class goes in your own namespace:
`x:matrixspace:<type>`. The operator must register the prefix either way.

The builder checks the **shape** (`mim:<type>` or `x:<vendor>:<type>`), not that
the type exists. `mim:banana` builds and seals fine.

---

## 3. What to map to: attributes

Governed attributes the shipped connectors emit. Names are exact and
case-sensitive.

**Kinematics** — the units are the trap:

| Attribute | Unit | Keep the native value in metadata as |
|---|---|---|
| `speed` | **metres/second** | `speed_kn` |
| `vertical_rate` | **metres/second** | `vertical_rate_ftmin` |
| `course` | degrees | |
| `heading` | degrees | |
| `rate_of_turn` | degrees/second | |
| `radial_velocity` | metres/second | |
| altitude | **metres**, in `location()`, not an attribute | `altitude_ft` |

Knots into `speed` is wrong by 1.94×. Feet/minute into `vertical_rate` is wrong by
197×. Feet into altitude is not validated at all. All three pass every check and
are silently wrong on the map.

**Identity and classification:**

`callsign` · `squawk` · `aircraft_type` · `vessel_name` · `vessel_type` ·
`object_class` · `platform_designation` · `classification_code` · `nav_status` ·
`track_status`

**Signal quality:** `snr_db` · `rcs_db` · `pitch` · `roll`

---

## 4. Controlled vocabularies

Exact strings. A wrong case is discarded, so a track keeps its position and loses
its affiliation.

**`hostility`** — MIM 5.3 `HostilityCodeType`:

```
Friend  AssumedFriend  Hostile  AssumedHostile  Suspect  Neutral
AssumedNeutral  Involved  AssumedInvolved  Pending  Unknown  Faker  Joker
```

Not `friendly`, not `FRIEND`, not `hostile`.

**`environment`** — closed set:

```
AIR  LAND  SURFACE  SUBSURFACE  SPACE  UNKNOWN
```

This drives the battle dimension a C2 renders, so it is worth setting whenever
your source knows it.

---

## 5. Anything else you have

Put it in `metadata`. Metadata is ungoverned and **always kept**, so nothing is
lost by sending it. Native track numbers, vendor fields, original units, sensor
serial numbers all belong there.

Your raw frame goes in `payload` verbatim. A future ontology can re-extract from
it, so a field you cannot map today is not lost.

Rule of thumb: **if in doubt, metadata.** A governed attribute you get wrong is
discarded; the same value in metadata arrives intact.

---

## 6. Confirm before you build

The list above is what our connectors emit. The **authoritative** set of governed
names, units and bounds lives in Ajar's signed ontology manifest, which your
operator holds.

Ask them for two things before you write the mapping:

1. **`ontology-mim-5.3-conformant-1.json`** — the contract your events are
   validated against. It is vendored here as
   [`vendor/contract/ontology.json`](../vendor/contract/ontology.json) and
   hash-pinned, so the copy you build against cannot drift. Confirm with your
   operator that it is the version their deployment runs.
2. **Confirmation of your entity types** — the exact classes or `x:` prefixes
   registered against your `source_id`.

Then check your work against [ATTRIBUTES.md](../rust/connectors/ATTRIBUTES.md),
and prove your bytes with `ajar-conformance` before going live.
