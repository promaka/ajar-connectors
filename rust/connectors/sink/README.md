<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-sink

Subscribes to sealed events, verifies each one against its publisher's registered
key, persists it, and can prove afterwards that the record was not altered.

It exists so the whole path can be run and inspected without Ajar Core: start
NATS, start any number of connectors, start this, and you have a working system
with a queryable database and an audit chain you can check yourself.

## Not a governance plane

There is no policy engine, no ontology validation, no classification handling and
no releasability. The sink answers one question, "did this publisher send exactly
these events, and is the record complete". Deciding what an event is *allowed* to
be is Ajar Core's job and stays there. Use this for development, bench
measurement and partner evaluation.

## Run it

```bash
ajar-sink run   sink.toml    # subscribe, verify, persist
ajar-sink audit sink.toml    # re-verify every signature and every link
ajar-sink stats sink.toml    # what is held, per source
```

Or bring up a bus, a publisher and the sink together:

```bash
docker compose -f deploy/dev/compose.yml up --build
docker compose -f deploy/dev/compose.yml run --rm sink audit /etc/ajar/sink.toml
```

## What is stored

One row per accepted event, holding the exact bytes that arrived plus the fields
worth querying on: source, entity type, the publisher's timestamp, the sink's own
receive time, and position. It is ordinary SQLite, so `sqlite3`, DuckDB, pandas
and Spark all read it without anything from this repo.

The stored bytes are never re-encoded. They are what the signature covers, so
re-encoding would make the record unverifiable later.

## The two guarantees

Each event carries an Ed25519 signature, and each record carries a link in a hash
chain:

```
record_hash[n] = SHA-256( record_hash[n-1] ++ sealed[n] )
```

The **signature** proves who produced an event and that its contents are
unaltered. The **chain** proves the record *set* is unaltered: deleting a row,
inserting one, reordering two or editing any stored byte breaks every link from
that point on. A signature alone cannot detect a deletion, because a removed
event leaves nothing behind to check.

`audit` recomputes both from the stored bytes, so it does not depend on trusting
the process that wrote them. Anyone holding the database file and the publishers'
verifying keys reaches the same verdict independently.

```
$ ajar-sink audit sink.toml
audit: INTACT
records: 266
head: 2a1cb2184f04a2c2a7ca25d8f11385043ab8aa0710778d1b56345b91deb02ca6
```

Exit status is 0 for an intact chain and 1 for a broken one, so it runs as a
scheduled check.

## Registered sources

A publisher absent from `[sources]` is refused rather than stored. An event
nobody can verify is worse than no event: it would sit in the chain looking like
evidence while proving nothing.
