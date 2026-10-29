<!-- SPDX-License-Identifier: Apache-2.0 -->
# Code style

How code in this repository is written. It applies to people and to coding
agents alike, in every language here. Formatters and linters (rustfmt, clippy,
gofmt, go vet, ruff, clang-format) settle layout; this file covers what they
don't.

The short version: write code that explains itself, comment only what it
can't, and keep one copy of everything.

## Comments

1. Comment the why, never the what. If the next identifier already says it,
   delete the comment. If it doesn't, rename the identifier first.
2. Describe the code as it is now. No history ("previously", "now", "the old
   walk", "no longer"), no past bugs, no rejected alternatives, no hedging.
3. No future tense ("when the durable leg lands", "a future edit must trip
   over this"). Open a ticket instead.
4. No references to private ADRs, tickets, rule numbers or numbered doc
   sections (`ADR-0019`, `#76`, `§3`, `README section 7f`). External standards
   are fine when they decode a constant: `I048/130`, `ITU-R M.1371`,
   `STANAG 4586 §B.4.1.2.11`.
5. No numbers, counts, dates or versions that restate code (`within 10 s`,
   `six sensors`, `0.6.5`). Interpolate the constant or leave it out. A
   comment that can go stale without a test failing should not exist.
6. No advocacy. Drop "honest", "deliberately", "by design", "by
   construction", "the whole point", "crucially", "load-bearing",
   "fail-closed" as a slogan, and "not X but Y" contrasts. State the fact.
   No imagined readers or scenes to justify code ("what a stranger needs",
   "fails in CI, not on a ship", "where the first hour fails"); say what the
   code does. The words themselves are fine as plain domain terms: a ship in
   AIS code is a vessel.
7. No emphasis: no em-dashes, no `**bold**`, no ALL CAPS, no box-drawing or
   `// =====` banners. Plain ASCII punctuation. A file that needs section
   banners should be split into modules.
8. No numbered step narration (`// 1. normalize`, `// 2. seal`). Name the
   variables so the code reads as the steps.
9. Comments go on their own line above the code, never trailing after a
   statement, block or multi-line call.
10. Say a cross-cutting rule once, in AGENTS.md or the crate doc, not at
    every call site (raw frame sealed into payload, never panic on input,
    affiliation only from config).
11. When you change commented code, rewrite the comment; don't append to it.
    Check that each comment still sits on the code it describes.

Keep:

- SPDX headers, `// SAFETY:` comments, and a one-line reason on a lint
  `allow` or `noqa` (a code, not a sentence).
- Spec item tags in tables: `Field::Fixed(2), // I048/130`.
- Unit and sentinel notes the type can't carry: `// 1023 = not available`.
- One line on a non-obvious dependency feature or flag.

## Doc comments

1. A module or crate doc (`//!`, module docstring, file header) is at most
   five lines: what it is, which spec edition, what becomes an event. A wire
   layout diagram may follow. No feature tours, tables or run instructions;
   those go in the README.
2. Document an item only when the doc adds something the name and type don't:
   a unit, an invariant, a sentinel, a spec reference, a non-obvious default.
   `/// Vessel name.` on `name` goes.
3. Public SDK API (rust/ajar-connector, go/ajarconnector,
   python/ajar_connector, cpp/include) keeps a one-line doc per public item.
   Go docs start with the identifier.
4. Operator-facing config is documented in the `.example.toml` and README,
   not mirrored field by field in Rust docs.
5. Code whose comments are published as docs, e.g. on docs.rs, can have more
   comments than these rules allow.

## Naming

1. Names carry units: `_m`, `_ft`, `_kn`, `_mps`, `_deg`, `_s`, `_ms`,
   `_ftmin`. A trailing `// volts` means the name is wrong.
2. Short is fine, vague is not: `be_uint` over `be`, `crc_extra_and_len` over
   `spec`.
3. One vocabulary for one role across crates and SDKs. The same concept has
   the same name in Rust, Go, Python and C++.
4. Closed sets are enums, not strings (`Role::Producer`, not `"producer"`).

## Structure

1. Inline a private function, closure, type alias or constant that has one
   use, unless its name stands for a spec concept or it has its own tests.
   No getters or forwarding wrappers with a single caller.
2. Extract on the third copy. Two copies of something small are fine; a
   helper copied into a third crate moves to `common` (connectors) or the
   SDK. A comment saying "same as X" means call X.
   Copy-me examples under `examples/` are exempt: they must stay
   self-contained.
3. Return the narrowest type. A constructor that can't fail returns `T`, not
   `Result<T>`. A function that always returns `Some` returns the value.
   Don't pair `Option`s where a `Result` belongs.
4. Destructure instead of validate-then-`expect("checked")`. Use `let ... else`
   and early `continue` to keep nesting at ideally three levels or less.
5. Data over code: a table and a loop, not 24 copies of `if bit(n) { skip }`.
6. `#[derive(Default)]` and `..Default::default()` over constructors that list
   thirty `None`s.
7. One inherent `impl` block per type, right after the type. `use` at the top.
   Import types, enums and traits from other crates and use the short name
   (`Ordering::Relaxed`, `Value`), not `std::sync::atomic::Ordering::Relaxed` in
   a body. Never import a function or macro from another crate; write its path
   at the call (`serde_json::json!`, `anyhow::bail!`,
   `ajar_connector_common::run()`). Importing a module is fine (`mpsc::channel()`),
   and so is the `proptest::prelude::*` glob in property tests.
8. No dead code: no unread config field, no unused pub item, no "compat" shim
   inside the workspace, no runtime check that a test already proves.
9. Use what is already in the dependency tree (`time`, `hex`, `uuid`,
    `getrandom`, `tempfile`, `thiserror`) instead of reimplementing it. Add a
    dependency rather than hand-roll base64.
10. One idiom per concern: angle wrap is `rem_euclid(360.0)`, mutex poisoning
    is handled the same way everywhere, TOML is written via serde, never
    `format!`.
11. Split a file before it needs banners. E.g. a parser over ~1000 lines splits
    by category or message family.
12. Don't make a file for a few dozen lines. A small type or helper stays in
    the file that uses it; a new file has to carry enough code to be worth
    opening.

## Performance

Write efficient code and make the intent visible in the code rather than
relying on the optimiser. Readability still wins over micro-optimisation.

1. Allocate once when the size is known: `Vec::with_capacity(n)`,
   `String::with_capacity(n)`, or `reserve` before a loop of pushes, not
   `Vec::new()` and growth. A count read from untrusted input does not size
   an allocation; cap it by the bytes actually present, or let it grow.
2. Borrow instead of copying. Pass `&[u8]` and `&str`; on per-frame paths, use
   `clone`, `to_vec` and `to_string` only where ownership is needed.
3. Keep per-frame loops lean: build tables, compile patterns and parse
   configuration once, outside the loop.
4. No `unsafe`, hand-written SIMD or lock-free tricks for speed unless a
   measurement shows the path needs it.

## Errors

1. Rust libraries use `thiserror`; wrap the source with `#[from]` instead of
   `Build(String)` and `e.to_string()`. Binaries use `anyhow` with
   `.with_context(|| ...)`; `map_err` only converts to a typed error.
2. An error message states what failed and the cause, lowercase, no trailing
   period: `CAT048 FRN 31 not length-modelled`. A remedy is one short clause
   at most; long remedies belong in `doctor`.
3. Go: `errors.New` for fixed text, `fmt.Errorf("ajarconnector: ...: %w",
   err)` when wrapping, one prefix convention.
4. Python: catch the narrowest exception, `raise ... from exc`.

## Logging

1. The message is a static lowercase phrase of two to ten words. Data goes in
   fields: `warn!(remote = %addr, error = %e, "feed connect failed")`.
2. No interpolation into the message, no remedies, no caps.
3. Binaries log through `tracing` (or the language's logger), never
   `eprintln!("[name] ...")`.

## Config

1. Every operator-facing config struct has `deny_unknown_fields`.
2. Defaults come from one `impl Default` with struct-level `#[serde(default)]`,
   not a `default_*` function per field.
3. An `.example.toml` has a two or three line header and at most one comment
   line per key. The shared block (source_id, nats_url, subject_prefix,
   signing_key_path) is identical across connectors, except that the scaffold's
   key path is relative so its quick start runs as written.

## Tests

1. One behaviour per test. The name says the behaviour in about six words:
   `confidentiality_label_to_policy_tags`. Intent goes in assert messages
   (`assert!(ok, "{msg}")`), not in narrating comments.
2. Test module docs are one line. No "what must hold" essays.
3. Test behaviour that can break, not language semantics.
4. Shared scaffolding lives in one place: `tests/common/mod.rs`, a
   `conftest.py` fixture, or a shared dev crate. Temp dirs via `tempfile`.
5. Imports first in a test module.
6. Build fixtures from one base and mutate it, rather than rebuilding the
   bytes by hand in every test.
7. Timing assertions are benchmarks, not unit tests.

## Dependencies and manifests

1. A dependency used by two crates is `workspace = true`.
2. Cargo.toml comments are one line, only for a non-obvious feature or
   version choice. Say it once, in the workspace manifest.

## Shell, CI and deploy

1. Bash only, `set -euo pipefail`, `[[ ]]`, `${BASH_SOURCE[0]}` for the root,
   lowercase variables unless exported. Header: SPDX, one-line purpose,
   `# Usage:`.
2. CI steps have imperative, sentence-case names of two to five words. Every
   `run:` step is named. A comment only for a non-obvious flag, one line.
   Set `defaults.run.shell: bash` once per workflow.
3. Helm values get one short trailing comment each; a block comment only
   above a section.

## Connector READMEs

Each connector's README is the one place a user reads to use it. It explains
what the connector is for and every design decision that shapes how it is
used; the code does not repeat that in comments. Keep these sections, in this
order, and leave out any that would be empty:

1. **Purpose**: the opening paragraph under the title, without a heading:
   which feed or system it connects and in which direction.
2. **Input**: wire format and edition, the message types decoded and those
   ignored, the transports and framing that fit.
3. **Output**: entity types; identity (`source_uid`, governed identity); a
   table of attributes with units; metadata keys; what goes into the payload.
4. **Configuration**: the example config, then each connector-specific option
   with its default.
5. **Behaviour**: the decisions a user will notice, e.g. what is correlated
   across frames, when no location is emitted, what is dropped and counted,
   caps and their metrics.
6. **Limits**: what is not decoded or not supported yet.

Every statement is checked against the code. Further sections (trying it
against live traffic, conformance) follow these.

## Prose in docs

Short sentences, no em-dashes, bold only for a term on first definition, no
maxims or closing summary lines ("That is the whole contract").
