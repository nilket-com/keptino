# ADR 0016 — One shared library, named libkeptino

## Status

Accepted.

## Why

The shared code is three crates, `keptino-core`, `keptino-fido` and
`keptino-s3`, and a head imports `keptino_core::vault::KeyStore`. The
operator wants the names terse and clean: the application is `keptino`, and
what it shares with Android is one library, `libkeptino`. Three crate names
for one library, each carrying the project name and a suffix, is the kind of
drift ADR 0004 exists to stop, and the Android build lists each crate it
links by hand.

## Decision

One workspace crate, `libkeptino`, at `common/libkeptino`, holds everything
the heads share. Its default build is what `keptino-core` is today: format,
crypto, policy, vault, generator, health and roaming. Two features add the
rest: `fido` brings the CTAP2 modules and their pure-Rust dependencies,
`s3` brings the signer and its two; neither is on by default, so a head
that links only the core links nothing more, as now. The `test-support`
feature keeps the simulated key. The modules keep their paths under the new
root: `libkeptino::vault::KeyStore`,
`libkeptino::fido::ceremony::Ceremony`, `libkeptino::s3::sign`. The Linux
head is the package and binary `keptino` with the library target `keptino`
as today. `keptino-erasure` is used by the core alone, so it folds in as
`libkeptino::erasure`. The crate root keeps `#![forbid(unsafe_code)]`.

Every `Cargo.toml`, every `use`, the Android native build inputs, the
interop harness, the fixture tests and the documents follow the new names.
No file byte changes, no fixture changes, no behavior changes; the lockfile
changes only in package names.

## Limits

A rename and a fold, nothing else: no function moves between modules, no
API changes, no new dependency. The Debian package, the installed
executable, the Android application id, the systemd-creds names and the
Keystore aliases are untouched. `plans/` and `doc/` keep the old crate
names in records already published; only the living documents change.

## Acceptance

`cargo tree -p keptino` shows no `fido` or `s3` dependency without the
features; `cargo tree -p droid` shows them only where Android enables them.
Every test of the three former crates passes under the new names; the
committed fixtures open on both heads; `android/interop/run.sh` passes at
the debug cost; `ci/check.sh` is clean; `grep -r keptino_core` and
`keptino-core` find nothing outside `plans/` and `doc/`.
