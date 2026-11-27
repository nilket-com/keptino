# ADR 0001 — One Cargo workspace for the platform heads

## Status

Accepted.

## Why

The Linux and Android heads build the same erasure codec. Independent
lockfiles, audit lists and build paths make a dependency change easy to miss.

## Decision

Put the Linux head, Android native crate, interop harness and
`common/erasure` in one Cargo workspace. Keep one lockfile, one audit
list and the seven-day dependency cooldown. Keep Linux release panics
aborting and the Android release profile unwinding across the JNI guard.

Align the Gradle inputs, native build, Linux installer and adb installer
with the workspace. Adopt the common formatting, writing and local CI
rules alongside the move. Verify fixture parity for both heads.

## Limits

Preserve the erasure API, vault bytes, credential names and platform
interfaces. Keep Android and Linux build artifacts in their expected locations.

## Acceptance

Build both heads from the root lockfile, run the workspace tests, and
recompute byte parity for all six committed fixtures.
