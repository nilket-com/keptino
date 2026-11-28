# ADR 0026 — Fuzz the inputs libkeptino reads from outside

## Status

Accepted.

## Why

The 2026-11-28 assessment (ADR 0023) names parsing and composition as the
places password managers usually break, and Keptino's format is its own.
`libkeptino` reads bytes it did not write: vault files from a bucket or a
disk, replies from security keys over USB HID and NFC, and S3 error bodies.
Unit tests cover the cases their authors thought of. Fuzzing covers the
rest, and it is the cheapest preparation for an outside review.

## Decision

`libkeptino::fuzz` holds one target body per input. Each takes arbitrary
bytes, must not panic, and checks a round trip wherever the parser has an
encoder:

- `shards`: shard repair and the whole envelope reader on a vault file.
- `envelope`: the envelope reader on a payload already out of its shards
  (`Envelope::read`, split from `Envelope::parse`): meta entries, cost,
  revision, nonce, salt and key slots. An accepted envelope rewritten with
  `encode_envelope` reads back the same.
- `payload`: what only the vault key can write: LZ4 under its budget, the
  meta entries and the entry records.
- `slot`: one key slot meta value.
- `s3`: the NoSuchKey scan, endpoint and bucket validation.
- `cbor`, `ctap`, `hid`, `nfc`: what a security key can send. Decoded CBOR
  re-encodes canonically, and HID framing reads back as the framed message.

A smoke test in `cargo test` runs every target over built seeds (a real
vault file, its payload, CTAP replies, HID and NFC frames) and 400
deterministic mutations of each, so the gate fuzzes a little on every
commit. `KEPTINO_FUZZ_ROUNDS` runs it longer.

`common/libkeptino/fuzz/` is a cargo-fuzz crate outside the workspace, one
binary per target, with its own lock file under the seven-day cooldown.
`fuzz/run.sh TARGET [SECONDS]` builds it with libFuzzer coverage on stable
Rust and runs it, under `ci/heavy` when the checkout has it; `cargo fuzz run` works where nightly is
installed. The module is compiled only for tests and the `fuzzing` feature,
so no head ships it.

## Limits

LZ4 is a C library reached through `lz4-sys`. The targets reach it, but
without a sanitizer only crashes show. A sanitizer run needs nightly.
Response headers and HTTP are the heads' code and are not covered here, nor
is JNI. The fuzz lock file is not in `cargo audit`'s scope; it holds only
libFuzzer and libkeptino's own dependencies. Fuzzing finds crashes and
broken round trips, not design flaws; the outside review stays open.

## Acceptance

The smoke test passes in the gate in debug in a few seconds, and its
seeds parse, so the mutations reach past the first refusal. Every
target builds with `run.sh` and runs for a minute without a finding. The
committed fixtures open byte for byte.
