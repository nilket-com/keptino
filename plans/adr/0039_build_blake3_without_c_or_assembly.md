# ADR 0039 — Build blake3 without C or assembly

## Status

Accepted.

## Why

ADR 0038 removed the C library that saw the decrypted database. The next
non-Rust code in `libkeptino`, and the only one in the Android core, is
`blake3`'s build script. It assembles hand-written SSE2, SSE4.1, AVX2 and
AVX-512 routines on x86-64 and compiles C NEON intrinsics on ARM64. Keptino
hashes erasure shards, health report digests and a few derivation
inputs: kilobytes to a few megabytes per save. The speed of hand-written
assembly buys nothing measurable here, and it is code no reviewer of this
project reads.

## Decision

`libkeptino` and `linux` enable the `blake3` feature `pure`. The build
script then compiles nothing. The hash uses the crate's Rust
implementations: Rust SIMD intrinsics on x86-64 up to AVX2, and the
portable Rust code on ARM64. The output is the same BLAKE3 function, so
every shard header and committed fixture stays byte-identical.

## Limits

The Linux TLS stack still builds `aws-lc-sys`, a large C and assembly
cryptography library, through `rustls`. Replacing it means choosing
another TLS crypto provider, which is its own decision. The Wayland
backend links the system's `libwayland-client`, which the window needs
anyway.

## Acceptance

`blake3`'s build output holds no object files. Every committed fixture
still opens and its parity recomputes. `ci/check.sh` passes, and Codex's
Android build passes for both ABIs.
