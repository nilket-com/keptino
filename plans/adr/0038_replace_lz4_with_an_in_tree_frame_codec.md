# ADR 0038 — Replace lz4 with an in-tree frame codec

## Status

Accepted.

## Why

The database is compressed with `lz4`, which builds the C library through
`lz4-sys`: about 8,200 lines of C in `lz4.c`, `lz4hc.c`, `lz4frame.c` and
`xxhash.c`. It runs inside the vault process and receives the whole
decrypted database on every save. The system call filter (ADR 0028) and
the Landlock filesystem sandbox do not stop a process from opening a
socket, because the same process syncs with the bucket. A compromised
release of that C code could send the plaintext anywhere, and nothing
in Keptino would notice.

Hostile input is not the issue: decompression runs only after the cipher
has authenticated the payload. The issue is trusting the code itself.

## Decision

`libkeptino::lz4frame` replaces the dependency with about 300 lines of
safe Rust.

The reader decodes any LZ4 frame the old library wrote:
- the frame header, with its descriptor checksum;
- linked or independent blocks, compressed or stored;
- the optional block checksums, content size and content checksum,
  using an in-tree xxHash32.

It refuses a frame that is truncated, that is followed by trailing bytes,
that needs a dictionary, that uses reserved bits, or whose blocks go past
their stated maximum. Output stays within the caller's budget and grows
only by copying into a new wiping allocation, as before.

The writer stores the database in uncompressed blocks. Every LZ4 reader
accepts these, including the installed builds on both heads, so a vault
saved by the new code still opens in the old. Vaults grow by their former
compression ratio. That is tens to hundreds of kilobytes at real sizes,
and a 30 MiB database with its parity still fits the 64 MiB file budget.
The ciphertext length no longer depends on how compressible the entries
are.

`lz4` stays as a dev-dependency only, so tests can cross-check the new
code against the real library in both directions.

## Limits

Files are larger. Compression could come back later in Rust, behind the
same reader, if size ever matters.

The dev-dependency still compiles the C library for tests. A later
decision can drop it once committed fixtures cover every frame feature
the reader handles.

## Acceptance

- `lz4` and `lz4-sys` are absent from the normal dependency tree of
  `libkeptino`, `keptino` and `droid`.
- Every committed fixture opens, and its parity recomputes.
- Frames from the real library open with the new reader: every
  compression level, block size, block mode and checksum setting.
- Frames from the new writer open with the real library.
- The `payload` fuzz target runs against the new reader.
- `ci/check.sh` passes, and Codex's Android build and device checks pass.
