# ADR 0006 — Bound every input the vault reads

## Status

Accepted.

## Why

Security review finding K9: a vault file, its decompressed database and
the records inside are read without an upper bound, and the Android head
shares one 128 MiB response cap between small metadata responses and the
vault body. A bucket writer cannot forge an authenticated payload, so this
is availability, not a break: a valid but enormous vault, or a large
unauthenticated body, lands in a locked, non-swappable process. The Linux
head caps remote downloads at 64 MiB; nothing caps the local file, the
decompressed size or the record count, and the writer could produce a file
the reader refuses.

## Decision

Budgets live in `common/core::format` and bind reader and writer alike: a
vault file of at most 64 MiB, a database of at most 30 MiB decompressed,
at most 100 000 records, and a record or field of at most 16 MiB. The
database budget is sized so that compression, base64 and parity cannot
carry a database within budget past the file budget. The parser refuses
a larger file before decoding shards and a longer record list or field
before allocating it, with a distinct `TooLarge` error the heads show as
such. Decompression stops at the database budget. `Database::encode`
refuses a database, record or file over budget before it changes any
bookkeeping, so a vault one head writes always opens on the other. The
Linux head reads a local file through a bound of the file budget rather
than trusting its reported size, and reports a refused save. The Android
head gives metadata responses their own small cap, checks `Content-Length`
against the file budget before reading a vault body, and reports a refused
save through its error type.

## Limits

No byte of any file changes; every committed fixture is far below every
budget. The budgets are constants; raising one is a new decision. The
Argon2 arena and the shard decoder's working memory are bounded by the
file budget already and are not changed here.

## Acceptance

Core tests: a file over budget, a record list over budget and a field over
budget are each refused with `TooLarge`; an encode over budget is refused;
decompression past the budget fails closed. Both heads open every fixture,
`android/interop/run.sh` passes at the debug cost, `ci/check.sh` is clean.
