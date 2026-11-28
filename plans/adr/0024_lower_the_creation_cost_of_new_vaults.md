# ADR 0024 — Create new vaults at 256 MiB

## Status

Accepted.

## Why

A Linux release build derives every vault key with Argon2id at 4 GiB, one
pass, one lane (`KdfParams::RELEASE`). A vault created on Linux records that
cost, and every device that opens it must find 4 GiB of free memory on each
unlock. Phones with less memory free cannot open such a vault. The pepper
already keeps a stolen vault file from being guessed offline, so the high
cost protects only a vault whose pepper or recovery seed has also been taken.
Codex and Gemini agreed on the lower creation cost (chatd seq 1208), and
Claude agrees.

## Decision

Explicit Create on Linux (ADR 0018) derives and records a new vault at
256 MiB, three passes, one lane: `KdfParams::CREATE`. A debug build keeps the
4 MiB test cost. The cost a vault records is never changed by an ordinary
Save, a rekey or a sync, so every existing vault keeps its cost. A vault that
records no cost still opens at 4 GiB (`KdfParams::RELEASE`), and its next
Save records 4 GiB as it does today. The pepper derivation (`derive_pepper`)
is unchanged.

The constant lives in `libkeptino`. This decision changes the Linux head;
Android's Create keeps its memory-scaled cost until a later decision adopts
`CREATE` there.

## Limits

An attacker who holds the vault and its pepper or recovery seed pays about
a fifth of the memory-time per guess on a new vault compared with 4 GiB at
one pass. Existing vaults are not migrated to the lower cost. There is no
action to change a vault's cost. No format marker, AAD or fixture changes.

## Acceptance

A vault created through the core at `CREATE` records `kdf_m=262144`,
`kdf_t=3`, `kdf_p=1` and reopens. A file recording no cost opens at
`RELEASE` and records it on Save. A vault recording 4 GiB keeps 4 GiB after
a Save and a rekey. The committed fixtures open byte for byte.
