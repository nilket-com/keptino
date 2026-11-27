# ADR 0003 — Seal the vault model on both platforms

## Status

Accepted.

## Why

Linux seals records in memory. Android retains plaintext records for the
unlocked session. Security review finding K7 identifies that exposure.

## Decision

Move the database, entries and indexes into `common/core::vault`. Give the
model a key storage trait. Linux supplies keys in secret memory. Android
supplies keys in locked pages. Seal records and secret fields, and decrypt
the working entry for editing. Preserve the Android error path for key
allocation failure.

## Limits

Keep platform memory allocation, session lifecycle and the JNI boundary
in the heads. Sharing the remaining unlock orchestration is a follow-up.
Track the proposed FIDO2 design separately until implementation is ready.

## Acceptance

Verify that the open store holds ciphertext, both heads preserve unknown
fields and KDF parameters, and existing files still round-trip. Exercise
editing on Android and reopening its output on Linux. Record the K7 result
in the security review.
