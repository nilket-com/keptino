# ADR 0002 — Share the vault format, cryptography and sync policy

## Status

Accepted.

## Why

Both heads implement the same TLV envelope parser, mirror check and key
derivation. A compatibility fix currently requires two implementations.

## Decision

Add `common/core` to the workspace. Move the TLV format, mirror check,
revision and bounded KDF cost fields into `format`. Move pepper and master
key derivation, authenticated encryption and compression with wiping buffers
into `crypto`. Share pure candidate ordering and revision and upload guards
in `policy`. Have both heads call these modules.

## Limits

Keep OS calls, credential access, network clients and UI in their heads.
Preserve unknown TLV fields, the unmarked writer and historical readers.

## Acceptance

Both heads consume the shared routines. Every committed fixture parses and
repairs byte for byte. Each platform opens the other's saves. Test the
historical reader and the marked and unmarked formats.
