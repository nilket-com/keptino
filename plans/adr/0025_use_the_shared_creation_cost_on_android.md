# ADR 0025 — Use the shared creation cost on Android

## Status

Accepted.

## Why

Explicit Create on Android passes the production memory size to the same
native call as Unlock. It therefore creates vaults at 4 GiB and one pass.
ADR 0024 introduced a shared creation cost of 256 MiB, three passes and
one lane. A vault first created on either head should use the same cost.

## Decision

Use a dedicated native Create call. Derive the fresh vault key with the full
shared `KdfParams::CREATE` tuple and encode those costs on the first save.
The ordinary Android install uses production costs even when packaged as a
debug APK. A new Android vault opens on Linux using its recorded costs.

When another device wins an R2 create race, discard the fresh candidate and
open the winner with its own recorded cost and security-key policy. A legacy
production winner with no recorded costs uses 4 GiB, one pass and one lane.

## Limits

Existing vaults keep their costs through ordinary saves. Pepper derivation
from the recovery seed still needs 4 GiB and four passes. A directly
provisioned pepper skips that separate derivation. Keep the existing file
format, fixture bytes and conditional R2 writes.

## Acceptance

Create a disposable vault on Android, set an entry, save and reopen it.
Check the recorded tuple and read the Android-saved entry on Linux. Exercise
a competing R2 writer, authentication failure, and failure before the first
local commit. Measure Create and reopen wall times and process peak resident
memory, identifying the device or emulator and its configuration.
