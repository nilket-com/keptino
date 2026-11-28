# ADR 0020 — The Nautilus design on Android

## Status

Accepted for implementation after ADR 0019.

## Why

The Android editor puts vault actions, entry edits and generator settings in
one scrolling form. The approved Android board separates the four jobs of
unlocking a vault, finding an entry, editing it and choosing a new password.

## Decision

Use the Nautilus roles and layouts in `doc/design.md`. Keep controls the same
width while their state changes. Give icon actions accessible names. Keep
system back navigation, large text, the keyboard and small windows usable.

Unlock opens the vault list. Its Save writes all set entries, including
deletions. Rows show names, usernames and pending or weak flags. Find uses
the shared name and tag index. Tag chips use exact membership. Android
indexes the row metadata and a weak flag while reading an authenticated
record or setting it. Drawing and filtering the list opens no sealed record.
The index is session-only and the file format stays the same.

Opening a row creates a working entry. Revert restores its set values.
Leaving without Set discards its edits and tells the user. Set returns to
the list and marks the name pending until a successful local Save.
Confirmed deletion and lock retain their existing safeguards.

The generator opens in a bottom sheet with a masked preview, strength in
whole bits, character or word controls and a length slider. Keep the
candidate sealed in native memory. Only Use this password applies it to the
working entry. Dismissal discards it, and using it still requires Set and Save.

## Limits

Keep the existing unlock, creation, setup, import, export, sync, device
credential and security key paths. Preserve the secure window, idle lock
and conditional clipboard clearing. Use the installed Android sans and
monospace families. Use only synthetic vaults for automated UI checks.

## Acceptance

Exercise list filtering and flags, discard and revert, Set followed by
Save and reopen, and canceling or applying a generated password. Verify
that editing one entry cannot save an unset draft on another. Run the
Android emulator checks and the workspace gate before publishing the pair.
