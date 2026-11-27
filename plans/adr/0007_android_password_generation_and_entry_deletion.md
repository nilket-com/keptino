# ADR 0007 — Generate passwords and confirm entry deletion on Android

## Status

Accepted.

## Why

Android users currently supply every password and can only overwrite an
obsolete entry. Linux already offers a random password and confirmed entry
deletion. Both heads use the same sealed working entry and indexed store.

## Decision

Move the Linux password generator into core. Both heads draw 24 characters
from the existing alphabet with OS randomness and rejection sampling.
Android generates directly into the native working entry. The editor
preserves its visibility choice and supports Revert. Set applies the edit
to the open vault, and Save persists it through the usual revision and
upload guards.

Offer Delete for a selected, stored entry whose edits have been set or
reverted. Ask for confirmation naming that entry. Cancel keeps the entry.
Confirmation removes it through the shared store and clears the editor.
A lock or change of selection invalidates the confirmation. Save persists
the deletion, and locking before a save discards it.

## Limits

Keep the vault format, sync rules and Linux editor behavior. The generator
uses the Linux defaults. Configurable alphabets, passphrases, a recycle bin
and entry history are separate decisions.

## Acceptance

Exercise generation, revert, set and save. Verify canceling deletion,
confirming the named entry, cleared name and tag indexes, locking before
save, and absence after save and reopen. Run the workspace gate and test
the Android editor with a synthetic vault.
