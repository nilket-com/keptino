# ADR 0032 — Lock when the Android screen turns off

## Status

Accepted.

## Why

An unlocked vault can survive a short app switch. Turning the screen off
should protect the vault immediately, even during an unlock or save.

## Decision

Enable lock on screen off by default. Keep the preference in the local
Android user's settings and expose it on the locked vault's Settings screen.
Observe the system screen-off event across ordinary app switches. Check the
display and device lock state when the activity returns. Use the same lock
path as the Lock button to revoke pending work, close the vault, remove
revealed fields and clear Keptino's clipboard when Android permits it.
Keep the two-minute idle lock active for either preference setting.

## Limits

Android controls delivery when the process is suspended and restricts
clipboard access while an app is in the background. The app can finish
a local write already in progress. Unsaved edits are discarded on lock.

## Acceptance

Exercise a real screen-off event on an emulator with a disposable vault.
Check that a brief foreground switch preserves the session, that screen
off clears the editor and requires a fresh unlock, and that turning the
preference off survives activity recreation and preserves the existing
idle policy.
