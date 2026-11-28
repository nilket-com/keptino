# ADR 0030 — Install for one Android user

## Status

Accepted.

## Why

The installer enumerated packages across Android users, pulled the APK from
the current user, and let ADB install for all users. On the Samsung, the
enumeration reported a permission error for a private profile even though
verification succeeded for the operator. The SDK signing tool also launches
Java through PATH and could run the system JDK despite setup selecting JDK 21.

## Decision

Accept a numeric Android user ID through `android/setup.sh --user ID`.
By default, resolve the current user once on the selected device. Use that
same ID for package discovery, both signing-rotation installs, ordinary
updates, and verification. Use it for debug installation and debug R2
provisioning, including the receiving activity and its private pipe.
Reject ambiguous discovery and invalid user IDs before sending credentials.
Put the selected JDK's bin directory first on PATH for the Android tools.

## Limits

The Android package manager shares APK code across users that already have
the package. User selection controls installation for the selected profile.
Android continues to isolate each user's app data and enforce package signing.

## Acceptance

Exercise fresh installation and an update with disposable signing material
on a multi-user emulator. Confirm that the other user does not acquire the
package. Check default selection, explicit selection, and refusal of invalid
IDs and inaccessible package queries. Confirm the SDK signer uses the selected
JDK even when the system Java comes first on the caller's PATH.
