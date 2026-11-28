# ADR 0027 — Install a release-signed Android app for everyday use

## Status

Accepted.

## Why

The operator opens a real vault on a Samsung installed by `android/setup.sh`.
The installer builds a debuggable APK. A computer authorized for ADB can
access the app through Android's debugging facilities. The existing app also
contains the local vault, trusted revisions and credentials protected by
Android Keystore. Uninstalling it to change signers could lose that state.

## Decision

Make `./android/setup.sh` build and install a non-debuggable release APK
under the existing application ID, `com.keptino.app`. Keep device selection
and in-place updates. Sign with an operator-controlled release key backed up
outside the checkout. Read signing passwords from a protected prompt or
descriptor. Keep secrets out of source control, logs and command arguments.

For a fresh install, verify the APK signature and the expected release
certificate fingerprint, package, version and packaged manifest before
installation. For an update, also identify the installed signer and Android
API level. Accept the same release signer or a verified signing lineage from
the installed certificate to the release certificate that grants installed-data
continuity on that API level. Android 13 and later can select a rotated
signer through APK Signature Scheme v3.1. Check which signer the device
will actually see. Use a version code Android accepts for an upgrade.
[Android signing tools](https://developer.android.com/tools/apksigner)
and [v3.1 platform behavior](https://source.android.com/docs/security/features/apksigning/v3-1).

A transition from the existing debug signer needs the matching old private
key and the release key to establish the lineage. Verify the original
certificate against the installed APK. Keep the lineage for future builds
and disable rollback to the old signer. If continuity cannot be verified,
stop before installation and report the reason. The installer must never
uninstall, clear data or downgrade to get past a signature check.

Existing R2 settings carry through the upgrade. The USB provisioning script
uses `run-as` and a debug-only intent. Reject `--r2` for an everyday install
before modifying the device or decrypting Linux credentials. Explain that
an existing installation carries its settings and that a fresh installation
can use the on-device setup screen. Keep debug provisioning available for
explicit development builds.

## Limits

This decision covers Android packaging and installation. Keep the existing
vault format, Keystore aliases, authentication prompts and rollback records.
Release signing establishes continuity with the publisher. It does not
replace device authentication or vault encryption.

## Acceptance

- Verify a fresh release install and a second update signed by the release
  key. Inspect the final and installed manifests, verify the signer for the
  device API level, and check that Android denies `run-as`.
- Rehearse the actual signing transition on a disposable installation using
  a synthetic vault and test credentials. Before and after the update, check
  the package UID, authenticate with the original Keystore settings, reopen
  the same vault, reject an older revision, and read the test R2 object.
  Save an edit and reopen it. The operator should see no setup prompt.
- Exercise an unrelated signer, missing old key, unsupported rotation and
  an attempted downgrade. Each refusal leaves the installed app and data
  usable. A rejected `--r2` request must leave the installation untouched.
- After the rehearsal, obtain the operator's go-ahead for the everyday
  Samsung upgrade. Report separately which device and API levels actually
  passed. Keep signing materials and device credentials out of test results.
