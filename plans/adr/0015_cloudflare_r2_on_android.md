# ADR 0015 — Cloudflare R2 on Android and setup from Linux

## Status

Accepted.

## Why

The phone needs to open and save the same vault as Linux. Entering the
pepper and R2 credentials by hand makes a first unlock unnecessarily hard.

## Decision

Android can choose local storage, Backblaze B2 or Cloudflare R2. Existing
settings retain their provider. R2 uses the shared SigV4 signer, the Linux
object name and base64 encoding, region auto and the account's HTTPS host.
Uploads compare the observed vault fingerprint and use the same GET's
strong ETag or a create-only condition. A conflict pauses uploads.

The ADB installation can import Linux setup with an explicit phone action.
The host releases pepper.cred and r2.cred through systemd-creds and streams
a bounded message to a private, temporary FIFO under the installed app UID.
The phone checks the R2 bucket using a read-only request and saves the
settings only after device authentication. Both ends discard the buffer.
No plaintext setup file, clipboard, intent extra or exported service is used.

## Limits

The USB helper requires a trusted, authorized ADB connection to a debuggable
Keptino build. Manual setup works in release builds. R2 uses a bucket in the
default jurisdiction as on Linux. Configuring the provider never writes an
object or changes a local vault file.

## Acceptance

Exercise the signed GET and conditional PUT through Android, including an
absent object, a conflicting writer, a denied download and bounded bodies.
Check the wire representation against Linux. Prove old settings still read,
a canceled import preserves the previous settings, and synthetic setup can
cross the ADB pipe. Verify production read access only with operator approval.
