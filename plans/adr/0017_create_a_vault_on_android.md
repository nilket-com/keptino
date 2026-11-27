# ADR 0017 — Create a vault on Android

## Status

Accepted.

## Why

Android can unlock a vault from Linux but a phone user needs a way to start
a new vault. A misspelled name or an unavailable bucket must never turn an
Unlock into a creation.

## Decision

After setup, the locked screen offers a separate Create vault action. It
asks for a name and a nonempty master password entered twice, and explains
once that the password cannot be recovered. Use the pepper already protected
by Android Keystore, including a pepper imported from Linux. Authenticate
as for Unlock. The core generates the salt and uses the normal production
4 GiB cost. Propagate derivation errors. Encode the empty vault once and
start its local trusted revision at one.

Use Linux file-name semantics for named vaults: reject slash and NUL and
require a name in the creation form. Check for an existing local vault,
legacy copy or recovery state before creation and before local commit.

With local-only settings, commit the new file locally. With R2 configured,
require an online GET reporting NoSuchKey, then PUT with If-None-Match: *.
Persist the candidate locally only after a successful conditional creation.
If another writer wins, discard the candidate and try to unlock the
downloaded winner using the supplied password and its own security-key
policy. A failed or ambiguous request leaves no new local vault. The user
can Unlock to recover an object already committed to R2. A configured
provider may never be bypassed through the offline checkbox.

## Limits

The Backblaze native upload API used by this head has no create-only
precondition. Refuse creation with those settings before sending a write.
Existing vaults continue through the normal Unlock and Save paths.

## Acceptance

Exercise local creation, duplicate refusal, revision one, successful R2
creation, a competing writer and failed reads and writes. Confirm failed
requests cannot create a local file or revision record. Open vault bytes
created on Android with the Linux reader using the same pepper and password.
