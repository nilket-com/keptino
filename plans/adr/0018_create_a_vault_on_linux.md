# ADR 0018 — Create a vault on Linux only when asked

## Status

Accepted.

## Why

On Linux, Unlock creates a new empty vault when the name exists neither
locally nor in the bucket. A misspelled name therefore opens a fresh vault
with the typed password instead of reporting the mistake, and a save then
uploads it under the wrong name. ADR 0017 gave Android a separate Create
action; the Linux head should follow the same rule.

## Decision

Unlock never creates. When the local file is absent and the bucket answers
that the object is absent, Unlock reports that no vault by that name exists
here or in the bucket and points to Create. When the bucket cannot be
reached and there is no local file, Unlock reports the storage error as
today. The core keeps its creation path; the head reaches it only through
Create.

The locked screen gains a Create vault action. It asks for the name, a
nonempty master password entered twice, and the PIN field is not shown. It
says once that the password cannot be recovered. A name containing slash or
NUL is refused, as Unlock refuses it today. Creation is refused when a local
file, a rekey marker or a revision record exists for that name, naming the
file to remove.

Creation needs the bucket. The head fetches the object and requires an
online answer that it is absent. The core then creates the vault with a
fresh salt at the normal 4 GiB cost and revision one, and the head encodes
it once. On a store that speaks S3 (AWS, GCS, R2 and custom S3) the upload
carries `If-None-Match: *`; a 412 or 409 means another device created the
name first, and the head discards the new vault and asks the user to Unlock
instead. Only after the upload succeeds does the head write the local file
and the revision record and open the vault, connected for later saves. A
failed or ambiguous request leaves no local file and no revision record; if
the object did reach the bucket, Unlock opens it.

## Limits

The Backblaze native API used by this head has no create-only precondition.
Backblaze is the Linux default and Linux already creates there, so creation
stays: the head fetches again immediately before an unconditional upload
and refuses if an object appeared. Two devices creating the same name in
that short window can still race, and the later upload wins. Android
refuses this case (ADR 0017); Linux names it instead of removing a working
path.

## Acceptance

Unlock of a missing name reports the error and writes nothing. Create
refuses a mismatched or empty password, an existing local file, a rekey
marker and a revision record before any request. Against the RustFS check,
Create writes the object with `If-None-Match: *`, then the local file and
revision one, and the vault unlocks again. A second Create of the name
is refused by the local file and, on a clean machine, by the bucket
object, writing nothing. The store refuses a create-only upload over an
existing object, the answer the head reports as another device winning.
Failed fetches and uploads leave nothing. The core fixtures stay byte for byte.
The Linux interop driver gains a `create` command, and the harness and the
RustFS check create new vaults through it.
