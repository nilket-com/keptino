# ADR 0014 — Sync with any S3 endpoint through one signer

## Status

Accepted.

## Why

The Linux head speaks path-style S3 Signature Version 4 to AWS, Google
Cloud Storage and Cloudflare R2, through a vendor's signing crate and with
the endpoint chosen by provider name. A user who runs an S3-compatible
store of their own, such as RustFS on a single node, cannot point Keptino
at it, although their own bucket is exactly what the one-endpoint rule
means. The Android head speaks only Backblaze B2 and has no signer at all.
The operator asked for RustFS, tested on their host; the team agreed the
signer belongs in shared code so both heads carry one implementation and
one set of vectors.

## Decision

Signer. A new workspace crate `common/s3`, `keptino-s3`, pure Rust, no
I/O, with `sha2`, `hmac` and `zeroize`: `validate_endpoint` takes an
`https://` URL with a host, an optional port and no userinfo, path, query
or fragment, and returns it with one trailing slash removed; in a debug
build alone an `http://` loopback endpoint passes, for tests against a
local store; `validate_bucket` keeps the existing lowercase, digit, hyphen,
dot and underscore rule and refuses `.` and `..`; `sign` takes the method,
the endpoint, the bucket, the object key, the region, the access key id,
the secret, the payload and the time, and returns the `host`, `x-amz-date`,
`x-amz-content-sha256` and `authorization` headers of `AWS4-HMAC-SHA256`
with single percent encoding, no path normalization and the payload's
SHA-256 as the content hash, which is what the Linux head sends today; and
`is_missing_key` recognizes an S3 error body whose code is `NoSuchKey`
without an XML crate. The signer is pinned to the headers the current
Linux signer produces for fixed inputs, so no request to AWS, GCS or R2
changes by a byte, and to a vector from the AWS Signature Version 4 test
suite, so the two implementations cannot share a mistake.

Linux. `storage::remote` signs through `keptino-s3` and drops the
`aws-sigv4`, `aws-credential-types` and `quick-xml` dependencies. One
provider name is added, `s3`, bound into `s3.cred` and `setup.sh` as the
others are: its credential is `endpoint`, `bucket`, `region`, access key id
and secret, NUL-separated, sealed by `systemd-creds` and held in secret
memory for the session. `setup.sh --configure-storage s3` asks for the
endpoint URL, which must be `https://`, the bucket, the region with
`us-east-1` as the default, and the keys, and validates each as the
provider will. The client keeps `https_only`, no redirects, the 30-second
timeout, the 64 MiB body bound and the fetch-and-compare before every
upload. The write precondition Codex raised in ADR 0012 is added where the
protocol offers it: a `PUT` carries `If-Match` with the entity tag of the
object the save fetched, or `If-None-Match: *` when the bucket held none,
and a `412` is reported as the remote having changed; a store that ignores
the header is no worse than today.

RustFS. The acceptance test runs a RustFS single node, locally in the
harness over loopback HTTP in the debug build, and once on the operator's
host over TLS: missing object, upload, download, overwrite, the oversize
refusal, and a save refused because the object changed underneath.
`README.md` documents the `s3` provider with RustFS as the example.

## Limits

Path-style addressing only. The endpoint must terminate TLS with a
certificate the OS trusts; a custom CA bundle is a separate decision.
Android keeps Backblaze alone in this decision; the signer is built for it,
and ADR 0015 or later gives the Android head the `s3` provider, which is
why the crate has no I/O and no HTTP client. No existing provider name,
credential file or wire byte changes. `backblaze` keeps its own API.

## Acceptance

Crate tests: the pinned Linux vectors for `GET` and `PUT` with a body and
a key with a space, an AWS test-suite vector, endpoint validation
accepting `https://host`, `https://host:9000` and refusing `http://` in
release, userinfo, a path, a query, a fragment and an empty host, bucket
validation, and `is_missing_key` on a RustFS and an AWS error body. Linux
tests: the `s3` credential parses and a malformed one is refused with the
setup hint; the conditional headers are set from the fetched entity tag.
Harness: `android/interop/run.sh` passes at the debug cost, and a new
`linux/rustfs-check.sh` runs the RustFS cases against a local node; the
operator runs it once against strix and the result is recorded on chatd.
`ci/check.sh` is clean with no `aws-*` crate in the lockfile for the
Linux head.
