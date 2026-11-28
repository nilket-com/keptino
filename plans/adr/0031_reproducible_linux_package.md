# ADR 0031 — Build the Linux package reproducibly

## Status

Accepted.

## Why

The 2026-11-28 assessment asks for signed, reproducible releases. Someone
who wants to trust a Keptino package today has to trust the machine that
built it. A reproducible package lets anyone rebuild the published commit
and compare bytes. Building the package twice on the build host already
gives identical bytes, but nothing records how, nothing checks it, and the
binary names the builder's home directory (`/home/<user>/.cargo/registry/…`)
in panic and log locations. That differs between builders and discloses
the user name.

## Decision

`linux/build-deb.sh [--sign KEY] [OUTDIR]` is the one way to build the
release package, and `setup.sh` installs what it builds.

- `SOURCE_DATE_EPOCH` is the commit's time, so every archive timestamp is
  fixed.
- `--remap-path-prefix` replaces the Cargo home with `/cargo` and the
  checkout with `/keptino`. Cargo's `trim-paths` would do this but is not
  stable.
- The build is `cargo deb --locked` in a target directory of its own. It
  runs under `ci/heavy` when the checkout has it.
- Beside the package it writes `BUILDINFO` (commit, whether the tree had
  uncommitted changes, the epoch, the `Cargo.lock` hash, `rustc -vV` and
  the cargo-deb version) and `SHA256SUMS` over both files.
- `--sign KEY` signs `SHA256SUMS` with an SSH key
  (`ssh-keygen -Y sign -n keptino-release`). A user verifies with
  `ssh-keygen -Y verify -n keptino-release -f allowed_signers -I <signer>
  -s SHA256SUMS.sig < SHA256SUMS`, then `sha256sum -c SHA256SUMS`.

`linux/repro-check.sh [COMMIT]` builds one commit twice:
- from two clean checkouts at different paths,
- through two different Cargo home paths,
- into two target directories.
It requires byte-identical packages and checksums, and that the unpacked
package names none of the home, Cargo home or checkout paths. It takes about
twenty minutes, so it is run before a release, not in the gate.

## Limits

The toolchain is not pinned: `BUILDINFO` records it, and a rebuild needs
the same `rustc` and cargo-deb. Reproducibility is checked on one host with
varied paths, not across distributions with different system libraries;
the package links only the C library and the Rust standard library. No
release is published or signed by this decision, and there is no
`allowed_signers` file yet.

## Acceptance

`repro-check.sh` passes for the implementation commit: identical packages
and checksums, and no builder path. `setup.sh` installs the package that
`build-deb.sh` built. `BUILDINFO` and `SHA256SUMS` sit beside it.
