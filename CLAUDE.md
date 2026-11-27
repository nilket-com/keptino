# Working in this repository

Two agents, Claude and Codex, work in this one checkout together with the
operator. These rules keep that safe.

## Read first
- `STYLE.md`: spelling, the one name per concept, plain prose.
- `ci/commit-subjects.md`: the commit grammar and the decision cadence the
  hooks enforce. Activate them once per clone: `git config core.hooksPath
  .githooks`.
- `plans/adr/`: numbered decisions. A design change starts with a `plan:
  adr NNNN` commit that adds exactly one file there; implementations follow
  as `impl: adr NNNN` commits. A patch with no design change is `fix:`,
  `test:` or `docs:`.
- `doc/security-review-vs-keepassxc-2026-11-26.md`: the threat model and
  what remains open.

## Ownership and coordination
- Claude owns `linux/` and `common/`; Codex owns `android/`. `README.md` is
  edited one section at a time and announced on chatd before editing.
- Coordinate on chatd (`CHATD_AS=claude|codex`, conversation `digisafe`).
  Announce file ownership before editing shared files. Stage only your own
  paths; never commit the other agent's working-tree changes.
- Commits are signed, one-line, no body, no attribution trailers. Push
  fast-forwards only; the pre-push hook checks `origin/main..HEAD`.

## What must not change
- Names bound into user data: systemd-creds names `pepper`, `backblaze`,
  `aws`, `gcs`, `r2`; the Argon2 salt string `digipepper`; the Android
  Keystore aliases; the legacy `digipepper.cred` migration path.
- Byte compatibility: every committed fixture under
  `android/droid/tests/fixtures` must open on both platforms and its parity
  must recompute byte for byte. Never write a format marker or AAD again;
  extend the TLV meta set and rely on the mirror check.
- The vault talks to one thing, the user's own storage bucket. No new IPC,
  network or plugin surface without a decision record.

## Before pushing
- `ci/check.sh` from the root: rustfmt, clippy with warnings denied, the
  tests of every crate, `cargo audit` with the accepted list, and the
  commit-history check. Dependencies resolve under the seven-day cooldown in
  `.cargo/config.toml`; override one crate only for a published security fix.
- Codex's Android device and emulator checks run from `android/`.
