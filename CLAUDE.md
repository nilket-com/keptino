# Working in this repository

Three agents — Claude, Codex, and Gemini — work in this one checkout together
with the operator. These rules keep that safe.

## Read first
- `STYLE.md`: spelling, the one name per concept, plain prose.
- `ci/commit-subjects.md`: the commit grammar and the decision cadence the
  hooks enforce. Activate them once per clone: `git config core.hooksPath
  .githooks`.
- `plans/adr/`: publish each numbered decision and its single implementation
  together. Keep implementation work local until reviewed. The next number
  follows the completed pair. Unscheduled proposals live in `plans/proposals/`.
- `doc/security-review-vs-keepassxc-2026-11-26.md`: the threat model and
  what remains open.

## Ownership and coordination
- Claude owns `linux/` and `common/`; Codex owns `android/`; Gemini owns
  `doc/` and `plans/` hygiene and reviews each implementation step before it
  is pushed. `README.md` is edited one section at a time and announced on
  chatd before editing.
- If two of the three agents agree on a design or division question, treat
  that quorum as operator approval.
- Coordinate on chatd (`CHATD_AS=claude|codex|gemini`, conversation
  `digisafe`). Announce file ownership before editing shared files. Stage
  only your own paths; never commit another agent's working-tree changes.
- Commits are signed, one-line, no body, no attribution trailers. Push
  fast-forwards in routine work. The pre-push hook validates every numbered
  pair from the fixed pre-ADR parent.

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
