# ADR 0035 — Record ADRs 0024 through 0034 in the security review

## Status

Accepted.

## Why

The 2026-11-28 security assessment in
`doc/security-review-vs-keepassxc-2026-11-26.md` (ADR 0023) listed five
concrete next security priorities. Since then, ADRs 0024 through 0034
shipped the 256 MiB new-vault creation cost on both heads, nine `libkeptino`
fuzz targets, the release-signed non-debuggable single-profile Android
installer, the Linux seccomp deny filter with cross-target compile checks,
reproducible Linux `.deb` packaging with untracked-file provenance, Android
lock-on-screen-off, and automated recovery drills. The review should record
which items are now closed and which remain open.

## Decision

Keep the earlier 2026-11-26 and 2026-11-28 sections of
`doc/security-review-vs-keepassxc-2026-11-26.md` intact and append a dated
post-ADR 0034 status table summarizing ADRs 0024 through 0034 alongside the
remaining open items (independent external review, physical Android USB/NFC
FIDO2 verification, signing and publishing releases, and any future
vault-worker split for a strict Linux seccomp allowlist).

## Limits

Documentation only. No code, vault format, or dependency changes.

## Acceptance

Verify links and factual accuracy against `main`, obtain review approval,
and pass `ci/commit_subjects.py` on the signed plan and implementation pair.
