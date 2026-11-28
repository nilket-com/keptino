# ADR 0023 — Document the 2026-11-28 security assessment and priorities

## Status

Accepted.

## Why

The initial security review in `doc/security-review-vs-keepassxc-2026-11-26.md`
predates FIDO2 security keys (ADR 0011 to 0013), pure-Rust S3 and Cloudflare R2
sync (ADR 0014 and 0015), `libkeptino` unification (ADR 0016), explicit vault
creation (ADR 0017 and 0018), and the Nautilus redesign (ADR 0019 to 0022). Its
status table is stale, and the document needs an explicit self-assessment caveat
separating design strengths from assurance gaps.

## Decision

Keep the original 2026-11-26 review baseline intact and append two dated
sections to `doc/security-review-vs-keepassxc-2026-11-26.md`:

- A 2026-11-28 status update summarizing ADR 0011 through ADR 0022.
- A clearly separated 2026-11-28 honest assessment from Claude, Codex and
  Gemini comparing Keptino and KeePassXC on design versus assurance, noting
  the self-assessment caveat, and ranking the concrete next security
  priorities (release-signed non-debuggable Android everyday install,
  `libkeptino` parser fuzzing and external review, physical Android FIDO2
  verification and recovery drills, Linux seccomp and reproducible releases,
  and default KDF cost versus phone availability).

## Limits

Documentation only. No code, vault format, or dependency changes. Remove
`plans/proposals/optional_fido2_security_keys.md` only if no open design
items remain outside the shipped ADRs.

## Acceptance

Verify the updated markdown links and formatting, obtain review sign-off from
Claude and Codex, and pass `ci/commit_subjects.py` on the signed plan and
implementation pair.
