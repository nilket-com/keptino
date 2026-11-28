# ADR 0036 — Refactor the main README

## Status

Accepted.

## Why

`README.md` accumulated sections chronologically across 35 decisions. It opens
with DigiSafe rename migration steps before explaining what Keptino does,
still lists the old 4 GiB new-vault cost and fixed 24-character generator,
omits shipped controls (Linux seccomp, Android lock-on-screen-off,
reproducible Linux packages, `libkeptino` fuzzing, automated recovery drills,
and the security assessment), and mixes platform protections with sync and
setup details.

## Decision

Rewrite `README.md` into a clear, top-to-bottom reference following `STYLE.md`:

- Lead with what Keptino is, its shared `libkeptino` core, and current
  Linux and Android Nautilus screenshots (preserving the `#android-screenshots`
  anchor).
- Group cryptography and format, platform protections (Linux and Android),
  FIDO2 security keys, cloud sync and provider setup, installation and
  reproducible builds, verification and security review links, and deliberate
  exclusions and known limits into dedicated sections.
- Move the DigiSafe upgrade and cloud-object rename notes to the bottom.
- Keep every technical claim accurate against `main` (`54b86a3`).

## Limits

Documentation only. No code, script, or vault format changes. Platform-specific
Android details stay in `android/README.md`.

## Acceptance

Verify all internal markdown links and image paths resolve, check wording
against `STYLE.md`, obtain review approval, and pass `ci/commit_subjects.py`
on the signed plan and implementation pair.
