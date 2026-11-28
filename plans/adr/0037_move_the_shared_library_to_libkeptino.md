# ADR 0037 — Move the shared library to libkeptino/

## Status

Accepted.

## Why

ADR 0016 merged the shared code into one crate, `libkeptino`, under
`common/libkeptino`. `common/` holds that crate and nothing else, so the
extra directory adds a level to every path and says nothing.

## Decision

The crate moves to `libkeptino/` at the root, so the directory and the
crate share one name. No code, vault byte or name bound
into user data changes. The workspace members, the Linux and Android path
dependencies, the Gradle inputs, the fuzz runner, the README and the
ownership line in `CLAUDE.md` name the new path. The tests that read the
committed fixtures reach them one level up less. The FIDO fixture writer
anchors its output path on the crate directory instead of the working
directory, which pointed above the repository.

Decision records and the dated rows of the security review keep the
paths that were true when they were written.

## Acceptance

`ci/check.sh` passes, every committed fixture still opens and its parity
recomputes, the Android build finds the crate, `libkeptino/fuzz/run.sh` builds a
target, and no live file outside `plans/` and `doc/` names `common/`.
