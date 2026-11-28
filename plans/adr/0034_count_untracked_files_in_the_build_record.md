# ADR 0034 — Count untracked files in the Linux build record

## Status

Accepted.

## Why

ADR 0031's `BUILDINFO` says whether the tree that built a package had
uncommitted changes, so a package that is not the commit cannot pass as
it. Codex found that the check ignored untracked files. A new source file,
or an asset pulled in with `include_bytes!`, could change the package while
`BUILDINFO` still said `uncommitted-changes no`.

## Decision

`linux/build-deb.sh` counts untracked files too: any change `git status
--porcelain` reports, tracked or not, makes `uncommitted-changes yes`.
Build output stays out because `.gitignore` covers `target/`.

## Limits

A tree with a stray untracked file that is not a build input is reported
as changed. That errs toward saying a package is not the commit, which is
the safe direction. Ignored files are still not counted.

## Acceptance

On a clean checkout `BUILDINFO` says `uncommitted-changes no`. With one
untracked file added it says `yes`, and with a tracked file modified it
says `yes`.
