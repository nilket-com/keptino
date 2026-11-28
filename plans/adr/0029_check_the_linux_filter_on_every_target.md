# ADR 0029 — Check the Linux system call filter on every target

## Status

Accepted.

## Why

Codex reviewed ADR 0028 after it was pushed and found three faults. The
filter does not compile for aarch64 musl, because the pinned libc has no
`SYS_kexec_file_load` there. The filter test ran every refused call first
and read errno once at the end, so a call that failed for another reason
could pass on a later call's EPERM. And preflight logged "Preflight
security checks passed" even when the filter or Landlock had not taken
effect.

## Decision

- On aarch64 musl the filter denies kexec_file_load by its generic number,
  294, the number libc gives aarch64 glibc. Every other target keeps
  libc's name.
- `linux/seccomp-targets.sh` compiles `linux/src/seccomp.rs` with its tests
  for x86-64 and aarch64, glibc and musl, against the libc that
  `Cargo.lock` pins. The whole head cannot cross-compile without C
  toolchains, so the module is checked alone. `ci/check.sh` runs it, and
  it names any Rust target the host lacks.
- The filter test reads each call's errno right after that call and names
  the call in its assertion.
- Landlock and the filter each report whether they took full effect.
  Preflight then logs that it passed only when both did. Otherwise it
  warns, naming the step that was not enforced. The command line form does
  the same for its filter.

## Limits

The cross check compiles and does not run: other architectures' filters
are not exercised. Preflight still continues when a step is not enforced,
as ADR 0028 decided.

## Acceptance

The cross check passes for the four targets, and failed on aarch64 musl
before the change. With the install line removed, the filter test fails at
its first call, ptrace, with ESRCH, not at a later one. A unit test covers
the preflight status line for none, one and two missing steps. The gate
passes.
