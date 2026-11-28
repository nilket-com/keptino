# ADR 0028 — Filter system calls on Linux after preflight

## Status

Accepted.

## Why

S1 in the 2026-11-26 review asks for Landlock and a seccomp filter after
preflight. Landlock limits which files the process reaches. It does not
stop code running inside a compromised process from reading another
process's memory, creating a user namespace (the usual first step of a
kernel exploit), or reaching kernel interfaces such as io_uring, BPF and
the keyrings that no part of Keptino uses.

## Decision

The last preflight step installs a seccomp filter on every thread
(`SECCOMP_FILTER_FLAG_TSYNC`), after no_new_privs. Every helper inherits it,
`systemd-creds` and `lsblk` included. The command line form installs it too.
The program is built in `linux/src/seccomp.rs` with no new dependency:

- A call in another architecture's numbering, or an x32 call, ends the
  process.
- A fixed list of calls answers EPERM: ptrace, process_vm_readv and
  process_vm_writev, process_madvise, pidfd_getfd, kcmp, bpf,
  perf_event_open, userfaultfd, the io_uring calls, kexec and module
  loading, mount and the new mount API, pivot_root, chroot, unshare,
  setns, keyctl, add_key, request_key, personality, acct, swap, reboot,
  host name, clock and quota settings, syslog, file handles,
  lookup_dcookie, vhangup, and on x86-64 iopl, ioperm, uselib, ustat,
  sysfs and `_sysctl`.
- `clone` with any namespace flag answers EPERM. `clone3` answers ENOSYS,
  because its flags are in memory the filter cannot read; the C library
  then falls back to `clone`.
- Every other call is allowed.

EPERM rather than ending the process: a library that probes a call sees an
ordinary refusal, and the attacker gains the call in neither case.

The list was checked against what Keptino makes. strace of GUI startup,
of the ten RustFS check runs, and of a TPM `systemd-creds` round trip and
`lsblk` shows none of the denied calls. With the filter on, the RustFS
check passes, the real `systemd-creds` encrypts and decrypts, and the
window unlocks.

## Limits

This filters by denial, not by an allowlist. The window, Wayland, fonts,
D-Bus, TLS, security keys and helpers share one process. An allowlist
there would break in the field whenever a library or the C library
changes, and a password manager that will not unlock is a failure. An
allowlist needs a smaller process to hold it, such as a vault worker
without the window; that split is not decided here. The filter does not
read the arguments of `socket`, `ioctl` or `execve`. Landlock already
limits which programs can be started. Other architectures run without the
filter and with a warning.

## Acceptance

On a thread under the filter, the denied calls answer EPERM, a namespace
`clone` answers EPERM, `clone3` answers ENOSYS, and threads and helpers
still start. An x32 call ends a forked child with SIGSYS. Every thread of
the running window reports `Seccomp: 2`. The RustFS check passes through
`examples/seccomp-exec`, which installs the filter and runs a command.
Unlock, copy, generate, save and lock work in the window.
