# ADR 0010 — Derive the pepper inside Keptino

## Status

Accepted.

## Why

The Linux pepper is Argon2id over the seed the user types at setup, salt
`digipepper`, four passes, 4 GiB, one lane, 32 bytes. Core has carried that
exact derivation since ADR 0002 and Android uses it, yet `linux/setup.sh`
still installs the external `argon2` package for one pipeline and the
Debian package depends on it. That tool runs the 4 GiB derivation with the
seed and the arena in ordinary memory: no memory lock, dumpable, nothing
wiped. The one secret that protects every vault against a stolen file is
derived with less care than the vault itself. The operator asked for the
dependency to go.

## Decision

The `keptino` binary gains one command line form, `keptino --derive-pepper`.
It reads the seed from standard input exactly as the `argon2` tool did,
every byte including any newline and any byte after it, refuses an empty
seed and a seed over 127 bytes, which the tool refused too, so no stored
credential came from one and no larger read can fill locked memory, and
derives the pepper
with `core::crypto::derive_pepper` at the fixed production cost, and writes
64 lowercase hex characters and a newline to standard output, the framing
`argon2 -r` produced, so `systemd-creds` stores the same bytes and the
pepper credential of an existing installation is reproduced to the byte.
Before the seed is read the process locks its memory, refuses to be dumped
and refuses a preloaded library, the first three steps of the GUI
preflight; the display, TME, LUKS and Landlock steps are for the GUI and
are skipped. The seed, the arena and the pepper are wiped before exit. Exit
status: 0 on success, 1 for an empty seed or a failed derivation with one
line on standard error, 2 for any other argument, which until now was
ignored and started the GUI.

`linux/setup.sh` runs `/usr/bin/keptino --derive-pepper` in place of the
`argon2` tool, drops `argon2` from the package list and the tool check,
and in its `--restore-pepper` form first checks with `dpkg` that the
installed package is 0.2.2 or newer, since that form runs before the build;
an older or missing package is told to run the full setup first. The
package version becomes 0.2.2 and its dependencies are `systemd,
libcap2-bin`. The README's Linux setup section drops `argon2` from the
package list and names the flag.

## Limits

No pepper byte changes: the derivation, salt and cost are those of the
pipeline being replaced, so a seed yields the same credential as before.
Android is untouched; it already derives in core. The flag takes no option:
the cost is fixed, the salt is fixed, and a debug or test cost is not
offered on the command line. The flag does not read or write any file and
does not open the vault directory. A `--version` or `--help` is not added
here.

## Acceptance

Core already pins the derivation against the `argon2` tool at a low cost.
Linux tests: the framing function writes the pinned low-cost vector as 64
hex characters and a newline for the same seed, refuses an empty seed and
one of 128 bytes, takes one of 127, and hashes a seed with a trailing
newline differently from one without, as the tool did; an ignored test runs
the installed-cost derivation end to end and compares it with `argon2
digipepper -id -t 4 -m 22 -p 1 -l 32 -r -v 13` on a host that has the tool.
`./linux/setup.sh --restore-pepper` succeeds on a host without `argon2` and
reproduces an existing pepper credential's plaintext. `cargo deb` builds a
package that depends on `systemd, libcap2-bin`. `ci/check.sh` is clean.
