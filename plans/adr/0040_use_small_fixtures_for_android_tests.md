# ADR 0040 — Use small fixtures for routine Android tests

## Status

Accepted.

## Why

The local and mock Backblaze editor tests each unlock the same 4 GiB
Linux vault twice. The Linux read-back also derives the same public
fixture pepper from its seed for each file. These costs make routine checks
difficult to run on a small emulator or build host.

## Decision

Run the editor tests with the committed unmarked Linux fixture that records
a 4 MiB Argon2id cost. Exercise both storage paths and reopen the edited
files on Linux. Use the fixture manifest's pepper for debug interoperability
and file checks. Keep seed derivation in the release and fixture-generation
runs. Provide the `--argon2-4gib` emulator option for the 4 GiB UI checks.

## Limits

This changes test inputs only. The production unlock path still reads each
vault's recorded cost and uses 4 GiB when the vault records none. New vaults keep
their existing creation cost.

## Acceptance

The ordinary local and mock Backblaze editor tests open, edit and save the
4 MiB fixture through the device credential prompt. Linux reads the edits.
The 4 GiB option selects the release fixture for both storage paths. No committed vault bytes change.
