# ADR 0033 — Rehearse vault recovery paths automatically

## Status

Accepted.

## Why

The 2026-11-28 security assessment (ADR 0023) notes that Keptino's stronger
key separation creates sharper lockout failure modes than KeePassXC: losing a
machine, damaging a local or bucket copy, or losing an enrolled security key
must be recoverable in practice, not only in design. Rehearsing these paths
automatically on throwaway vaults proves the recovery mechanics end to end
without risking a real vault.

## Decision

Add two automated recovery drills using Keptino's own storage, key derivation,
and security-key code on throwaway vaults:

- `linux/src/storage/drill.rs` (run in `cargo test -p keptino drill`):
  rehearses losing a daily security key on a two-key vault (`daily` +
  `backup`), recovering with the backup key alone, removing the lost key to
  rekey under a fresh roaming secret, confirming the lost key no longer opens
  the rekeyed vault, and enrolling a replacement key alongside the backup.
- `linux/recovery-drill.sh` (run against a local RustFS node under
  `ci/heavy` when present): rehearses five storage and pepper disasters using
  `keptino --derive-pepper` and the Linux interop driver:
  1. Lost machine: re-deriving the pepper from the seed on a fresh home opens
     the bucket copy and advances it to revision 3.
  2. Wrong seed (one character off): unlock fails and writes no local file.
  3. Local copy damaged beyond Reed-Solomon repair (5 of 12 shards zeroed):
     unlock fails closed rather than silently overwriting local data; moving
     the damaged file aside recovers revision 3 from the bucket and saving
     restores the local file.
  4. Stale device: a machine holding revision 2 adopts revision 3 from the
     bucket.
  5. Bucket copy damaged beyond repair: the intact local copy still opens.

## Limits

The key drill uses simulated HID keys at the debug KDF cost, and the shell
drill substitutes a pass-through `systemd-creds` shim because it tests seed
derivation and copy recovery rather than a physical TPM. A vault copy saved
before a lost security key was removed can still be opened by that lost key
with the password and pepper until old backups are deleted. Physical hardware
drills on a real YubiKey and phone remain manual operator exercises.

## Acceptance

`cargo test -p keptino drill` passes in `ci/check.sh`. `linux/recovery-drill.sh`
passes all five cases against a local RustFS node.
