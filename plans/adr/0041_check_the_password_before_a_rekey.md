# ADR 0041 — Check the password before a rekey

## Status

Accepted.

## Why

On Linux, Protect and Remove on the keys screen rekey the vault: they
derive a new master key from the master password the user types there.
Nothing compares that password with the vault. A typo is accepted, and
after Save the vault opens only with the typo. The upload carries that
copy to the bucket and every other device. The user is locked out of
their own vault without knowing why.

## Decision

Before any rekey derives its new key, the head derives the vault's
current key from the typed password, at the vault's own salt and cost,
and compares it with the key the vault is open under. `libkeptino` adds
`Database::is_master_key`, a constant-time comparison. Linux adds
`persistence::verify_password`. A mismatch stops the rekey with "That
is not this vault's master password; nothing changed."

The current key needs the roaming secret when the vault has key slots:
- Protect (no slots yet) checks first, before any key is asked.
- Remove with keys left: the first kept key's assertion already releases
  the old secret. `fido::reenroll_owner` now returns it, and the password
  is checked before any other key is asked or a new key derived.
- Remove of the last key: any enrolled key that answers releases the
  secret for the check. When none answers (the only key is lost while
  the vault is still open), the password cannot be checked. The keys
  screen then asks for it twice, and the rekey goes ahead only when both
  entries match.

## Limits

The check costs one more derivation at the vault's cost before the
rekey's own. The typed-twice case catches a slip of the hand, not a
misremembered password. Android's keys screen is Codex's to check under
its own decision.

## Acceptance

- A wrong password stops Protect before any key is touched, and stops
  Remove after the first key answers, with nothing changed.
- The right password rekeys as before.
- Removing the last key with no key present asks for the password twice,
  refuses two different entries, and proceeds on two matching ones.
- The recovery drill runs the check through real derivations.
- `ci/check.sh` passes.
