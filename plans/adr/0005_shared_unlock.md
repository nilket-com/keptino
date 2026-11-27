# ADR 0005 — Share the unlock between the heads

## Status

Accepted.

## Why

After ADR 0003 both heads still carry their own copy of the same unlock
logic: the salt check between the local and remote copies, the order the
copies are tried in, deriving the master key once and reusing it for the
second copy, the fallback when the preferred copy does not open, the check
that a database names itself, and the reasons a head pauses uploads
afterwards. Two copies of a decision rule drift; the Android copy already
pauses uploads in one case the Linux copy does not.

## Decision

Add `unlock` to `common/core::vault`. It takes the vault name, the parsed
local and remote envelopes, the default cost and a closure that derives a
key from a salt and a cost; it returns the open database, which copy opened
(`Source`), the cost it was derived with, and an optional `Caution` that the
head turns into paused uploads. The two cautions are: the preferred copy
failed and the other opened; a legacy local copy won on its timestamp over a
remote copy that carries a revision. With neither copy present it creates
the vault with a random salt at the default cost. A key that failed on one
copy serves the other when their costs match and is wiped otherwise and at
every exit. A database without `db_name` is damaged. Both heads call it:
Linux from `storage::persistence::load`, Android from `Vault::open`.

## Limits

The heads keep what differs: parsing and what to do about a copy that fails
to parse (Linux refuses, Android opens the other and pauses), where the
pepper and the password come from, the revision file on Linux, the working
entry and the JNI result codes on Android, and every message text. No file
byte changes. The one user-visible change is on Linux, which now pauses
uploads when a legacy local copy beats a versioned remote, the rule Android
already applied.

## Acceptance

Core tests cover ordering, the tie, the fallback with one derivation, a
wrong key, a failing derivation, a foreign salt, the legacy-over-versioned
caution and that a legacy remote never pauses. Linux and Android open every
committed fixture, `android/interop/run.sh` passes at the debug cost and
once at the release cost, and `ci/check.sh` is clean.
