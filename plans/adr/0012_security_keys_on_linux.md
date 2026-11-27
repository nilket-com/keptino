# ADR 0012 — Enroll and use security keys on Linux

## Status

Accepted.

## Why

ADR 0011 put the roaming secret into the key derivation, the key slots into
the vault and the CTAP2 ceremonies into `keptino-fido`, and proved them
against a simulated key. No user can touch any of it: nothing opens a
device and no screen offers to enroll a key. This decision gives the Linux
head the transport and the screens, so the operator's YubiKey protects the
vault. Android follows in ADR 0013 over the same core.

## Decision

Transport. `linux::fido` finds security keys through `/sys/class/hidraw`:
a device whose report descriptor declares usage page `0xF1D0`, usage
`0x01`, is a key; `/dev/hidrawN` is opened read and write, `CTAPHID_INIT`
on the broadcast channel allocates the channel, and 64-byte packets move
with a one-second read timeout, a thirty-second wait for a touch, and a
keepalive-aware loop that writes `CANCEL` when the user gives up. The
driver runs the `keptino-fido` ceremonies on a worker thread; the GUI never
blocks and no vault lock is held while a key is in hand. The Landlock rules
already allow `/sys` read and `/dev` read-write, so the sandbox does not
widen. Access to the device comes from systemd's `60-fido-id.rules` and
`uaccess`; `linux/setup.sh` checks those rules exist and otherwise says what
to install. More than one key present is fine: an assertion is offered to
each in turn until one owns a slot.

Unlock. `load` parses the local copy first; when either copy carries slots
the unlock screen shows a PIN field, taken when a slot needs verification,
and the status line asks for a touch. The derive closure runs the assert
ceremony over the candidate's slots with that transport, as the fixture
tests do, and maps the outcome into `Derived`: a secret into the key
derivation, a cancellation ends the unlock, a key that owns no slot leaves
the copy unavailable. The two-copy rules of ADR 0011 hold unchanged.

Rekey across copies. A rekey writes a fresh salt, so the local and the
remote copy differ in salt until the upload lands, and `unlock` keeps
refusing copies with different salts: nothing inside a successor can prove
the predecessor authorized it, since a successor without slots opens with
the password alone and the predecessor's salt is public. The device that
rekeyed is the one party that knows the transition, so it alone finishes
it. Its save writes a marker file `<db>.keptino.rekey` beside the vault
before the upload: the fingerprint of the remote object it opened, and the
salt and revision of the successor it committed. The upload replaces the
remote only while the remote still matches that fingerprint, as every
upload already does, and the marker is removed when the upload succeeds. At
a later unlock on that device, a remote whose fingerprint equals the
marker's is the predecessor and is not offered to `unlock`; the local copy
opens alone and uploads stay enabled, so the rekey finishes after a restart
or a failed upload. A remote with any other fingerprint and a different
salt is refused as before. Every other device sees `DifferentVault` once
the successor lands, with a message naming the way out: an Adopt bucket
copy action on the unlock screen that keeps the local file as a generation,
opens the remote alone with the keys in hand, and only then replaces the
local copy. Nothing ever falls back to an older copy after a cancel or a
failed assertion. No `Caution` is added; on both heads every caution pauses
uploads, and a finished rekey is not a caution.

Screens. A Keys button in the button bar opens a keys screen in place of
the editor: each slot with its number, mode and the first bytes of its
credential id, and three actions. Add a key enrolls a new key into a free
slot, in verified mode when the key has a PIN or built-in verification and
touch-only otherwise, with a switch to choose touch-only on a key that
allows it, and takes effect on Save like every other change. Protect with
a security key, offered when the vault has no slot, makes the roaming
secret, enrolls the first key and rekeys. Remove a key rekeys: a fresh salt
and a fresh roaming secret, each remaining key touched in turn to receive
a new slot, a key not in hand dropped after a confirmation that names it,
and the database re-encrypted; removing the last key turns protection off.
Enrollment and rekey finish only when the save commits; a cancel, an
unplug or an error before that leaves the vault and the session as they
were, and a credential already made on the hardware is not undone. Lock
discards the screen.

`STYLE.md` gains the term rekey.

## Limits

Linux only; Android gains the same through ADR 0013 and until then opens a
vault with slots only with the simulated key in its tests, so a user who
enrolls a key here cannot open that vault on the phone until 0013 lands;
the keys screen says so. USB HID only; NFC and BLE on Linux are out. Four
slots at most. No key file, no HMAC-SHA1 OTP slot. No file byte changes for
a vault without slots. The rekey ceremony is the only path that changes a
salt; losing every enrolled key with the vault locked means the vault
cannot be opened, as the proposal states, and the keys screen says that
before the first enrollment.

## Acceptance

Linux unit tests: the hidraw report descriptor check accepts a FIDO
descriptor and rejects a keyboard's; the driver loop against an in-process
fake device completes a ceremony, surfaces a keepalive, cancels on request
and times out; the keys screen state adds, removes and rekeys against the
simulated key through messages, leaving state unchanged on cancel; unlock
with the fixture through the real `load` path with a simulated transport.
Linux tests for the rekey marker: a rekeyed local over the predecessor
remote opens the local alone with uploads enabled, after a restart too; a
remote that changed under the old salt is refused; a successor without
slots carrying a higher revision is refused on a device without the marker;
a stale device adopts the bucket copy only through the explicit action,
which keeps a generation and needs the key. Operator check on the YubiKey,
recorded in the impl commit's subject only as done: protect a test vault,
unlock with touch and with PIN, add a second key, remove the first, unplug
during a touch, cancel at the PIN. `ci/check.sh` clean,
`android/interop/run.sh` passes at the debug cost, every committed fixture
opens.
