# ADR 0013 — Enroll and use security keys on Android

## Status

Accepted.

## Why

A vault protected on Linux needs an enrolled security key on the phone too.
Android can open the two-slot fixture with a simulated key, but its production
unlock cannot ask a physical key to open a slot. The phone needs to unlock,
enroll a spare, and recover sync after either device rekeys the vault.

## Decision

**USB.** During a foreground key operation, let the operator choose an
attached device. Request access through `UsbManager` with an app-scoped
permission result. Check the request, device, active operation, and current
permission before opening it. Read the bounded HID report descriptor for
each candidate interface. Claim only the FIDO application collection
(usage page 0xF1D0, usage 0x01) with 64-byte interrupt IN and OUT reports.
Leave keyboard and smart-card interfaces available to their owners. Use
`UsbRequest.queue` and bounded `requestWait` calls on a worker. Check the
completed request and byte count. Use the shared HID codec to allocate a
channel with INIT and verify its nonce before starting the ceremony.
[USB host](https://developer.android.com/develop/connectivity/usb/host) ·
[UsbRequest](https://developer.android.com/reference/android/hardware/usb/UsbRequest)

**NFC.** Enable foreground reader mode for NFC-A and NFC-B during a requested
operation, skip NDEF discovery, and connect to one `IsoDep` tag. Select the
FIDO applet and check its response through the shared NFC codec. Transceive
the short APDUs from the ceremony within the adapter's maximum length and a
bounded timeout. The shared codec handles command chaining, ISO 61xx response
bytes, and CTAP 9100 polling using P1 0x80 on the message. Pace pending
polls and bound the whole exchange even if the tag keeps answering.
Tag loss ends that operation. A new tap starts a fresh exchange.
[IsoDep](https://developer.android.com/reference/android/nfc/tech/IsoDep)

**Rust and Kotlin.** Build the Android native library with the production
`keptino-fido` crate and track its sources and manifest in the Gradle
native build inputs. Keep the simulator a test dependency. Drive
`Ceremony::assert` and `Ceremony::enroll` inside Rust. Kotlin supplies
transport I/O and user input. A blocking JNI call on an I/O worker can
drive the existing synchronous `Vault::open_with_security_key` resolver
through transport callbacks. Kotlin receives frames, prompts, status, and
public slot descriptions. The roaming secret, decrypted extension output,
PIN tokens, and derived keys stay in Rust. Pass each entered PIN in a
temporary byte array and wipe it after handoff. Keep PINs out of saved UI
state, logs, and exception text. The shared ceremony controls verification
mode and refreshes PIN authorization between enrollment and assertion.

Tie each operation to the current vault session and one foreground request.
Hold no registry or vault mutex while waiting for hardware, a PIN, or a
permission dialog. Cancel on operator request, lock, detach, tag loss, or
loss of the initiating screen. Let the expected USB permission dialog
complete without losing its request. Abort the native ceremony, send HID
CANCEL when possible, cancel pending requests, close the connection, and
disable reader mode. Discard late completions, including after activity
recreation. An invalid or blocked PIN stops the attempt without automatic
resubmission. Keep the Android device credential prompt distinct from the
security key PIN.

**Unlock and key management.** Use the shared candidate order, slot-specific
verification mode, and upload cautions. A cancel ends the entire unlock.
Only a key that owns no usable slot returns the recoverable unavailable
result. Refuse a protected candidate before allocating its Argon2 arena
when the assertion fails. Ordinary unlock and save for a vault without
slots require no transport permission or hardware.

The unlocked Keys screen lists each slot and its verification mode. Protect
enrolls the first key with a fresh salt and roaming secret. Add a key
asserts an existing slot, then enrolls a distinct key around the same
secret. Keep the four-slot limit and request the PIN for the key currently
in hand. Remove rekeys with a fresh salt, proves ownership of each surviving
slot before re-enrollment, and names every missing slot the operator chooses
to drop. Removing the last slot turns off protection after confirmation.
Explain the loss of access if all enrolled keys are lost while locked.
Rekey prompts for the master password and obtains the pepper through the
existing authenticated settings path. Confirm the password before committing
a successor, including when removing the last key.

**Save and sync.** Stage a pending key change under the active session.
Publish the new salt, slots, master key, and revision together after the
local atomic write succeeds. Cancel or a failed local write leaves the
previous vault usable. Ordinary saves preserve the slots without a touch.
For a synced rekey, persist the app-private marker before replacing the
local file. Bind it to the observed predecessor fingerprint and the local
successor salt and minimum revision, as in ADR 0012. Android can keep its
existing SHA-256 bucket fingerprint because the marker stays on the phone.
Distinguish a confirmed absent object from an offline or failed read.
If the predecessor has never been observed, keep the local save and require
explicit reconciliation before allowing an upload.
Keep a pending marker across a failed upload or restart. Withhold a verified
predecessor during unlock and recheck it before upload. A stale marker
cannot authorize replacing a changed bucket object.

On another device, different salts require explicit **Adopt bucket copy**.
Authenticate the downloaded bytes alone, check the trusted revision, keep
the old local bytes as one generation, and atomically install those exact
downloaded bytes. A retry after interruption must not rotate generations
twice, advance the revision, or upload a replacement during adoption.

## Limits

USB host and NFC are optional Android features. An operator can use either
transport the phone and key support. Use Android's NFC permission and USB
device grant. The vault format, bucket protocol, and Keystore aliases stay
compatible with ADR 0012. BLE, platform passkeys, and new network services
are outside this record.

## Acceptance

- Drive both transports through the production JNI unlock and Keys paths
  with a fake device. Open the fixture with either enrolled key, reject an
  unrelated key before Argon2, exercise different slot sets across candidates,
  and prove cancellation never opens the alternate. Cover enrollment with
  fresh PIN authorization, a duplicate key, the slot limit, removal, and
  removal of the last key.
- Exercise USB permission denial and stale delivery, keyboard-only and
  composite devices, short transfers, detach during I/O, and bounded cancel.
  Exercise NFC selection, chained responses, repeated pending responses,
  early removal, screen lock, and activity recreation. A late callback
  cannot open a vault or commit a key change after cancellation.
- Test failed local writes, offline rekey, interrupted upload, changed
  remote, and restart at the marker and vault writes. Test adoption in both
  directions with one preserved generation. Run the workspace gate, debug
  and release interop fixtures, and Android instrumentation.
- On a disposable vault, enroll on Linux and unlock on the phone. Enroll on
  the phone and unlock on Linux. For each advertised Android transport,
  record a physical enrollment, unlock, cancel, and unplug or early tap
  removal. Use a spare enrolled key to check revocation. Record hardware
  results separately from emulator results.
