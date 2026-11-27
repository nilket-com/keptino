# Proposal — Optional FIDO2 hmac-secret security keys folded into key derivation

Status: proposed (2026-11-26 UTC). Supremacy item S2 from the KeePassXC
security review (`doc/security-review-vs-keepassxc-2026-11-26.md`): Keptino's
machine-bound pepper defeats theft of a vault file from the storage bucket,
but every device that syncs the vault holds the same pepper and an unlock on a
compromised host exposes both the master password and the decrypted pepper.
KeePassXC offers only YubiKey HMAC-SHA1 over a legacy OTP slot, where two keys
must share a user-programmed static secret and Android support depends on
third-party helpers. This record adds FIDO2 `hmac-secret` security keys across
Linux and Android with multi-key enrollment, explicit user-verification state
binding, fast rejection before the 4 GiB Argon2id arena, no format marker, no
C library, and no Play Services or HTTPS relying-party domain.

## Why
- A security key keeps its credential secret inside its secure element and
  requires physical touch (and authenticator PIN or biometric when requested)
  per unlock. An attacker who captures the bucket vault, the master password
  and the machine pepper still cannot unlock a vault on another host or after
  a rekey without an enrolled physical security key.
- FIDO2 `hmac-secret` generates device-internal secrets during
  `authenticatorMakeCredential`; two security keys cannot share an internal
  key. Feeding one authenticator's raw `hmac-secret` output directly into
  Argon2id would prevent enrolling a backup security key without duplicating
  the vault file. Indirection through a slot-wrapped 32-byte roaming secret
  lets one vault enroll up to four security keys (for example, a daily key and
  a backup key in storage).
- CTAP 2.1 authenticators maintain two distinct internal secrets per
  credential (`credRandomWithUV` and `credRandomWithoutUV`) and select between
  them based on whether user verification was performed on `getAssertion`. A
  slot wrapped after a PIN-verified assertion will not unwrap under a
  touch-only assertion, and vice versa; each key slot must record and request
  its exact user-verification mode.
- Android's `CredentialManager` and WebAuthn `prf` APIs require Google Play
  Services and an HTTPS `rpId` domain serving `.well-known/assetlinks.json`.
  Both violate Keptino's rule that the vault talks only to the user's storage
  bucket, fail on de-Googled Android (GrapheneOS, AOSP), and pass derived
  bytes through Binder IPC and JVM strings. Direct CTAP2 over USB HID and NFC
  `IsoDep` needs neither Play Services nor any domain.

## Decision
1. **Slot-wrapped 32-byte roaming secret and UV binding.** When security-key
   protection is enabled on a vault (or rotated), Keptino generates a random
   32-byte roaming secret `R`. Enrolling a security key runs
   `authenticatorMakeCredential` (`rk = false`, `extensions = {"hmac-secret":
   true}`, relying party id `"keptino.local"` — CTAP2-only; any future browser
   or platform path would require its own relying party), defaults `uv_mode`
   to `1` when `clientPin` or built-in `uv` is configured (`0` when neither is
   configured, while letting the user explicitly choose touch-only `0` on a
   PIN-capable key that permits `hmac-secret` without UV), and immediately
   performs an `authenticatorGetAssertion` in that chosen `uv_mode` to wrap
   `R`. Each enrolled key occupies one key slot (`fido_slot_1` through
   `fido_slot_4`), serialized as base64 of:
   - `version`: `u8` (`0x01`),
   - `uv_mode`: `u8` (`0` = touch-only without UV; `1` = UV required via
     `pinUvAuthParam` or built-in `uv`),
   - `cred_id_len`: `u16` LE (`1..=256`), followed by `cred_id`,
   - `salt`: 32 random bytes passed as `hmac-secret` `salt1`,
   - `nonce`: 24 random bytes,
   - `wrapped`: 48 bytes (`R` encrypted and authenticated under
     XChaCha20-Poly1305 keyed by
     `SHA3-256(b"keptino-fido2-slot-v1" || [uv_mode] || salt || H)`, with
     associated data
     `b"keptino-fido2-slot-aad-v1" || [uv_mode] || cred_id || salt`, where `H`
     is the 32-byte `hmac-secret` output).

   At unlock, the reader requests the recorded `uv_mode` verbatim and never
   guesses. Touching an unenrolled key or mismatched UV state fails the
   16-byte Poly1305 tag in milliseconds before Keptino allocates the 4 GiB
   Argon2id arena, revealing nothing about the master password or pepper.
2. **Envelope representation, recovery, and atomic commit.** Key slots ride as
   ordinary TLV meta entries (`fido_slot_1`..`fido_slot_4`) with no `format`
   marker and no AAD mode.
   - A vault with key slots derives a different master key than the same vault
     without them, so stripping every `fido_slot_*` entry from the plaintext
     envelope leaves a ciphertext that no password can open.
   - Altering, adding or dropping one slot while another slot unwraps `R`
     fails the envelope mirror check after decryption.
   - **Adding a backup key** while unlocked touches only the new security key,
     wraps the existing `R` into a new slot, and advances `revision`.
   - **Revoking a lost key or disabling security-key protection** requires an
     unlocked session and an explicit rekey (fresh vault `salt`, fresh `R`
     when slots remain, re-derived master key), advancing `revision` and
     tripping the trusted-revision guard on every other synced device. Because
     a fresh `R` cannot be wrapped for an absent authenticator, rekey wraps
     `R` for every surviving security key the user touches during the ceremony
     and drops any untouchable slot after explicit confirmation (an offsite
     backup key dropped during emergency revocation is re-enrolled when next
     in hand). Earlier local `.keptino.N` generations remain encrypted under
     their original keys until rotated out. If every enrolled security key is
     lost while the vault is locked, the vault cannot be opened; there is no
     recovery bypass.
   - **Interrupted ceremonies.** User cancellation, USB detach, an NFC tap
     ending early or process death aborts in memory without mutating the
     session's master key or slots; enrollment, removal or rekey takes effect
     only when the complete local atomic vault save commits.
   - Ordinary saves while unlocked reuse the session's master key and preserve
     existing `fido_slot_*` entries without prompting for a repeat touch.
3. **Key derivation with `R` in `common/core`.** `common/core::crypto` keeps
   its existing five-crate dependency set and adds `KeySlot` wrap/unwrap plus
   `roaming: Option<&[u8; 32]>` on master-key derivation:
   - `None`: unchanged byte for byte.
   - `Some(r)`:
     - `pre_hash = SHA3-256(salt || pepper || password)` (unchanged; fixed
       32-byte `salt` and `pepper`, variable `password` last),
     - `Argon2::new_with_secret(r, Algorithm::Argon2id, Version::V0x13,
       params)` over `(pre_hash, salt || pepper)` (`r` keys the initial
       Blake2b block per RFC 9106 while keeping the 64-byte salt within
       Argon2's 64-byte bound),
     - `post_hash = SHA3-256(b"keptino-roaming-v1" || main_hash || pepper || r
       || salt)`.
   - Pinned test vector (`password = b"correct horse battery staple"`,
     `salt = [0x11; 32]`, `pepper = [0x22; 32]`, `r = [0x33; 32]`,
     `m_cost = 4096`, `t_cost = 1`, `p_cost = 1`):
     - `pre_hash`  = `d21ff2ec49aa0c6ae7fe125bc14de0fcf01be0cb0b2117107fabf5a89298b8be`
     - `main_hash` = `343980216b04e59eb6f487ae58253ea818fafeb32fa7922bf43f024ac5c49a54`
     - `master`    = `35276f16657b2e7184e8f0575e20a4a462b1f8efc22dff15b19877b7505fe8da`
4. **Separate `common/fido` crate (`keptino-fido`), `#![forbid(unsafe_code)]`.**
   CTAP2 lives in its own workspace crate beside `common/core` so `core` stays
   small and cryptographic dependencies (`p256`, `hkdf`, `hmac`, `sha2`,
   `aes`, `cbc`) enter only heads that enable security keys. `common/fido`
   performs no I/O and provides:
   - CTAPHID 64-byte packet framing (`INIT`, `CBOR`, `KEEPALIVE`, `CANCEL`)
     and ISO 7816-4 NFC APDU framing (`SELECT A0000006472F0001`,
     `NFCCTAP_MSG 80 10 00 00`, `NFCCTAP_GETRESPONSE 80 11 00 00`);
   - deterministic canonical CBOR for `authenticatorGetInfo`,
     `authenticatorClientPin`, `authenticatorMakeCredential` and
     `authenticatorGetAssertion`;
   - `pinUvAuthProtocol` 1 and 2, requesting scoped `mc`/`ga` permissions for
     `"keptino.local"` on CTAP 2.1 keys and `getPinToken` on CTAP 2.0 keys;
   - a pure-Rust deterministic `SimulatedAuthenticator` (holding distinct
     `credRandomWithUV` and `credRandomWithoutUV` secrets per credential)
     exposed behind a `test-support` feature so `common/core`, `linux`,
     `android/droid` and `android/interop` drive identical fixtures.
5. **Thin transport adapters in the heads.**
   - **Linux (`linux/`)**: enumerates `/sys/class/hidraw` and opens
     `/dev/hidraw*` devices whose HID report descriptor declares FIDO usage
     page `0xF1D0`, usage `0x01` (both `/sys` read and `/dev` read/write are
     already permitted by `security.rs`'s Landlock ruleset); `linux/setup.sh`
     checks `systemd-udev` (`70-u2f.rules`).
   - **Android (`android/`)**: wired USB-C claims the HID `UsbInterface` with
     `claimInterface(intf, true)`, verifies FIDO usage page `0xF1D0` via a
     report-descriptor `controlTransfer` (`0x81, 0x06, 0x2200`), and exchanges
     64-byte packets on the `USB_ENDPOINT_XFER_INT` IN and OUT endpoints via
     `UsbDeviceConnection.bulkTransfer` (supported on interrupt endpoints on
     API 30+); NFC uses `NfcAdapter.enableReaderMode` with `IsoDep`. Kotlin
     passes only raw 64-byte HID packets or raw APDU frames across JNI; ECDH
     secrets, PIN tokens, `H` and `R` remain in Rust secret memory.
6. **Proposed implementation order.** Scope each numbered decision when its
   implementation is ready. NFC can have its own decision if Android
   reader-mode lifecycle work warrants it.
   1. `common/core` roaming KDF extension, `KeySlot` codec/wrap/unwrap,
      pinned vector test, and stripped/altered slot tests.
   2. `common/fido` (`keptino-fido`) CTAP2 state machines, framing codecs,
      `pinUvAuthProtocol` 1 and 2, and `SimulatedAuthenticator` transcript
      suite (including flipped-`uv_mode` rejection).
   3. Linux `/dev/hidraw*` adapter, setup check, and enrollment/unlock UI.
   4. Android USB-C HID (and NFC `IsoDep`, unless split) adapter, JNI bridge,
      UI, and cross-platform FIDO fixture in `android/interop/run.sh`.

## Limits
- Optional per vault; vaults without `fido_slot_*` behave identically to
  today. Maximum four key slots per vault.
- Non-resident (`rk = false`) credentials only; BLE authenticators, WebAuthn
  browser passkeys and platform authenticators are out of scope.
- The core work depends on ADR 0002. The platform adapters depend on the
  sealed vault model in ADR 0003.

## Acceptance
- `common/core` matches the pinned roaming KDF vector and rejects tampered or
  stripped `fido_slot_*` entries before opening a vault.
- `common/fido` transcript tests pass for CTAPHID and NFC APDU framing,
  `pinUvAuthProtocol` 1 and 2, multi-key enrollment, key revocation rekey,
  interrupted/aborted ceremonies leaving state unchanged, and fast Poly1305
  rejection when `uv_mode` is flipped between `0` and `1` or an unenrolled
  authenticator responds.
- A committed debug fixture with two `SimulatedAuthenticator` key slots opens
  with either key on both Linux and Android without allocating the Argon2
  arena on a wrong key; `ci/check.sh` and `cargo audit` pass with zero C
  dependencies.
- Before any transport (Linux USB HID, Android USB-C HID, Android NFC
  `IsoDep`) is documented as supported, at least one end-to-end physical
  security-key test passes on that transport, covering enrollment, unlock,
  cancellation, and mid-operation disconnect or early tap removal.
