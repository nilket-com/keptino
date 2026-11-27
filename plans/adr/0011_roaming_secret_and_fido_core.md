# ADR 0011 — Fold a roaming secret into the key and speak CTAP2 in core

## Status

Accepted.

## Why

Supremacy item S2 of the security review: the pepper binds a vault to the
machines that hold it, but every synced device holds the same pepper, and
an unlock on a compromised host exposes both the master password and the
pepper. A FIDO2 security key with the `hmac-secret` extension keeps its
secret in hardware and needs a touch per use, so a stolen file, password
and pepper still open nothing without the key. The proposal in
`plans/proposals/optional_fido2_security_keys.md` was reviewed by all three
agents and the operator asked for it after the generator work. It spans
core, a new protocol crate, a Linux transport with its screens and two
Android transports; ADR 0004 allows one implementation per decision, so
the team split it (3/3). This decision is the part no user sees: the key
derivation, the key slots in the vault, the CTAP2 protocol and a simulated
security key the tests drive. ADR 0012 adds the Linux transport and
screens, ADR 0013 the Android transports.

## Decision

Key derivation. `core::crypto::derive_master_key` and `derive_master_key_in`
take `roaming: Option<&[u8; 32]>`. With `None` every byte is as today. With
`Some(r)` the pre-hash is unchanged, Argon2id runs with `r` as its secret
input, and the post-hash is SHA3-256 over the domain string
`keptino-roaming-v1`, the Argon2 output, the pepper, `r` and the salt. The
proposal's vector is pinned: password `correct horse battery staple`, salt
of 0x11 bytes, pepper of 0x22 bytes, `r` of 0x33 bytes, cost 4096, 1, 1,
master key `35276f16657b2e7184e8f0575e20a4a462b1f8efc22dff15b19877b7505fe8da`.

Key slots. `core::roaming` defines `KeySlot`: version 1, `uv_mode` 0 or 1,
the credential id of 1 to 256 bytes, a 32-byte salt sent to the key as the
`hmac-secret` salt, a 24-byte nonce and 48 bytes of the roaming secret
sealed with XChaCha20-Poly1305. The sealing key is SHA3-256 over
`keptino-fido2-slot-v1`, `uv_mode`, the salt and the 32-byte `hmac-secret`
output; the associated data is `keptino-fido2-slot-aad-v1`, `uv_mode`, the
credential id and the salt, each variable field behind a two-byte
big-endian length and the version byte first, so the layout is injective. A
slot is one meta entry `fido_slot_1` to `fido_slot_4`, base64, so it rides
inside the mirrored TLV meta set with no format marker and no AAD mode, as
the rules require. `Envelope` exposes the slots in order and refuses a
malformed one as damaged. A vault with slots derives a different master key
from the same vault without them, so a file stripped of its slots opens
with no password, and a slot altered while another still unwraps fails the
mirror check after decryption. `unlock` changes in one way: its derive
closure receives the candidate it is about to open, `Source` and that
copy's slots, not only the salt and cost, and returns the key, a
recoverable failure that keeps today's fallback and upload pause, or a
cancellation that ends the unlock at once. A key is reused for the second
copy only when its salt, cost and slot set are identical to the first,
since two copies with one salt can carry different slots after a backup key
was added or one copy was damaged. Copies with different salts stay
refused; how a rekey with a fresh salt reconciles the copies is for ADR
0012.

Protocol crate. `common/fido` is the workspace crate `keptino-fido`,
`#![forbid(unsafe_code)]`, no I/O. It carries CTAPHID framing (`INIT`,
`CBOR`, `KEEPALIVE`, `CANCEL`, 64-byte packets, channel allocation) and the
NFC APDU framing (`SELECT A0000006472F0001`, `NFCCTAP_MSG` with P1 `0x80`,
`NFCCTAP_GETRESPONSE` after status `0x9100`, and ISO 7816 `61xx` chaining
handled apart from it, as Codex found); a canonical CBOR encoder and
decoder of its own, so no CBOR crate is added; `authenticatorGetInfo`,
`authenticatorClientPin` with `pinUvAuthProtocol` 1 and 2 and scoped
`mc`/`ga` permissions for the relying party `keptino.local` on CTAP 2.1
keys or `getPinToken` on CTAP 2.0 keys, `authenticatorMakeCredential` with
`rk = false` and `hmac-secret`, and `authenticatorGetAssertion` with the
encrypted salt; and two ceremonies, enroll (make the credential, then
assert in the chosen `uv_mode` to wrap the secret) and assert (unwrap one
slot), as state machines a head drives: each step tells the driver what to
do next, write these HID packets, read one packet, transceive this APDU,
ask the user for the PIN, done with the roaming secret, or failed with a
typed reason including cancellation, and the driver can abort while
waiting. A PIN typed on a head reaches the crate through its own wiped
input. A ceremony verifies the assertion's relying party hash, the user
presence flag and the user verification flag against the chosen slot's
`uv_mode` before it accepts the extension output. No vault or registry lock
is held during device I/O or a PIN prompt, every exchange is bounded, and a
canceled ceremony leaves vault and session state as they were; a credential
already made on the hardware is not promised back. The dependencies are the
pure-Rust `p256`, `hkdf`, `hmac`, `sha2`, `aes`, `cbc` and `zeroize`, under
the cooldown. Behind the feature `test-support` the crate offers
`SimulatedAuthenticator`, deterministic, with distinct `credRandomWithUV`
and `credRandomWithoutUV` per credential, that every head's tests drive.

Fixture. A debug-cost vault with two simulated slots, one per `uv_mode`,
joins `android/droid/tests/fixtures` and the erasure parity list. Each head
opens it through its real open path with either simulated key and refuses
an unenrolled key or a flipped `uv_mode` with no Argon2 arena allocated,
which Android shows by counting entries into its arena boundary. A second
case pairs a local and a remote copy of one salt and cost with different
slot sets, and a third cancels on one copy with the other present.

`STYLE.md` gains the term roaming secret.

## Limits

No user-visible change on either head: no transport, no screen, no setup
step, no udev rule. Vaults without slots are byte for byte as today and
every committed fixture still opens. At most four slots; version byte 1;
non-resident credentials only; BLE, browser passkeys and platform
authenticators are out. The rekey and revocation ceremonies are specified
in the proposal and land with the Linux screens in ADR 0012; here the
protocol crate can enroll and assert, nothing more. The core crate's
dependency set does not grow; the protocol crate is linked only where a
head enables security keys, which no head does yet.

## Acceptance

Core: the pinned roaming vector; `None` yields today's key for the existing
vectors; a slot wraps and unwraps; a flipped `uv_mode`, an altered
credential id or an unenrolled key fails the tag with no arena allocated; a
file with its slots stripped does not open with the password, though it may
run the legacy derivation; a file with one slot altered and another valid
fails the mirror check; a fifth slot or a malformed one is damaged;
`unlock` reuses a key only across identical salt, cost and slots, keeps
fallback for a recoverable failure and stops on cancellation. Protocol
crate: transcript tests for CTAPHID and NFC framing including a
multi-packet command, `KEEPALIVE` then read again, `CANCEL`, `61xx` and
`GETRESPONSE`; canonical CBOR round trips and rejection of non-canonical
input; at least one known-answer vector from outside the crate so client
and simulator cannot share a mistake; both PIN protocols against the
simulated key; enrollment and assertion for both `uv_mode` values; a wrong
relying party hash or flag refused; an aborted ceremony leaving no state.
The fixtures open on both heads through their harnesses with either key;
`android/interop/run.sh` passes at the debug cost; `ci/check.sh` is clean
and `cargo audit` shows no C dependency.
