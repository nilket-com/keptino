# Keptino vs KeePassXC: security review

Date: 2026-11-26. Tree reviewed: `main` at 9b1b6cf (Linux) and 115545f (Android, Codex); hashes are those after the 2026-11-26 signed-history rewrite. Reviewers: Claude (Linux, vault format, sync, feature comparison) and Codex (Android app, droid native core). Static review plus the existing Rust suites; no attack reproductions and no file edits. Reference: KeePassXC 2.8.0 (stable 2026-10-21) and the KDBX 4 format.

## Verdict

Keptino's cryptographic core is stronger than KeePassXC's: a 4 GiB Argon2id derivation with a TPM-sealed machine pepper, whole-process memory locking, keys in `memfd_secret`, per-record authenticated encryption of entries in RAM, erasure-coded files, and no browser, auto-type or IPC surface. KeePassXC is ahead in three places that matter: its file header is authenticated, it locks on sleep and session lock, and it carries a mature feature set around the vault (generator, history, deletion, backups). Two items should be fixed now: the sync path's TLS dependencies are behind on advisories, and the vault envelope metadata is unauthenticated, which allows a storage-side rollback. Everything else is small to medium work. With the plan below, Keptino closes every gap that is not a deliberate exclusion and adds controls KeePassXC does not have.

## Where Keptino already exceeds KeePassXC

| Property | KeePassXC 2.8 | Keptino |
| --- | --- | --- |
| KDF | Argon2d/id, default 64 MiB, parameters in header | Argon2id 4 GiB, SHA3 pre/post hashing, plus a 32-byte TPM-sealed pepper never stored in plaintext |
| Second factor | Optional key file or YubiKey HMAC-SHA1 | Mandatory machine-bound pepper (Linux: systemd-creds/TPM; Android: Keystore, StrongBox when present, device credential or strong biometric per use) |
| Memory | Botan locked allocations; Qt memory not lockable; only passwords protected in RAM | `mlockall` over the whole process incl. the KDF arena; keys in `memfd_secret` (outside the kernel direct map, unmapped between uses); every record and secret field sealed under per-object keys with authenticated context |
| Process | `PR_SET_DUMPABLE` 0, no core dumps | Same, plus file capabilities put the loader in secure-execution mode (ignores `LD_PRELOAD` paths and `LD_AUDIT`), refusal to start without memory lock, Wayland-only build |
| Integrity | HMAC detects corruption | Reed-Solomon 8+4 with BLAKE3 per shard repairs corruption |
| Attack surface | Browser native messaging, Auto-Type, SSH agent, Secret Service, passkeys, importers (five of 2.8.0's security fixes were in these) | None of these; one TLS client to the user's own bucket |
| Clipboard | Clear after timeout if unchanged | Clear after timeout, password-manager hint, 60 overwrite passes |
| Android | No KeePassXC Android app | FLAG_SECURE, backup and transfer excluded, MTE sync mode, cleartext traffic off, settings wrapped by per-use authenticated Keystore AES-GCM |

## Findings, ranked

Severity: high / medium / low. Effort: S (hours), M (days), L (a week or more). Platform: Linux, Android, Shared (vault format, both must change together).

### K1. Vault envelope metadata is unauthenticated; rollback by a storage writer. High. Shared. M.
KeePassXC: the KDBX4 outer header is covered by HMAC-SHA256 keyed from the master key and verified before decryption.
Keptino: salt, nonce, `modified_ts`, `created_ts` and `db_name` are plaintext TLV; the AEAD call has empty associated data (`linux/src/storage/persistence.rs:373,392`; `android/droid/src/crypto.rs` encrypt/decrypt). Unlock picks the copy with the larger `modified_ts` (`persistence.rs:132`; `android/droid/src/vault.rs:274-292`).
Risk: anyone who can write the bucket object or the local file replays an older valid vault with a bumped timestamp. It opens cleanly, and the user's next save overwrites the newer copy. Confidentiality is unaffected; integrity and availability of recent edits are.
Fix: a format-2 envelope. Add a `format` meta field and, when present, pass the canonical serialization of the meta entries (sorted name=value pairs, excluding `db`) as AAD. Readers accept format 1 without AAD and format 2 with it; writers always write format 2, so vaults migrate on first save with no key change. Add a monotonically increasing `revision` meta field (authenticated) and store the last-seen `revision` per database outside the synced object (Linux: `~/.config/keptino/<db>.revision`; Android: in the Keystore-wrapped settings). Refuse to open a remote copy whose revision is lower than the last seen without an explicit "accept older copy" confirmation, and refuse to upload over a remote whose revision is not the one loaded (this also closes K12's silent conflict loss). The interop fixtures need a format-2 set alongside the existing format-1 set.

### K2. Linux TLS dependencies carry unpatched advisories. High. Linux. S.
`cargo audit` on `linux/Cargo.lock`: 28 advisories. In the live sync path: rustls 0.23.36 (RUSTSEC-2026-0285, -0349 downgrade of later connections, -0346, -0348), rustls-webpki 0.103.9 (-0382 may accept distrusted intermediates, -0098/-0099 name constraints, -0104 CRL panic, -0049), aws-lc-sys 0.37.0 (-0044 to -0048 X.509 and PKCS7 bypasses, AES-CCM timing), quick-xml 0.38.4 (two parser DoS, parses provider error bodies), time and url (stack exhaustion). The webpki-root-certs advisory does not apply: the Linux target uses the platform verifier with system roots. The quinn advisories are lockfile-only and not linked. `android/droid` has two low warnings and no vulnerabilities.
Risk: every unlock and save does TLS to the provider. A MITM presenting a certificate from a distrusted intermediate could be accepted, exposing the encrypted vault and the provider API credential. The vault stays protected by the KDF; the credential would be lost.
Fix: `cargo update` in `linux/` and `android/droid/` (dry run confirms aws-lc-sys reaches 0.47 via aws-lc-rs 1.19); bump quick-xml to 0.41 in `linux/Cargo.toml` (not reachable by a lock update); rerun the suites; add `cargo audit` and `cargo deny check advisories` to CI and as a non-fatal warning in `setup.sh`.

### K3. Lock does not fire on sleep or session lock, and locking is deferred. Medium. Linux and Android. M.
KeePassXC locks on idle, on `org.freedesktop.ScreenSaver ActiveChanged` (and GNOME/KDE variants), on `org.freedesktop.login1 PrepareForSleep`, optionally on minimize, and on Ctrl+L.
Linux: lock only after 240 s idle (`linux/src/gui/state.rs:49`). Lid close or screen lock leaves the vault open until the timer fires after resume. No manual lock: `Message::Lock` exists but nothing in the UI sends it.
Android: `VaultViewModel.lock()` defers the entire lock while a save or upload is in flight (`VaultViewModel.kt:140-141`), the Lock button is disabled while busy (`MainActivity.kt:286`), and revealed values stay in the rendered model during a slow upload. Keeping the vault open across a brief app switch is deliberate; there is no screen-off or device-lock policy.
Fix, Linux: a zbus subscription producing `Message::Lock` on `PrepareForSleep(true)` and screensaver `ActiveChanged(true)`; a lock button and Ctrl+L. Fix, Android: on lock, immediately clear the UI model and revoke a session generation that pending completions check, let a safe in-flight local commit finish, and offer a lock-on-screen-off option.

### K4. Clipboard clearing has gaps on both platforms. Medium. Linux and Android. S.
Linux: the clear is unconditional, so it also destroys whatever the user copied since and wipes the Primary selection (`state.rs` ClearClipboard); the timer is the Tick subscription, which exists only in the Unlocked state, so copy-then-lock within 20 s leaves the secret on the clipboard until exit.
Android: a manual lock calls `vm.lock()` without clearing Keptino's clip (`MainActivity.kt:286`), and `onDestroy` removes all pending callbacks (`MainActivity.kt:139-142`), so finishing the Activity loses the cleanup.
KeePassXC clears only if the clipboard still holds what it set, and clears its pending clip on lock.
Fix: hash the copied value and skip the wipe when the clipboard differs; run the Linux clear from a detached thread independent of app state; on Android attempt an ownership-checked clear on lock and on finish, keeping the resume retry for background denial. Keep the overwrite passes.

### K5. Linux vault files are created with the process umask. Medium. Linux. S.
`fs::File::create` at `persistence.rs:470` with no mode; on this host `~/.config/keptino/main.keptino` is 0664. The 0700 directory from `setup.sh` is the only protection; a run before setup or a changed umask leaves the vault group or world readable.
Fix: `OpenOptions::mode(0o600).create_new(true)` for the temp file and `DirBuilder::mode(0o700)` in `base_path()`.

### K6. No previous generation survives a save; Android write path has no size or commit check. Medium. Linux and Android. S.
KeePassXC keeps entry history and offers a backup before save. Keptino replaces the only local copy and the only remote object. On Android, reads are capped at 64 MiB with no matching write cap (`VaultStorage.kt:204-216`), `save` clears the dirty state before the local commit is verified and then uploads (`VaultViewModel.kt:121-130`), and `AtomicFile.finishWrite` is not checked.
Fix: keep N rotated local generations (0600) on both platforms before the rename; on Android reject oversized output before replacing anything, keep the dirty state on failure, and verify the local commit before upload or a success message.

### K7. Android holds every entry in plaintext for the whole session. Medium. Android. M.
`android/droid/src/vault.rs:72-76,119,256-260` keeps all serialized entries, including never-viewed passwords, PINs and notes, in wiping vectors on the native heap while unlocked. Linux seals each record and each secret field under per-object keys in secret memory. A native memory disclosure on Android has vault-wide impact.
Fix: port the Linux `ProtectedBytes` and `EntryAtlas` layer to droid with the session key on a `LockedPage`, decrypting one record at a time on access.

### K8. No password generator and no entry deletion. Medium. Linux and Android. S.
KeePassXC has password and passphrase generators, a recycle bin and entry history. Keptino has neither a generator nor any way to remove an entry (the Linux `Message` enum has no delete). Users typing their own passwords is the largest practical weakness of a vault, and a retired or compromised secret can only be overwritten.
Fix: a generator (length, character classes, EFF wordlist passphrases) and a delete action with confirmation, on both platforms.

### K9. Unbounded or shared resource limits on inputs. Medium (Android), low (Linux). M.
Android: the 128 MiB response cap is shared between auth/upload metadata and vault content (`VaultStorage.kt:246-250`); `crypto.rs:135-147` decompresses without an output bound and `atlas.rs:65-72` collects all records eagerly. A bucket writer cannot author an authenticated payload, so this is availability on a valid large vault, not a break. Linux: the download body is read with `.text()` and no size cap (`linux/src/storage/remote.rs:164`) into a locked, non-swappable process.
Fix: small limits for JSON responses, a Content-Length check and hard cap for vault bodies (64 MiB is generous), a decompressed-size and entry budget shared with the writer, and allocation-failure handling.

### K10. KDF parameters are hard-coded and the Android arena wipe is not optimization-resistant. Low. Shared. S.
Argon2id m=2^22, t=1, p=1 is a constant (`persistence.rs:274-278`; `crypto.rs`); a debug build uses 2^12 and writes vaults a release build cannot read with no distinguishing error. Parameters can never change without breaking every vault. `crypto.rs:38-54` clears the 4 GiB arena with ordinary assignments.
Fix: write `kdf_m`, `kdf_t`, `kdf_p` meta fields (authenticated by K1), defaulting to today's constants when absent, with an explicit rekey path; use `zeroize` on the arena on every exit.

### K11. Secret lifetimes outside the protected layer. Low. Linux and Android. S to M.
Linux: `systemd-creds` and `lsblk` are found by PATH lookup and the app aborts if missing (`security.rs:90`, `persistence.rs:248`, `remote.rs:65`); the pepper and the provider secret cross a pipe into a child whose memory is neither locked nor undumpable on every unlock and save.
Android: settings pass through immutable JVM strings including the pepper (`VaultStorage.kt:116-118,163-166`); decrypted pepper and password bytes persist across the network download and cloud credentials persist on a local-only unlock (`VaultViewModel.kt:67-85`).
Fix: absolute paths and a warning rather than abort for `lsblk`; decrypt the provider credential once per session into `SecretMemory`; on Android a wipeable settings encoding and narrower lifetimes for pepper versus sync material.

### K12. Sync has no conflict detection beyond newer-timestamp-wins. Low. Shared. Covered by K1's revision field.
Two devices editing offline silently lose one side. KeePassXC merges. With K1's `revision` and parent check, Keptino refuses the overwrite and offers keep-local or take-remote; a full merge is not needed.

### K13. Minor Linux items. Low. S.
`force_secure_display` rewrites `WAYLAND_DISPLAY` to `wayland-0` (`security.rs:52`), breaking a second compositor socket for no gain since the build is Wayland-only; drop it. `cargo install cargo-deb --locked` in `setup.sh` fetches an unpinned version at setup time; pin it. Widget-owned plaintext in iced text inputs and the shaping cache is the same class of issue KeePassXC has with Qt; mitigated by memory locking and non-dumpability; not a priority.

## Features KeePassXC has that Keptino lacks

| Feature | Recommendation |
| --- | --- |
| Password and passphrase generator | Add (K8) |
| Entry deletion, history, recycle bin | Add delete now (K8); history later with K6 generations |
| Backup before save | Add (K6) |
| Lock on sleep and session lock, manual lock | Add (K3) |
| Password health and reuse report | Done in ADR 0009: offline report of reused, weak, stale and empty passwords on both heads |
| Have I Been Pwned check | Deliberate exclusion: it adds a third-party endpoint to an app that otherwise talks only to the user's bucket. Offline-only option at most |
| TOTP | Optional, M. It stores the second factor next to the first; leave out unless requested |
| Key file and YubiKey HMAC-SHA1 | The TPM pepper is a stronger mandatory equivalent locally but not roaming. See supremacy item S2 |
| Browser integration, Auto-Type, SSH agent, Secret Service, passkeys | Deliberate exclusion. Document it as a design principle in the README |
| Quick Unlock (Polkit on Linux) | Deliberate for Linux: it keeps a derived key alive across locks. Android already gates on device credential or biometric per use |
| Database merge | Not needed once K1's revision check refuses silent overwrites |

## Supremacy items (controls KeePassXC does not have)

- S1. Sandbox the Linux process: Landlock restricting the filesystem to `~/.config/keptino` read-write, `/usr` read-only and `/run/user/<uid>` for Wayland; `PR_SET_NO_NEW_PRIVS`; a seccomp allowlist after preflight. KeePassXC cannot do this because its integrations need broad access. M for Landlock, L for seccomp.
- S2. FIDO2 `hmac-secret` as an optional roaming factor folded into the KDF input, usable on both platforms. KeePassXC supports only YubiKey HMAC-SHA1 via the OTP slot. L.
- S3. Rollback-resistant sync via K1's authenticated revision and a locally trusted last-seen revision. No KeePassXC equivalent.
- S4. Per-record authenticated encryption in RAM on Android (K7), matching Linux.
- S5. Supply-chain gate in CI (K2), signed release tags, and a reproducible Debian build.
- Already in place: 4 GiB KDF with TPM pepper, `memfd_secret` keys, whole-process memory lock, erasure coding, no IPC surface.

## Prioritized plan

Phase 1, this week, all S:
1. K2 dependency update, quick-xml bump, `cargo audit` in CI and setup. Claude.
2. K5 file mode 0600 and directory 0700. Claude.
3. K4 clipboard: conditional clear and state-independent timer on Linux; clear on lock and finish on Android. Claude and Codex.
4. K3 part one: manual lock on Linux; immediate UI revocation and session generation on Android. Claude and Codex.
5. K6 Android part: write cap, commit verification, dirty state preserved. Codex.

Phase 2, next, M:
6. K1 format 2 with AAD and revision, trusted last-seen revision, refuse-and-choose on conflict, format-2 interop fixtures. Joint, one release: Claude in `persistence.rs`, Codex in `vault.rs`/`crypto.rs` and settings.
7. K3 part two: D-Bus lock on sleep and session lock (Linux); lock-on-screen-off option (Android).
8. K6 local backup generations on both platforms.
9. K8 generator and delete on both platforms.

Phase 3, M to L:
10. K7 droid memory layer.
11. K9 bounded decoding and limits.
12. K10 KDF parameters in the file; arena wipe.
13. K11 secret lifetimes; K13 minor items.

Supremacy track: S1 Landlock then seccomp; S2 FIDO2; README design-principles section listing the deliberate exclusions and the reasons.

## Appendix: cargo audit, linux/Cargo.lock, 2026-11-26

Vulnerabilities in linked crates: rustls 0.23.36 (RUSTSEC-2026-0285, -0346, -0348, -0349; patched 0.23.46), rustls-webpki 0.103.9 (-0049, -0098, -0099, -0104, -0382; patched 0.103.16), aws-lc-sys 0.37.0 (-0044, -0045, -0046, -0047, -0048; patched 0.39), quick-xml 0.38.4 (-0194, -0195; patched 0.41, manifest bump), time 0.3.44 (-0009; patched 0.3.47), url 2.5.8 (-0592; patched 2.5.9). Lockfile-only, not linked for this target: quinn-proto 0.11.13 (10 advisories), quinn-udp 0.5.14 (-0538), webpki-root-certs 1.0.6 (-0383). Warnings: 18, none in the crypto path. `android/droid/Cargo.lock`: instant unmaintained, lru 0.7.8 unsound; no vulnerabilities.

## Shared core, 2026-11-26 night

ADR 0001 unified the Cargo workspace and erasure crate. ADR 0002 shared the
vault format, cryptography and sync policy. ADR 0003 moved record and
secret-field sealing into `common/core::vault`. Its `KeyStore` uses
`memfd_secret` on Linux and `Mutex<LockedPage>` on Android, closing K7. All platform
duplicates of the atlas, envelope, Argon2 derivation, AEAD, LZ4, erasure
framing and in-memory vault store are deleted. Every committed fixture is
parsed and repaired byte for byte by core's tests, the debug fixtures are
decrypted end to end with the fixture pepper, and the release fixtures by an
ignored 4 GiB test both agents ran. ADR 0005 shared the remaining unlock
orchestration across both heads.

## Status, 2026-11-26 evening

All on `main`:

| Finding | State |
| --- | --- |
| K1 envelope authentication and revision | Reopened on the user's observation and settled as the mirrored-TLV design: the plaintext meta set must equal the authenticated inner copy after decryption, which protects every existing vault with no re-save and no new format, and lets `revision` and `kdf_*` ride as ordinary TLV fields that older readers preserve. The marked AAD files written on 2026-11-26 still open and convert on save. Both readers landed and both writers now emit the unmarked mirrored form (flipped together); the marked AAD fixtures stay as regression tests. Upload guard uses the remote object fingerprint seen at unlock. A legacy copy counts as revision 0 against a trusted revision. |
| K2 dependencies | Updated; seven-day cooldown in `.cargo/config.toml`; `cargo audit` in setup; zero vulnerabilities. Of the eight unmaintained/unsound warnings, two left with iced's unused `highlighter` feature (syntect) and one with chrono (replaced by jiff); reed-solomon-erasure and its instant and lru dependencies left when the Reed-Solomon code moved in-tree (`common/erasure/`, no dependencies, parity proven byte-identical against the old crate and every committed fixture); the two under iced's text and SVG stack, plus a lockfile-only lru listing, are accepted with reasons in `.cargo/audit.toml` until iced moves |
| K3 lock | Lock button, Ctrl+L, logind and screensaver D-Bus listener on Linux (verified by Codex on a private bus); immediate session revocation on Android |
| K4 clipboard | Conditional, state-independent wipe on Linux; cleared on lock and finish on Android |
| K5 file mode | 0600 files, 0700 directory |
| K6 generations | Three previous saves kept as `.keptino.1` to `.3` on Linux; bounded and verified atomic writes on Android |
| K7 Android memory layer | Closed in ADR 0003: `common/core::vault` seals every record under an atlas key and secret fields under per-entry keys on both heads (`SecretMemory` on Linux, `Mutex<LockedPage>` on Android), verified by `an_opened_store_holds_only_ciphertext` and API 37 device checks |
| K8 generator and delete | Both heads use the shared password generator and confirm deletion before Save (ADR 0007); ADR 0008 added character classes, length and EFF passphrases with the entropy shown |
| K9 limits | Closed in ADR 0006: `common/core::format` enforces shared reader and writer budgets (64 MiB vault file, 30 MiB decompressed database, 100 000 records, 16 MiB record or field) with bounded decompression and pre-allocation checks; Linux bounds local reads to the file budget alongside the 64 MiB remote cap; Android separates metadata and vault response caps with a `Content-Length` check against the file budget |
| K10 KDF parameters | `kdf_m`, `kdf_t`, `kdf_p` written and honored across both heads; Argon2 arena wiped with `zeroize` on every exit |
| K11 lifetimes | Absolute tool paths, clean error for a missing pepper, provider credential kept in secret memory for the session on Linux |
| K13 minor | WAYLAND_DISPLAY only defaulted, lsblk optional, cargo-deb pinned, unused dependency dropped |
| S1 Landlock | Done; Codex confirmed live Wayland rendering and lock events under the sandbox |
| Commit hygiene | ket's commit preflight and hooks adopted; full history re-signed |

Android (Codex): K1, K2, K3 (session revocation), K4, K6 (bounded and verified writes), K7 (sealed in-memory vault via `common/core::vault`), K9 (shared core budgets plus separate metadata and vault response caps), K10, and the Keystore-backed rollback guard are on `main`; interop harness runs against both heads.

Open: S2 FIDO2 security keys: the roaming secret in the key derivation, the key slots and the CTAP2 protocol crate landed in ADR 0011, the Linux USB HID transport, unlock and keys screen in ADR 0012 (design in `plans/proposals/optional_fido2_security_keys.md`); the Android transports are ADR 0013, and until then Android opens a vault with key slots only in its tests. A custom S3 endpoint (`plans/proposals/custom_s3_sync.md`) is ADR 0014. TOTP stays out unless asked.

## Status update, 2026-11-28 (post-ADR 0022)

Superseding the 2026-11-26 evening `Open:` note above (TOTP remains out unless asked), the remaining planned security and core items landed on `main` (`948d832`):

| Item | State |
| --- | --- |
| S2 FIDO2 security keys | Landed across both heads: roaming secret KDF, key slots (`fido_slot_1..4`), and pure-Rust `#![forbid(unsafe_code)]` CTAP2 in ADR 0011; Linux USB HID transport and Keys screen in ADR 0012 (verified on a physical YubiKey); Android USB HID and NFC `IsoDep` transports in ADR 0013 (NFC is fixture-tested only; physical Android USB enrollment still needs live-device verification). |
| Custom S3 and Cloudflare R2 sync | Pure-Rust `#![forbid(unsafe_code)]` SigV4 signer and `"s3"` provider with `If-Match`/`If-None-Match` strong-ETag preconditions landed in ADR 0014 (removed `aws-sigv4`, `aws-credential-types`, and `quick-xml` from the S3 path); Cloudflare R2 and `BuildConfig.DEBUG`-gated USB/ADB provisioning landed on Android in ADR 0015. |
| Single shared core and explicit creation | `common/libkeptino` unified the core, erasure, FIDO2, and S3 code into one crate with default-off features (ADR 0016). Explicit Create vault landed on Android (ADR 0017) and Linux (ADR 0018) so Unlock never silently creates a vault. |
| Nautilus UI and list projection | Shared visual language in `doc/design.md`, Linux Nautilus + floating Find/Generator popovers (ADR 0019, ADR 0022), and Android four-screen Nautilus layout (ADR 0020, ADR 0021). List rendering and filtering use an opt-in non-secret list projection (`INDEX_LIST_ROWS`) and open no sealed records. |

## Honest assessment, 2026-11-28 (Claude, Codex, Gemini)

> **Self-assessment caveat**: This review and the findings table above were written by the project's three coding agents and its operator about their own code. No independent third party has audited or attacked Keptino yet.

### Short version

On **design**, Keptino is stronger than KeePassXC's defaults against specific threat scenarios such as bucket or disk theft, broad desktop integration attack surface, plaintext in RAM, silent rollback, and storage corruption. On **assurance**, KeePassXC is far ahead — and assurance is most of what security means in practice. For the operator's own Linux, Android, and R2 setup, Keptino's design is a reasonable choice; for a new user who cannot read the code or re-run the checks, KeePassXC still earns more trust today.

### Where Keptino is ahead on design

- **Stolen vault files are not enough**: A copy stolen from the bucket, a backup, or a disk cannot be brute-forced with the master password alone; it also requires the 32-byte pepper (recoverable or provisioned across devices, with its stored copy protected by the Linux TPM via `systemd-creds` or Android Keystore/StrongBox with per-use credential or biometric), plus any enrolled FIDO2 `hmac-secret` security key. KeePassXC's default `.kdbx` relies on the master password alone (64 MiB Argon2 default), though KeePassXC can also add an independent key file or YubiKey HMAC-SHA1 slot.
- **Minimal attack surface and sandboxing**: No browser native messaging, Auto-Type, SSH agent, Secret Service, passkeys, or third-party importers — the areas where many KeePassXC security fixes land. Linux is Wayland-only and applies a Landlock sandbox on supported kernels; network traffic is limited to configured sync and provider authentication over one TLS client, with pure-Rust `#![forbid(unsafe_code)]` parsers in `libkeptino`.
- **Memory isolation on both heads**: Whole-process `mlockall` and `memfd_secret` keys (outside the kernel direct map, unmapped between uses) on Linux; best-effort `LockedPage` keys on Android (where the KDF arena may be swapped); per-record and per-secret-field AEAD sealing in RAM on both heads; and list/filter views that never open sealed records. Revealing or copying still exposes plaintext while in use, and an attacker controlling the running process can read secrets as they are used.
- **Rollback and corruption resistance**: Authenticated mirrored-TLV metadata, monotonic `revision` checked against a locally trusted last-seen revision, S3/R2 strong-ETag preconditions (`If-Match`/`If-None-Match`), and Reed-Solomon 8+4 with per-shard BLAKE3 repair.

### Where KeePassXC is ahead (and why it matters more)

- **Independent scrutiny**: KeePassXC has years of public use, external source review (2.7.4), and ANSSI certification (2.7.9 on Windows 10; see [KeePassXC audits](https://keepassxc.org/audits/)). Keptino's internal reviews caught real bugs at almost every ADR — evidence that the process works, and also evidence that there are bugs to find when outside eyes have not yet tried to break it.
- **Custom format and key composition**: Keptino's primitives are standard (Argon2id, XChaCha20-Poly1305, AES-256-GCM, BLAKE3, SHA-3), but their composition — mirrored-metadata envelope, per-record sealing, pepper folding, and roaming key slots — is bespoke. Real-world password-manager breaks usually happen in composition and parsing, not in the ciphers.
- **Lockout and recovery risk**: Losing both the machine and the pepper recovery seed, or every enrolled security key, permanently destroys access to the vault. The pepper recovery seed itself must be strong and stored separately. KeePassXC's failure modes are simpler.
- **Bus factor and provenance**: Mostly agent-written code maintained by one operator. Fine for an author who inspects and tests it, harder to recommend broadly.

### Concrete next security priorities

1. **Release-signed, non-debuggable Android everyday build**: `android/setup.sh` currently builds `:app:assembleDebug` and installs `app-debug.apk` with `android:debuggable="true"` in the packaged manifest. While normal unlocks still use production KDF cost, `debuggable="true"` exposes the running app over an authorized debugging connection (and enables `BuildConfig.DEBUG` paths). Move everyday phone installs to a release-signed, non-debuggable build while preserving existing vaults and Keystore-wrapped settings across the signing transition. (Reference: [Android `debuggable` guidance](https://developer.android.com/privacy-and-security/risks/android-debuggable).)
2. **Fuzzing and independent review**: Add `cargo-fuzz` targets on `libkeptino`'s untrusted-input boundaries (format/envelope reader, TLV parser, Reed-Solomon decoder, CTAP2/CBOR parser, and S3 response handling — the error-body scan and the ETag and header parsing), followed by an external review of the format and key handling by someone who did not write them.
3. **Physical Android FIDO2 verification and recovery drills**: Verify Android USB HID and NFC FIDO2 on real hardware, and practice the full recovery paths on a throwaway vault (restoring from the pepper seed, adopting a bucket copy, and recovering after losing one security key).
4. **Signed, reproducible releases and Linux seccomp**: Add a seccomp allowlist after Linux preflight (the second half of S1 alongside Landlock), and publish signed, reproducible release artifacts.
5. **Default KDF cost vs phone availability (planned ADR 0024)**: Lower the default Argon2id cost for *new* vaults (e.g., 256 MiB, `t=3, p=1`) to reduce peak allocation so constrained phones are far less likely to OOM on creation or unlock, while keeping existing 4 GiB vaults, the default for vaults without a recorded cost, and `derive_pepper` untouched. This trades a modest per-guess memory cost, which matters only once the pepper or its recovery seed is also stolen, for vaults that open reliably on constrained phones.

## Hardening sprint update, 2026-11-28 (post-ADR 0034)

Superseding the open priorities above with what shipped on `main` across ADRs 0024 through 0034:

| Item | State |
| --- | --- |
| Default KDF cost for new vaults (ADR 0024, ADR 0025) | Shipped on both heads: `KdfParams::CREATE` (`256 MiB, t=3, p=1`) for explicit Create on Linux and Android; the release default for vaults without a recorded cost (`4 GiB, t=1, p=1`), existing recorded vault costs on ordinary `Save`, and `derive_pepper` (`4 GiB, t=4`) stay untouched. API 37 emulator warm create/reopen measured 3.11 s / 2.93 s at 449–450 MiB peak RSS. |
| `libkeptino` fuzzing (ADR 0026) | Shipped: 9 targets (`shards`, `envelope`, `payload`, `slot`, `s3`, `cbor`, `ctap`, `hid`, `nfc`) with round-trip invariants, a deterministic 400-mutation-per-seed smoke test in `cargo test`, and a stable coverage-guided `libFuzzer` runner (`common/libkeptino/fuzz/run.sh`; 25M initial runs, zero findings). |
| Release-signed, non-debuggable Android everyday install (ADR 0027, ADR 0030) | Shipped: `android/setup.sh` defaults to `:app:assembleRelease` (`isDebuggable = false`), verifies release cert pins and two-step v3 signer rotation (`android/install-release.py`) retiring the old signer's permission capability, enforces one explicit Android user profile (`--user ID` or `am get-current-user`) across discovery, install, verification, and debug R2 provisioning, and puts `$JAVA_HOME/bin` first on `PATH` for `apksigner`. Multi-user, rotation, and interrupted-migration rehearsals verified on API 37; signer rotation and ordinary release verification confirmed on the operator's Samsung. |
| Linux system call filter — S1 completion (ADR 0028, ADR 0029) | Shipped: hand-built cBPF seccomp deny filter (`linux/src/seccomp.rs`) installed with `PR_SET_NO_NEW_PRIVS` + `TSYNC` after preflight (foreign arch / x32 `SIGSYS`, ~55 denied syscalls `EPERM`, `clone3` `ENOSYS` + namespace `clone` `EPERM`), cross-target compile checks across `x86_64`/`aarch64` × `gnu`/`musl` (`linux/seccomp-targets.sh`), and degraded preflight reporting. A strict syscall allowlist remains open and requires a separate vault-worker process. |
| Reproducible Linux `.deb` build (ADR 0031, ADR 0034) | Shipped: `linux/build-deb.sh` (`SOURCE_DATE_EPOCH`, `--remap-path-prefix`, `BUILDINFO`, `SHA256SUMS`, optional SSH signing via `--sign KEY`, and full `git status --porcelain` dirty provenance including untracked files) plus `linux/repro-check.sh` verifying byte-identical packages with zero builder-path leaks. |
| Android lock-on-screen-off — K3 completion (ADR 0032) | Shipped: `ACTION_SCREEN_OFF` (`RECEIVER_NOT_EXPORTED`, enabled by default) plus `onResume()` display/keyguard check immediately locks open vaults, cancels prompts, clears Keptino's clipboard, resets Compose state, and clears stale idle deadlines. Verified end to end on API 37. |
| Automated recovery drills (ADR 0033) | Shipped: `cargo test -p keptino drill` (`linux/src/storage/drill.rs`, lost daily FIDO2 key → backup unlock → rekey/revoke → enroll replacement) and `linux/recovery-drill.sh` (five live RustFS + `keptino --derive-pepper` disaster cases, including fail-closed corrupt local file recovery). |

### Still open

1. **Independent third-party security review** of the vault format, key composition, and parsers (still the single largest assurance gap versus KeePassXC).
2. **Physical Android hardware FIDO2 verification** (live USB HID and NFC key enrollment on a physical phone).
3. **Published signed releases** (creating and publishing `allowed_signers` and signed release artifacts using ADR 0031's `--sign` workflow).
4. **Optional vault-worker split on Linux** if a strict seccomp allowlist (beyond ADR 0028's deny filter) is ever desired.
