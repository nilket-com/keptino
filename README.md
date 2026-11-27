# Keptino

A password vault by nilket for Linux and Android.

Keptino was previously named DigiSafe. On Linux, launch it with `keptino`. The
Debian package replaces `digisafe` and keeps the old command working. If you
pinned DigiSafe to your dock, remove the old pin and pin Keptino after upgrading.
Run `./linux/setup.sh` before opening Keptino. If
`~/.config/keptino` is absent, setup moves `~/.config/digisafe` there with its
cloud credentials. It renames vaults to `.keptino` and re-wraps the TPM-sealed
pepper under its new credential name without writing the plaintext to disk.
If both directories exist, setup leaves the old directory in place. The
original pepper seed and master password still open the vault.

### Android

Connect your phone, authorize USB debugging, and run `./android/setup.sh` to
build and install Keptino or update it in place. The Android app opens and edits
Linux `.keptino` vaults. See
[Android setup, builds, and interoperability tests](android/README.md). Existing
vaults require the original pepper and a device with enough available memory for
the Linux 4 GiB password derivation. The platform protections below describe Linux;
Android uses Android Keystore and the lifecycle protections documented separately.

### Linux features

 - 4GiB Argon2id / Sha3 salted and peppered master password derivation.
 - TPM locked pepper via systemd-creds.
 - Secret memory based master key storage.
 - Authenticated in-memory encryption of cached entries, passwords, PINs, and notes.
 - The entire app is unswappable and undumpable.
 - Landlock filesystem sandbox: the process and the helpers it spawns can reach only system files, devices, the runtime directory, the font cache and `~/.config/keptino`; the rest of the home directory is unreachable. A kernel without Landlock runs unconfined and says so in the journal.
 - Dynamic linker hijacking blockage.
 - Tracing blockage. (ptrace, strace, ltrace, gdb)
 - Forensic-resistant clipboard clearing mechanism that only wipes what Keptino copied.
 - Lock button and Ctrl+L; idle lock after four minutes; locks when the session locks or the machine sleeps (logind and screensaver D-Bus signals).
 - Uniform 24-character password generator; entries are deleted on a confirming second press.
 - Linux vault sync on unlock and save with Backblaze B2, Amazon S3, Google Cloud Storage, or Cloudflare R2. API credentials use systemd-creds.
 - Atomic file io, with the three previous saves kept as `<db>.keptino.1` to `.3` for recovery.
 - Reed-Solomon 8:4 erasure coding with BLAKE3 checksums and 4KiB+ shards, implemented in-tree (`common/libkeptino/src/erasure.rs`, no dependencies) and byte-compatible with every vault ever written.
 - XChaCha20Poly1305 encryption.
 - LZ4 level 9 compression.
 - Simple TLV serialization.
 - CPU rending only via tiny-skia.
 - Wayland only.

### Linux setup

On Debian/Ubuntu, install a Rust toolchain and run `./linux/setup.sh` as your
normal user. Setup uses sudo to install missing system dependencies
(`build-essential`, `pkg-config`, `dpkg-dev`, `systemd`, `libcap2-bin`,
`libwayland-dev`, and `libxkbcommon-dev`) and installs `cargo-deb` if needed.
It checks credential encryption and builds/installs Keptino before asking
for the pepper seed and credentials for your selected storage provider. The
pepper is derived by the installed binary itself, `keptino --derive-pepper`,
in locked memory; no external `argon2` tool is involved.

### Security keys on Linux

A FIDO2 security key with the `hmac-secret` extension, such as a YubiKey 5,
can protect a vault as a second factor beside the master password and the
pepper. Open the vault, press Keys, and choose Protect with a security key:
the vault is rekeyed so that every device then needs an enrolled key to open
it. Up to four keys can be enrolled; keep a backup key enrolled, because a
vault whose every key is lost while locked cannot be opened. Removing a key
rekeys again and asks for a touch of each remaining key. Keys speak CTAPHID
over USB through `/dev/hidrawN`; systemd's udev rules grant the logged-in
user access, and setup warns when they are missing. On Android, open Keys to manage the same enrolled keys.
Use USB-C on a phone with USB host support. Android NFC has been tested with
the fixture authenticator only.

Package installation grants `/usr/bin/keptino` the `CAP_IPC_LOCK` capability
so it can lock its memory, including the 4 GiB password derivation, without
being constrained by the desktop session's memlock limit. This is reapplied
on upgrades. Launch the installed executable; a build in `target/` does not
have this capability.

Dependencies are pinned by `Cargo.lock` and resolved under a seven-day
cooldown (`.cargo/config.toml`, Cargo 1.100 or newer): a crate version
published less than a week ago is not adopted by `cargo update`, so a
compromised release that is yanked within days never reaches a build. If
`cargo-audit` is installed (`cargo install cargo-audit --locked`), setup runs
`cargo audit` before building and prints any advisories without stopping.
Advisories that are accepted for now are listed with their reasons in
`.cargo/audit.toml`, so only new ones appear.

Rerunning setup reuses the encrypted credentials in `~/.config/keptino`.
Setup checks the pepper and the active provider credential. If either file
is empty or cannot be decrypted, setup stops for repair. Keep the original
pepper credential when using an existing vault.

To re-enter only the Backblaze credentials, run
`./linux/setup.sh --reset-backblaze`. This skips the build and preserves the
pepper. The old Backblaze file is replaced only after encryption succeeds.

To recover an invalid pepper credential, run `./linux/setup.sh --restore-pepper`
and enter the original pepper seed used for the vault. This skips rebuilding,
backs up the previous encrypted pepper, and validates the regenerated value
before replacing it. It preserves cloud storage credentials. A different seed
will not unlock an existing vault.

If setup reports `Unexpected TPM PCR state of the system`, the current boot
measurements do not satisfy the policy for the listed credential. With the
original pepper seed, use `--restore-pepper` at the local prompt. If the seed
is unavailable, keep the encrypted pepper and recover access in the boot
state in which it was sealed. Re-enter the storage key separately if setup
also lists the provider credential.

### Cloud storage on Linux

Keptino syncs one object named `<database name>.keptino` in a private
bucket. Every provider stores the same Base64-encoded encrypted vault.
Existing installations default to Backblaze B2 and reuse `backblaze.cred`.
Besides the four named services, `s3` points Keptino at any S3-compatible
store of your own, such as RustFS or MinIO on a host you run: enter the
`https://` endpoint, the bucket, the region (`us-east-1` unless the store
says otherwise) and a key pair allowed to get and put objects. The
endpoint's certificate must be trusted by this machine; plaintext HTTP is
refused. Every S3 request, to a named service or your own endpoint, is
signed by Keptino's own Signature Version 4 code, and a save asks the
store to refuse the write if the object changed since it was fetched.

| Provider | What to provision | Free storage terms |
| --- | --- | --- |
| Backblaze B2 (`backblaze`) | A read/write application key restricted to the vault bucket. Enter the key name, ID, and application key. | First 10 GB free. [B2 pricing](https://www.backblaze.com/cloud-storage/pricing) |
| Cloudflare R2 (`r2`) | A Standard bucket in the default jurisdiction. Create an Object Read & Write token scoped to that bucket. Enter the bucket name, account ID, access key ID, and secret access key. [R2 setup](https://developers.cloudflare.com/r2/get-started/s3/) | 10 GB-month each month with free operation allowances. [R2 pricing](https://developers.cloudflare.com/r2/pricing/) |
| Google Cloud Storage (`gcs`) | A Standard bucket and a service account with Storage Object User on that bucket. Create an HMAC key for the account. Enter the bucket name, location (e.g. `us-central1`), HMAC access ID, and secret. [HMAC keys](https://cloud.google.com/storage/docs/authentication/hmackeys) | 5 GB-month each month across `us-central1`, `us-east1`, and `us-west1`, subject to Free Tier limits. [Google Cloud pricing](https://cloud.google.com/storage/pricing) |
| Amazon S3 (`aws`) | A general purpose bucket and an IAM access key pair. Grant `s3:GetObject` and `s3:PutObject` on vault objects and `s3:ListBucket` on the bucket so a first unlock can distinguish a missing vault from denied access. Enter the bucket name, AWS region, access key ID, and secret access key. [S3 permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) | The new-customer free plan lasts up to six months. [S3 pricing](https://aws.amazon.com/s3/pricing/) |

To switch providers, first save your current vault and confirm the local
`~/.config/keptino/<database name>.keptino` file exists. Close Keptino
and run setup with the desired provider. For R2, run

```sh
./linux/setup.sh --configure-storage r2
```

This command provisions credentials and selects the provider without rebuilding
Keptino. Unlock the same database name and save once to upload it to an empty
destination bucket. Switching redirects future syncs and leaves the previous
bucket's object in place. To recover on another installation, configure the
same bucket and use the original pepper seed, database name, and master password.

### Cloud objects after the rename

Keptino reads and writes `<database name>.keptino` in the existing bucket.
If the latest vault is in the cloud under `<database name>.digisafe`, use
the provider's console to copy the object to the new key before unlocking on
Linux or Android. Preserve the object's contents. If the latest vault is on
your migrated installation, unlock it and save once to upload it under the
new key. The old object stays available under its original name.

Every vault file carries its metadata twice: in the plaintext envelope and
inside the encrypted database. After decryption the two copies must match
exactly, so a changed, added or dropped plaintext field (a replayed
modification time, say) fails to open like a wrong password. This holds for
every vault ever written, with no re-save. Saves also record a `revision`
that advances on each save and the Argon2 cost the vault was opened with;
earlier releases open such vaults, use their own compiled cost, and carry
the revision along without advancing it. Unlock compares the local and
remote copies by revision, then by modification time, and tries the other copy if the preferred one fails to authenticate,
pausing uploads for the session when that happens. A copy whose revision is
below the highest one already opened on this machine is refused; remove
`~/.config/keptino/<database name>.revision` to accept it deliberately. Each
save uses a fresh nonce, including when editing a local copy offline, and
uploads only over the exact remote object this session loaded or last
uploaded: if another device wrote in between, the save stays local and asks
you to unlock again first. If the provider is unreachable, an existing local
copy opens with a status message and saves locally for that session. A
failed upload also leaves a local copy and displays the error.

### Secrets in memory

Passwords, PINs, and notes stay encrypted while hidden, including in the selected
entry. Reveal a field to view or edit it; hide it when finished. Notes also start
hidden. Selecting another entry hides all secret fields again. Copying a password
or PIN does not require revealing it.

The memory layer uses XChaCha20-Poly1305 with random keys in `memfd_secret`, fresh
nonces, and authenticated field/record identifiers. Secret mappings are exclusive
and unmapped after use. Application-owned temporary plaintext buffers are wiped
on disposal; the master password is moved into the unlock task instead of cloned.
Existing vaults open and save in their original on-disk and Backblaze formats.

This reduces plaintext exposure while the application is idle. It does not
protect against an attacker controlling the process. Revealing/editing secrets,
copying them, and compressing a vault still involves Iced, clipboard, and LZ4
buffers whose internal copies are not guaranteed to be wiped. Clipboard history
and receiving applications can also retain copied secrets.

### Deliberate exclusions

Keptino has no browser integration, auto-type, SSH agent, Secret Service
interface, passkey store, plugin system or breach-database lookup, and no
quick unlock that keeps a derived key alive across locks. Each is an IPC or
network surface into the process that holds the master key; several of
KeePassXC's 2.8.0 security fixes were in such surfaces. The vault talks to
one thing, the user's own storage bucket, over TLS. Copying through the
clipboard is the only way a secret leaves the process.

### Known Weaknesses

 - iced String buffers.
 - no virtual keyboard input.
 - bpftrace.
 - wayland-data-control.

#### Linux screenshots from the DigiSafe release
![ScreenShot](doc/img/unlock_screen.png)

![ScreenShot](doc/img/empty_entry.png)

![ScreenShot](doc/img/sample_entry.png)

