# Keptino for Android

The Android application reads and writes Linux `.keptino` vaults. It uses a Rust
core for the vault, key derivation and encryption; Kotlin handles the editor,
Android Keystore, local files, Backblaze B2 and Cloudflare R2. The former plaintext JSON prototype
is not used or automatically imported.

## Move an existing Android vault

Keptino installs alongside DigiSafe under the new application ID `com.keptino.app`.
Android keeps each installation's private files and Keystore settings separate.

1. Open each vault in the old app (`com.digisafe.app`), save your edits and use
   **Export saved vault** to put the encrypted file in Downloads or another folder you can access.
2. Install Keptino and configure it with the original pepper seed or pepper value.
   Enter your Backblaze credentials again if you use sync.
3. Enter the same database name, choose **Import Linux vault**, select the exported
   `.digisafe` file and unlock with the original master password. Check the entries
   before removing the old app. Keptino uses `.keptino` for new saves and exports.

Sync now uses the object key `<database name>.keptino`. To migrate a cloud-only
vault, copy the existing `<database name>.digisafe` object to that key in the same
bucket, preserving its contents. If you have the latest local vault, you can
import it and use **Save** with sync configured to upload it under the new key.

## Install or update over ADB

Everyday installs use a non-debuggable release signed by your own key. For
the first install, create the key on your trusted build host. Keep the key
and its password in separate backups you can recover without opening Keptino.
These commands prompt for the password. Use JDK 21's `keytool`.

```sh
(
    set -eu
    umask 077
    mkdir -p ~/.config/keptino-signing
    cd ~/.config/keptino-signing
    keytool -genkeypair -storetype PKCS12 -keystore release.p12 -alias keptino \
        -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=Keptino release"
    keytool -exportcert -keystore release.p12 -alias keptino -file release.der
    sha256sum release.der | cut -d' ' -f1 > release.sha256
)
```

Compare the pinned digest in `release.sha256` with the SHA-256 fingerprint
shown by `keytool -list -v -keystore release.p12`. Keep a trusted copy of the
fingerprint with your backup. To use another private directory outside the
checkout, set `KEPTINO_SIGNING_DIR`.

Connect the phone, enable **USB debugging** and authorize this computer.
For an existing debug install, supply its original signing key once:

```sh
./android/setup.sh --rotate-from ~/.android/debug.keystore
```

The installer checks the installed certificate, signs the rotation with both
keys and saves `release.lineage` alongside the release key. Back up this
public file too. Android checks the signer of the private receiver permission
that AndroidX declares. Setup installs the same non-debuggable release twice
during rotation. The first update transfers ownership of the permission. The
second retires the old signer's permission capability. If interrupted
between updates, rerun setup with the release key and saved lineage to finish.
The final lineage grants the old certificate continuity for installed data
and disables rollback to the debug signer. A missing or mismatched key
stops the upgrade before installation. Keep your existing installation
while you locate the original key.

For a fresh install and subsequent updates, run:

```sh
./android/setup.sh
```

Setup verifies the package, version code, signer and packaged manifest before
and after installation. An upgrade preserves vaults, revision records and
Keystore-protected settings. On a fresh install, enter the pepper and optional
sync credentials on the phone. Interactive signing reads the keystore
passwords from the terminal. Automation can pass a descriptor number in
`KEPTINO_RELEASE_PASSWORD_FD` and, for rotation, `KEPTINO_OLD_PASSWORD_FD`;
each descriptor supplies one line and must be inherited by the installer.

With several devices or emulators connected, use `adb devices -l` to find the
target and run `./android/setup.sh --serial SERIAL`. Setup also honors
`ANDROID_SERIAL`.

### Build prerequisites

Use a 64-bit Linux host, Rust, JDK 21, and Android SDK command-line tools. The
project uses Android command-line tools 23.0 and pins AGP 9.5.1, Gradle 9.9.1, Compose compiler 2.4.21, Compose BOM
2026.09.00, Android API 37, and NDK 30.0.16248370. AGP provides built-in Kotlin.
The wrapper downloads Gradle; no system Gradle installation is required.

Set `JAVA_HOME` and `ANDROID_HOME` if your tools are outside the default search
paths. For example:

```sh
export JAVA_HOME="$HOME/.local/opt/jdk-21.0.13+9"
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/23.0/bin:$ANDROID_HOME/platform-tools:$PATH"
```

Setup uses `sdkmanager` to install missing SDK packages. The native build
adds the required Rust targets through `rustup`. To build the APK on an
already configured host without installing it, run `cd android && ./gradlew :app:assembleDebug`.

Gradle invokes `droid/build.sh` to build and package the Rust library for ARM64
and x86-64. A native library built only for the host will not work in the APK.
Minimum supported Android version is Android 11 (API 30), on 64-bit devices.
Debug and release applications use the production Linux KDF defaults when a vault
has no recorded costs. New saves record the Argon2id memory, passes and lanes as
ordinary TLV metadata. Android bounds these costs before derivation and checks
them against the authenticated inner copy before opening the vault.

## Use your Linux R2 setup on Android

An everyday release keeps existing R2 settings during an upgrade. On a fresh
release, choose **Use Cloudflare R2** on the phone. For a separate development
installation, USB import is available with an explicit debug build:

```sh
./android/setup.sh --debug --r2
```

The installer updates Keptino in place. On the phone, tap **Receive setup**
and approve the device authentication prompt. The helper reads the existing
Linux `pepper.cred` and `r2.cred` with systemd-creds and sends them through
an app-private FIFO. The phone reads the selected vault object before saving
its settings. The terminal reports whether it found the vault. The vault
master password stays with you and is used on the ordinary unlock screen.

Use `--serial SERIAL --debug --r2` if several devices are attached. For manual
setup, select **Use Cloudflare R2** and enter the account ID, bucket, access
key ID and secret access key, along with the original pepper. R2 uses the
same default-jurisdiction endpoint, `auto` region and base64 object as Linux.
A changed object stops the conditional upload and preserves the local save.

## Create a vault on Android

After setup, choose **Create a new vault**, enter a new vault name, and enter the
master password twice. Keptino uses the pepper in the phone's protected
settings. Use the same pepper on Linux to open this vault there.

Local-only settings create the file on the phone. With R2 configured,
leave **Open local copy only** unchecked. Keptino reserves the name in R2
before saving the local copy. If another device wins the race, Keptino
tries to unlock that device's copy. If the connection drops during creation,
use **Unlock** to check whether R2 received it. The Backblaze native upload
API cannot reserve a name, so Android offers creation with local-only or R2
settings.

## Open an existing Linux vault

1. Configure a device PIN, pattern or password. In Keptino setup, enter the **original pepper seed** used by Linux, or its original
   32-byte pepper encoded as 64 hexadecimal characters. A new seed cannot unlock
   an existing vault. Do not paste real credentials into test fixtures or logs.
2. For sync, use the same provider and bucket as Linux. R2 settings can be
   transferred over USB as described above. For Backblaze B2, enter the
   bucket-restricted application key ID and application key. Leave sync disabled
   to use local import and export.
3. Enter the database name used on Linux. Unlock with sync enabled to download
   the encrypted vault, or import a Linux `.keptino` file. Import refuses to
   overwrite an existing local file.
4. Enter the master password and unlock. “Open local copy only” skips network
   access explicitly. Failed remote requests do not silently create an empty vault.
5. Find an entry by part of its name or an exact tag, or use the tag and
   weak-password filters. Tap a row to open it. The list shows usernames and
   flags. Passwords, PINs, and notes stay hidden until you reveal them.
6. The die beside Password opens the generator. Choose characters or words,
   adjust the length, and tap **Use this password** to apply the preview.
   **Revert** restores the set entry. Back discards unset edits.
   **Set entry** returns to the list. **Save** writes the set entries and
   confirmed deletions locally before syncing. If the upload fails, you
   can retry Save. Use **Export** in the vault menu for the last saved file.
7. Choose **Health** in the vault menu to see which entries have reused,
   potentially weak, stale, or empty passwords. The report uses the set
   entries and runs offline. **Back to vault** returns to the list.
8. Open **Keys** to protect the vault or add a spare. Choose the attached USB
   key and follow the touch or PIN prompts. Each of the four slots can unlock
   the vault independently. NFC is experimental and has been tested with
   the fixture authenticator only. Android key management passed the emulator
   checks. The Samsung recognized the USB-C YubiKey, but physical enrollment
   stopped at touch confirmation. Physical unlock and revocation are unverified.
   Removing slots requires the master password and each key you keep. Losing
   every enrolled key while locked prevents recovery with the password alone.

A rekey changes the vault salt. On another device, **Adopt bucket copy**
checks the downloaded vault and preserves the previous local bytes as
`<name>.keptino.1`. After an offline rekey, uploads stay paused until the
bucket copy is reconciled.

Create derives a new vault key with Argon2id at **256 MiB, three passes, one lane**.
Unlock and Save honor the cost in the vault. A legacy production vault without
recorded costs still needs 4 GiB at one pass. Deriving the pepper from its seed
also needs 4 GiB, at four passes. Importing the original pepper skips that step.

On every open, Android compares the plaintext metadata against the copy inside
the authenticated ciphertext, including on older vaults without a revision.
New saves omit the format marker and advance the revision. Marked format-2
files still open and convert on save. Pre-format-2 builds can edit unmarked files
when their KDF defaults match. They preserve the revision without advancing it.
The short-lived Android build that required the marker for revisions needs updating.

Android remembers the highest
revision opened or saved for each local vault name in a Keystore-protected
record. To deliberately recover an older file, import it under a fresh name
and select **Open local copy only**.

If the preferred copy fails authentication and the other opens, uploads pause
for that session. Before each upload, Android checks whether the encrypted
remote object has changed since unlock or the last successful upload. If it
changed, the edit stays in the local file and can be exported before reopening.
Concurrent writes between the final check and the upload remain possible.

## Device behavior

Android Keystore encrypts the pepper and optional sync credentials with
AES-GCM. Saving setup and unlocking the vault require the system prompt for a
strong biometric or the device credential, including offline unlocks. The prompt
authorizes that specific cipher operation. The master password still unlocks the
vault separately. Saving an already unlocked vault uses its session credentials.
Changing cloud credentials while retaining the stored pepper requires authorization
to read the pepper and again to encrypt the replacement settings.

Setup requests StrongBox when available and falls back to the default Android
Keystore if StrongBox is unavailable. The locked screen reports the storage key's
security level. The first authenticated read migrates existing settings and retires
the legacy key after writing and verifying the replacement. A canceled prompt
leaves the existing setup usable. If a lock-screen reset invalidates the key, use
**Change setup** and enter the original pepper and storage credentials. Android
can retain this key across biometric enrollment because device credentials are
also allowed. [Android Keystore authentication](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,int))

The native startup check disables process dumps where the kernel permits and
refuses vault access when it detects tracing or known injected libraries. The
native master key and derived pepper use dedicated, wiped pages with best-effort
memory locking. The key-derivation buffer uses dump exclusion where
supported and may be swapped. The locked screen shows available bootloader,
Verified Boot, debug-image, developer-options, ADB and native memory warnings.
These are local observations. OEMs can withhold boot properties.

Android backup is disabled. The window blocks screenshots, filters obscured
touches and excludes the vault from autofill. Android 13+ also suppresses the
Recents screenshot, and Android 14+ marks the vault window's accessibility
data sensitive. Native allocations request synchronous memory tagging on devices
that support ARM MTE. [Android MTE](https://developer.android.com/ndk/guides/arm-mte)

The app locks after two minutes without interaction, including time spent in the
background. A monotonic deadline is checked again when the app resumes, so a
frozen background process does not extend the unlock period. Unsaved changes are
discarded when it locks. Locking hides revealed fields immediately, even during
a save or upload. An in-progress local save can finish after the editor locks.
Switching to another app does not immediately lock the
vault or erase a copied password. Clipboard copies are marked sensitive and
clearing is attempted after 30 seconds, provided the clipboard still contains the
application's copy. Locking or finishing the activity also triggers an immediate
cleanup attempt. Android may refuse background clipboard access; the app retries
when resumed. Clearing is best effort, and other clipboard consumers may retain copies.
Secret inputs disable keyboard suggestions, and ordinary inputs disable autocorrect
and automatic capitalization. This is a request to the IME, not a guarantee against
a malicious keyboard. Revert entry edits discards only the current working edit.

The native core owns master keys and the vault. Kotlin requests secret fields only
on reveal or copy. Revealed/edited text still passes through JVM/Compose strings,
which cannot be reliably wiped. Locking clears application references.

The debug build allows plain HTTP only for the emulator host (`10.0.2.2`) and
loopback in the B2 client, for the local mock. Release requires HTTPS. No real
Backblaze account is needed for local import/export or automated mock tests.

## Verification

The compatibility tests and fixture generation are under `droid/`. Emulator tests
are under `app/src/androidTest/`. Run:

```sh
cargo test --manifest-path droid/Cargo.toml
./gradlew connectedDebugAndroidTest
```

To exercise USB and NFC framing through JNI using the public fixture keys,
build the debug and test APKs, set `ANDROID_SERIAL` to a running emulator, and
run `python3 interop/check-keys.py`. The authenticator runs on host loopback.
For physical checks, the opt-in `PhysicalSecurityKeyTest` requires a separate
debug application ID ending in `.keycheck`. It uses the public debug fixture
and a file called `hardware.keptino` in that installation. The Linux companion
`cargo run -p keptino --example phone-key-check -- enroll NEW_FILE` writes a
protected fixture. Use `unlock PHONE_FILE` to verify the reverse direction.
For PIN-configured keys, pipe a local hidden-input password prompt into
the example with `--pin-stdin`.

Do not treat an APK build as proof of compatibility. The end-to-end check must
open a fixture emitted by Linux, edit and save it through the Android native
library, then reopen the Android result in Linux. Use synthetic credentials only.

Toolchain references: [AGP compatibility](https://developer.android.com/build/releases/agp-9-5-0-release-notes),
[Android SDK tools](https://developer.android.com/tools),
[Compose BOM](https://developer.android.com/develop/ui/compose/bom).

The debug interoperability run also builds the Android vault core at
`be0f6f3` from local Git history. It has that historical writer edit an
unmarked Linux file, then checks the edit, revision and recorded KDF costs
with the current reader.

For the full emulator check, generate the Linux fixtures with
`interop/run.sh fixtures`, build both APKs with
`./gradlew assembleDebug assembleDebugAndroidTest`, and run:

```sh
python3 test-emulator.py --serial emulator-5556
```

Use the serial printed by `adb devices` and a dedicated emulator with no existing
screen lock. The script sets a temporary test PIN (default `1234`, configurable
with `--device-pin`) and clears it at the end. It exercises the real system
credential prompt, canceled reads and writes, and migration of legacy setup.
The script starts an isolated Backblaze
mock and connects through `adb reverse`; it does not depend on emulator host-IP
routing. It checks native error handling, Keystore/local storage, the Linux debug
fixture, B2 upload/download, and the visible editor with the production Linux
fixture. It also opens a production fixture available only from the mock, edits it through
the UI, uploads it, and asks the unmodified Linux harness to verify all three
Android-written files. Logs and outputs are under `build/reports/interop/`.
Fixture credentials are synthetic and listed in `droid/tests/fixtures/manifest.json`.

The credential, migration and production editor tests passed on the Android 17
(API 37) x86-64 emulator with 8.5 GiB of guest RAM. The following configuration
provides 12 GiB:

```sh
sdkmanager 'emulator' 'system-images;android-37.0;default;x86_64'
printf 'no\n' | avdmanager create avd --name keptino-api37 \
  --package 'system-images;android-37.0;default;x86_64' --device pixel_6
"$ANDROID_HOME/emulator/emulator" -avd keptino-api37 -memory 12288 -cores 4 \
  -no-window -no-audio -no-snapshot -gpu software
```

Start the emulator in another terminal, wait for Android to boot, then run the
test script. The test script replaces the debug application's test setup and
vault files; use a dedicated emulator with no personal vaults. A real phone has
not been used to validate memory availability or OEM lifecycle behavior.

Both apps choose a fresh random nonce on every save. Android also advances the
modification timestamp on each save so Linux can recognize the newer copy. ARM64 and x86-64 libraries are built; only x86-64 has been
executed in the emulator. `assembleRelease` produces an unsigned APK: `setup.sh` signs it with the host release key and verifies it for the device.

Use command-line tools 23.0 when creating the API 37 AVD. Older tools can silently
write `target=android-0`, causing emulator graphics/system-server crashes. Check
`~/.android/avd/keptino-api37.ini` contains `target=android-37.0`.
