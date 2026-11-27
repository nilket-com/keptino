# Keptino for Android

The Android application reads and writes Linux `.keptino` vaults. It uses a Rust
core for the vault, key derivation and encryption; Kotlin handles the editor,
Android Keystore, local files and Backblaze. The former plaintext JSON prototype
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

Enable **USB debugging** on the phone, connect it to your Linux computer, and
accept the debugging authorization prompt. From the repository root, run:

```sh
./android/setup.sh
```

Setup builds the debug APK from the current checkout and installs it in place,
preserving saved vaults and Keystore settings. For updates, use the same
debug signing key as the existing install. On first launch, configure the
pepper and optional sync credentials in the app.

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

## Open an existing Linux vault

1. Configure a device PIN, pattern or password. In Keptino setup, enter the **original pepper seed** used by Linux, or its original
   32-byte pepper encoded as 64 hexadecimal characters. A new seed cannot unlock
   an existing vault. Do not paste real credentials into test fixtures or logs.
2. Optionally enter the Backblaze application key ID and application key. Both
   must be supplied to enable sync. For sync between Android and Linux, configure
   Linux to use Backblaze and restrict the key to the same bucket on both devices.
   Keptino reads the bucket name from Backblaze when it authorizes the key.
   Leaving both empty enables local import/export use.
3. Enter the database name. Import a Linux `.keptino` file, or unlock with
   Backblaze enabled to download it. Import refuses to overwrite an existing local
   file. The original imported file is left unchanged.
4. Enter the master password and unlock. “Open local copy only” skips network
   access explicitly. Failed remote requests do not silently create an empty vault.
5. Find an entry by name or tag; previous/next navigate the entries. Password,
   PIN and note start hidden. Reveal a field to edit it; copy does not require reveal.
   **Generate password** fills the working password with 24 random characters by default.
   Under **Generator options**, choose the length and character classes, or choose
   **Words** for a hyphen-joined passphrase. The status shows the entropy in bits.
   Your choices last until you lock the vault.
   **Revert entry edits** restores the stored value. **Delete entry** asks you
   to confirm the selected name and takes effect on disk when you save.
6. Use **Set entry**, then **Save**. Save writes the encrypted local file atomically
   before uploading. An upload failure reports that the local save succeeded.
   **Export saved vault** exports the last saved encrypted file for Linux to open.
7. Choose **Health** to see which entries have reused, potentially weak, stale,
   or empty passwords. The report runs offline and includes edits made with
   **Set entry**. **Back to editor** returns to your working entry.

The default production vault requires **4 GiB of available memory** for password
derivation. Deriving the pepper from its seed also needs 4 GiB. Importing the
original pepper skips the seed calculation.

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

Android Keystore encrypts the pepper and optional Backblaze credentials with
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
memory locking. The 4 GiB key-derivation buffer uses dump exclusion where
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
executed in the emulator. `assembleRelease` produces an unsigned APK: distribution
requires a signing configuration and key, which this repository does not contain.

Use command-line tools 23.0 when creating the API 37 AVD. Older tools can silently
write `target=android-0`, causing emulator graphics/system-server crashes. Check
`~/.android/avd/keptino-api37.ini` contains `target=android-37.0`.
