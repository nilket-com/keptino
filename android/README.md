# DigiSafe for Android

The Android application reads and writes the Linux `.digisafe` format. It uses a Rust
core for the vault, key derivation and encryption; Kotlin handles the editor,
Android Keystore, local files and Backblaze. The former plaintext JSON prototype
is not used or automatically imported.

## Build

Use a 64-bit Linux host, Rust, JDK 21, and Android SDK command-line tools. The
project uses Android command-line tools 23.0 and pins AGP 9.5.1, Gradle 9.9.1, Compose compiler 2.4.21, Compose BOM
2026.09.00, Android API 37, and NDK 30.0.16248370. AGP provides built-in Kotlin.
The wrapper downloads Gradle; no system Gradle installation is required.

On the development machine:

```sh
export JAVA_HOME="$HOME/.local/opt/jdk-21.0.13+9"
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/23.0/bin:$ANDROID_HOME/platform-tools:$PATH"
sdkmanager 'cmdline-tools;23.0' 'platform-tools' 'platforms;android-37.0' 'build-tools;36.0.0' 'ndk;30.0.16248370'
rustup target add aarch64-linux-android x86_64-linux-android
cd android
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Gradle invokes `droid/build.sh` to build and package the Rust library for ARM64
and x86-64. A native library built only for the host will not work in the APK.
Minimum supported Android version is Android 11 (API 30), on 64-bit devices.
Debug and release applications both use the production Linux KDF parameters.
Tests may explicitly request the smaller Linux debug KDF; there is no automatic
fallback to a weaker derivation.

## Open an existing Linux vault

1. In setup, enter the **original pepper seed** used by Linux, or its original
   32-byte pepper encoded as 64 hexadecimal characters. A new seed cannot unlock
   an existing vault. Do not paste real credentials into test fixtures or logs.
2. Optionally enter the Backblaze application key ID and application key. Both
   must be supplied to enable sync. The bucket name is `digisafe`, matching Linux.
   Leaving both empty enables local import/export use.
3. Enter the database name. Import a Linux `.digisafe` file, or unlock with
   Backblaze enabled to download it. Import refuses to overwrite an existing local
   file. The original imported file is left unchanged.
4. Enter the master password and unlock. “Open local copy only” skips network
   access explicitly. Failed remote requests do not silently create an empty vault.
5. Find an entry by name or tag; previous/next navigate the entries. Password,
   PIN and note start hidden. Reveal a field to edit it; copy does not require reveal.
6. Use **Set entry**, then **Save**. Save writes the encrypted local file atomically
   before uploading. An upload failure reports that the local save succeeded.
   **Export saved vault** exports the last saved encrypted file for Linux to open.

The production key derivation requires **4 GiB of available memory**, in addition
to the app and operating system. Deriving the pepper from its seed also needs
4 GiB. Devices unable to supply that memory cannot open production Linux vaults;
the app does not reduce the KDF cost. Importing an existing pepper avoids the seed
calculation but does not remove the master-password KDF requirement.

## Device behavior

Setup (pepper and optional Backblaze credentials) is encrypted with an Android
Keystore AES-GCM key. On devices with a secure lock screen, using that key also
requires the device to be unlocked. Android backup is disabled. Screenshots are blocked.
The app locks after two minutes without interaction, including time spent in the
background. A monotonic deadline is checked again when the app resumes, so a
frozen background process does not extend the unlock period. Unsaved changes are
discarded when it locks. Switching to another app does not immediately lock the
vault or erase a copied password. Clipboard copies are marked sensitive and
clearing is attempted after 30 seconds, provided the clipboard still contains the
application's copy. Android may refuse background clipboard access; the app retries
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

For the full emulator check, generate the Linux fixtures with
`interop/run.sh fixtures`, build both APKs with
`./gradlew assembleDebug assembleDebugAndroidTest`, and run:

```sh
python3 test-emulator.py --serial emulator-5556
```

Use the serial printed by `adb devices`. The script starts an isolated Backblaze
mock and connects through `adb reverse`; it does not depend on emulator host-IP
routing. It checks native error handling, Keystore/local storage, the Linux debug
fixture, B2 upload/download, and the visible editor with the production Linux
fixture. It also opens a production fixture available only from the mock, edits it through
the UI, uploads it, and asks the unmodified Linux harness to verify all three
Android-written files. Logs and outputs are under `build/reports/interop/`.
Fixture credentials are synthetic and listed in `droid/tests/fixtures/manifest.json`.

The verified emulator configuration uses Android 17 / API 37 with 12 GiB RAM:

```sh
sdkmanager 'emulator' 'system-images;android-37.0;default;x86_64'
printf 'no\n' | avdmanager create avd --name digisafe-api37 \
  --package 'system-images;android-37.0;default;x86_64' --device pixel_6
"$ANDROID_HOME/emulator/emulator" -avd digisafe-api37 -memory 12288 -cores 4 \
  -no-window -no-audio -no-snapshot -gpu software
```

Start the emulator in another terminal, wait for Android to boot, then run the
test script. The test script replaces the debug application's test setup and
vault files; use a dedicated emulator with no personal vaults. A real phone has
not been used to validate memory availability or OEM lifecycle behavior.

Android saves use a fresh random nonce rather than Linux's incrementing counter,
avoiding nonce reuse between devices saving from the same starting file. The
modified timestamp never moves backwards. Both remain readable by Linux without
a format conversion. ARM64 and x86-64 libraries are built; only x86-64 has been
executed in the emulator. `assembleRelease` produces an unsigned APK: distribution
requires a signing configuration and key, which this repository does not contain.

Use command-line tools 23.0 when creating the API 37 AVD. Older tools can silently
write `target=android-0`, causing emulator graphics/system-server crashes. Check
`~/.android/avd/digisafe-api37.ini` contains `target=android-37.0`.
