#!/usr/bin/env bash
# Build and install Keptino from any working directory.
set -euo pipefail

usage() {
    echo "Usage: $0 [--serial ADB_SERIAL] [--user ID] [--rotate-from ORIGINAL_DEBUG_KEYSTORE | --debug [--r2]]"
    echo "Default: install a signed release. See android/README.md to set up the release key."
    echo "Connect a device with USB debugging enabled and authorize this computer."
}

fail() { echo "$*" >&2; exit 1; }

serial=${ANDROID_SERIAL:-}
provision=false
debug=false
rotation=()
profile=()
while (( $# )); do
case "$1" in
    -h|--help) usage; exit 0 ;;
    --serial|-s)
        [[ -n ${2:-} ]] || { usage >&2; exit 2; }
        serial=$2; shift 2 ;;
    --user)
        [[ ${2:-} =~ ^[0-9]{1,10}$ ]] && (( 10#$2 <= 2147483647 )) || fail "Expected a numeric Android user ID."
        profile=(--user "$2"); shift 2 ;;
    --debug) debug=true; shift ;;
    --rotate-from)
        [[ -n ${2:-} ]] || { usage >&2; exit 2; }
        rotation=(--rotate-from "$(realpath -m -- "$2")"); shift 2 ;;
    --r2) provision=true; shift ;;
    *) usage >&2; exit 2 ;;
esac
done

if $provision && ! $debug; then
    fail "USB R2 provisioning needs --debug --r2. Release upgrades keep R2 settings. For a fresh release use setup on the phone."
fi
if $debug && (( ${#rotation[@]} )); then fail "--rotate-from requires a release build."; fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
if [[ -z $sdk ]]; then
    sdk="$HOME/Android/Sdk"
    # Earlier DigiSafe builds on this host used a cached SDK and JDK.
    if [[ ! -d $sdk && -d $HOME/.cache/digisafe-android-sdk ]]; then
        sdk="$HOME/.cache/digisafe-android-sdk"
    fi
fi
export ANDROID_HOME="$sdk"
if [[ -z ${JAVA_HOME:-} && -x $HOME/.cache/digisafe-jdk21/bin/java ]]; then
    export JAVA_HOME="$HOME/.cache/digisafe-jdk21"
fi

if [[ -n ${JAVA_HOME:-} ]]; then
    [[ -x $JAVA_HOME/bin/java ]] || fail "JAVA_HOME must point to a JDK with bin/java."
    export PATH="$JAVA_HOME/bin:$PATH"
fi

adb="$sdk/platform-tools/adb"
packages=()
[[ -x $adb ]] || packages+=(platform-tools)
[[ -f $sdk/platforms/android-37.0/android.jar ]] || packages+=('platforms;android-37.0')
[[ -x $sdk/build-tools/36.0.0/aapt2 ]] || packages+=('build-tools;36.0.0')
[[ -x $sdk/ndk/30.0.16248370/toolchains/llvm/prebuilt/linux-x86_64/bin/clang ]] || packages+=('ndk;30.0.16248370')
if (( ${#packages[@]} )); then
    sdkmanager=$(command -v sdkmanager || true)
    for tool in "$sdk/cmdline-tools/23.0/bin/sdkmanager" "$sdk/cmdline-tools/latest/bin/sdkmanager"; do
        if [[ -x $tool ]]; then sdkmanager=$tool; break; fi
    done
    [[ -n $sdkmanager ]] || fail "Install the Android SDK command-line tools and set ANDROID_HOME to the SDK directory. See android/README.md."
    "$sdkmanager" --sdk_root="$sdk" "${packages[@]}"
fi

target=()
[[ -z $serial ]] || target=(-s "$serial")
if ! serial=$("$adb" "${target[@]}" get-serialno) || [[ -z $serial || $serial == unknown ]]; then
    "$adb" devices -l >&2
    fail "Connect and authorize one device, or select a listed device with --serial SERIAL."
fi
[[ $("$adb" -s "$serial" get-state) == device ]] || fail "Unlock $serial and authorize USB debugging, then rerun setup."

user=$(python3 ./adb_user.py "$adb" "$serial" "${profile[@]}")
printf 'Building Keptino for installation on %s (Android user %s)\n' "$serial" "$user"
if ! $debug; then
    ./gradlew :app:assembleRelease
    exec python3 ./install-release.py --sdk "$sdk" --serial "$serial" --user "$user" "${rotation[@]}"
fi
./gradlew :app:assembleDebug
"$adb" -s "$serial" install -r --user "$user" app/build/outputs/apk/debug/app-debug.apk
printf 'Installed Keptino on %s.\n' "$serial"

if $provision; then exec python3 ./provision-r2.py --adb "$adb" --serial "$serial" --user "$user"; fi
