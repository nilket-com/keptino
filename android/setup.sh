#!/usr/bin/env bash
# Build and install Keptino from any working directory.
set -euo pipefail

usage() {
    echo "Usage: $0 [--serial ADB_SERIAL]"
    echo "Connect a device with USB debugging enabled and authorize this computer."
}

fail() { echo "$*" >&2; exit 1; }

serial=${ANDROID_SERIAL:-}
case ${1:-} in
    -h|--help) usage; exit 0 ;;
    --serial|-s)
        [[ $# == 2 && -n ${2:-} ]] || { usage >&2; exit 2; }
        serial=$2 ;;
    *) [[ $# == 0 ]] || { usage >&2; exit 2; } ;;
esac

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

printf 'Building Keptino for installation on %s\n' "$serial"
./gradlew :app:assembleDebug
"$adb" -s "$serial" install -r app/build/outputs/apk/debug/app-debug.apk
printf 'Installed Keptino on %s.\n' "$serial"
