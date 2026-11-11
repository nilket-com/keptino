#!/usr/bin/env bash
# Cross-compiles the vault core and places it where Gradle packages it.
# Only 64-bit ABIs: unlocking a vault needs a 4 GiB allocation.
set -euo pipefail
cd "$(dirname "$0")"

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
tools=toolchains/llvm/prebuilt/linux-x86_64/bin
# The newest complete NDK; one still being installed has no compiler yet.
ndk=${ANDROID_NDK_HOME:-$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d -exec test -x "{}/$tools/clang" \; -print 2>/dev/null | sort -V | tail -n 1)}
bin="$ndk/$tools"
if [[ -z "$ndk" || ! -x "$bin/clang" ]]; then
	printf 'No Android NDK found. Set ANDROID_NDK_HOME or install one under %s/ndk.\n' "$sdk" >&2
	exit 1
fi
api=${ANDROID_API:-30}
profile=${1:-release}
case "$profile" in
	release) flags=(--release) ;;
	debug) flags=() ;;
	*) printf 'Usage: %s [release|debug]\n' "$0" >&2; exit 2 ;;
esac

jni_libs=../app/src/main/jniLibs
for pair in aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64; do
	target=${pair%%:*}
	abi=${pair##*:}
	env_target=${target//-/_}
	rustup target add "$target" >/dev/null
	env \
		"CC_$env_target=$bin/$target$api-clang" \
		"AR_$env_target=$bin/llvm-ar" \
		"CARGO_TARGET_${env_target^^}_LINKER=$bin/$target$api-clang" \
		cargo build --locked --target "$target" "${flags[@]}"
	mkdir -p "$jni_libs/$abi"
	cp "target/$target/$profile/libdroid.so" "$jni_libs/$abi/libdroid.so"
done
printf 'Built libdroid.so (%s) with %s\n' "$profile" "$(basename "$ndk")"
