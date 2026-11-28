#!/usr/bin/env bash
# Checks that the Linux package is reproducible (ADR 0031): builds one
# commit twice with linux/build-deb.sh, from two clean checkouts at
# different paths, with different Cargo home paths and target directories,
# and requires byte-identical packages that name none of those paths.
#   linux/repro-check.sh [COMMIT]     default HEAD; about twenty minutes
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
commit=$(git -C "$root" rev-parse "${1:-HEAD}")
work=$(mktemp -d "${TMPDIR:-/tmp}/keptino-repro.XXXXXX")
cleanup() {
	for side in a b; do
		git -C "$root" worktree remove --force "$work/checkout-$side" 2>/dev/null || true
	done
	[[ -n ${KEEP_WORK:-} ]] || rm -rf "$work"
}
trap cleanup EXIT
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)

for side in a b; do
	git -C "$root" worktree add -q --detach "$work/checkout-$side" "$commit"
	# The same registry and tools under a path of this side's own, as a
	# second builder's home would be.
	ln -s "$cargo_home" "$work/cargo-home-$side"
	printf '== Build %s from %s\n' "$side" "$work/checkout-$side"
	CARGO_HOME="$work/cargo-home-$side" CARGO_TARGET_DIR="$work/target-$side" \
		"$work/checkout-$side/linux/build-deb.sh" "$work/out-$side" >"$work/build-$side.log" 2>&1 || {
		tail -20 "$work/build-$side.log"
		exit 1
	}
done

deb=$(cd "$work/out-a" && ls keptino_*.deb)
if ! cmp -s "$work/out-a/$deb" "$work/out-b/$deb"; then
	printf 'not reproducible: %s differs between the builds\n' "$deb"
	if command -v diffoscope >/dev/null; then
		diffoscope "$work/out-a/$deb" "$work/out-b/$deb" | head -60 || true
	fi
	KEEP_WORK=1
	printf 'kept for inspection: %s\n' "$work"
	exit 1
fi
cmp -s "$work/out-a/SHA256SUMS" "$work/out-b/SHA256SUMS" || {
	echo 'not reproducible: SHA256SUMS differ'
	exit 1
}
printf 'ok: both builds are byte-identical\n'

mkdir "$work/unpacked"
dpkg-deb -x "$work/out-a/$deb" "$work/unpacked"
leaks=$(grep -rlaF -e "$HOME" -e "$work" -e "$cargo_home" "$work/unpacked" || true)
if [[ -n $leaks ]]; then
	printf 'the package names a builder path:\n%s\n' "$leaks"
	exit 1
fi
printf 'ok: no builder, home or checkout path in the package\n'
cat "$work/out-a/SHA256SUMS"
