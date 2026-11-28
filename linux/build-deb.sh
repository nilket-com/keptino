#!/usr/bin/env bash
# Builds the Linux release package reproducibly (ADR 0031): the same commit,
# Cargo.lock, Rust toolchain and cargo-deb give the same bytes on any
# machine, from any checkout path and any user's home.
#   linux/build-deb.sh [--sign KEY] [OUTDIR]
# OUTDIR (default target/deb) receives the .deb, SHA256SUMS and BUILDINFO,
# the record of what built it. --sign KEY adds SHA256SUMS.sig with an SSH
# signing key (ssh-keygen -Y sign, namespace keptino-release).
set -euo pipefail
sign_key=
if [[ ${1:-} == --sign ]]; then
	sign_key=${2:?signing key}
	shift 2
fi
linux=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$linux/.." && pwd)
out=$(mkdir -p "${1:-$root/target/deb}" && cd "${1:-$root/target/deb}" && pwd)
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)

# Every timestamp in the package is the commit's. A tree with uncommitted
# changes still builds, but its BUILDINFO says so: it is not the commit.
commit=$(git -C "$root" rev-parse HEAD)
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct HEAD)
dirty=no
[[ -z $(git -C "$root" status --porcelain --untracked-files=no) ]] || dirty=yes

# The binary names its sources in panic and log locations; these prefixes
# replace the builder's paths, so neither the user name nor the checkout
# location reaches the package. trim-paths is not yet stable.
export RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$root=/keptino"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$root/target/reproducible}

heavy=
[[ -x $root/ci/heavy ]] && heavy=$root/ci/heavy
rm -f "$out"/keptino_*.deb "$out/SHA256SUMS" "$out/SHA256SUMS.sig" "$out/BUILDINFO"
(cd "$linux" && $heavy cargo deb --locked --output "$out")
deb=$(cd "$out" && ls keptino_*.deb)

{
	printf 'commit %s\n' "$commit"
	printf 'uncommitted-changes %s\n' "$dirty"
	printf 'source-date-epoch %s\n' "$SOURCE_DATE_EPOCH"
	printf 'cargo-lock-sha256 %s\n' "$(sha256sum "$root/Cargo.lock" | cut -d' ' -f1)"
	rustc -vV | sed 's/^/rustc /'
	printf 'cargo-deb %s\n' "$(cargo deb --version | awk '{print $2}')"
} >"$out/BUILDINFO"
(cd "$out" && sha256sum "$deb" BUILDINFO >SHA256SUMS)
if [[ -n $sign_key ]]; then
	ssh-keygen -q -Y sign -f "$sign_key" -n keptino-release "$out/SHA256SUMS"
fi
printf 'Built %s\n' "$out/$deb"
cat "$out/SHA256SUMS"
