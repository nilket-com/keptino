#!/usr/bin/env bash
# Compiles the system call filter (ADR 0028, ADR 0029) for every Linux target
# it is built for, with the libc version Cargo.lock pins. The whole head
# cannot cross-compile without C toolchains, so the module is checked alone:
# a call missing from libc on one target breaks the build there.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
targets=(x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl)
installed=$(rustup target list --installed)
missing=()
for target in "${targets[@]}"; do
	grep -qx "$target" <<<"$installed" || missing+=("$target")
done
if ((${#missing[@]})); then
	echo "Missing Rust targets: rustup target add ${missing[*]}" >&2
	exit 1
fi
libc=$(awk '/^name = "libc"$/ { getline; gsub(/"/, "", $3); print $3; exit }' "$root/Cargo.lock")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/src"
cat >"$work/Cargo.toml" <<TOML
[package]
name = "seccomp-targets"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
libc = "=$libc"

[workspace]
TOML
printf '#[path = "%s/linux/src/seccomp.rs"]\npub mod seccomp;\n' "$root" >"$work/src/lib.rs"
cd "$work"
cargo generate-lockfile --offline -q
for target in "${targets[@]}"; do
	cargo check -q --offline --locked --all-targets --target "$target" \
		--target-dir "$root/target/seccomp-targets"
	echo "ok: the filter compiles for $target"
done
