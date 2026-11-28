#!/bin/sh
# Coverage-guided fuzzing of one libkeptino target on stable Rust (ADR 0026):
# the flags cargo-fuzz passes with `-s none`, built for the host target so
# build scripts stay uninstrumented, run under ci/heavy when present.
#   libkeptino/fuzz/run.sh TARGET [SECONDS]
# Targets: shards envelope payload slot s3 cbor ctap hid nfc.
# A crash is saved under artifacts/TARGET/; rerun it by passing the file.
set -eu
target=${1:?target}
seconds=${2:-300}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
host=$(rustc -vV | sed -n 's/^host: //p')
# The shared host runner when this checkout has it, else run directly.
heavy=
[ -x "$root/ci/heavy" ] && heavy="$root/ci/heavy"
export CARGO_TARGET_DIR="$root/target/fuzz"
export RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares \
--cfg fuzzing -Cdebug-assertions -Coverflow-checks"
cd "$here"
$heavy cargo build --locked --release --target "$host" --bin "$target"
mkdir -p "corpus/$target" "artifacts/$target"
shift $(($# > 1 ? 2 : 1))
exec $heavy "$CARGO_TARGET_DIR/$host/release/$target" \
	-artifact_prefix="artifacts/$target/" -max_total_time="$seconds" \
	-rss_limit_mb=2048 -max_len=70000 "corpus/$target" "$@"
