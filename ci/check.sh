#!/usr/bin/env bash
# The repository-owned gate, run on a machine the project controls before a
# push. Android device and emulator checks live under android/.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run() {
	printf '\n==> %s\n' "$*"
	"$@"
}

run cargo fmt --all --check
run cargo clippy --workspace --all-targets --locked -- -D warnings
run cargo test --workspace --locked
# The system call filter on every Linux target it is built for (ADR 0029).
run linux/seccomp-targets.sh
# Advisories: the accepted list in .cargo/audit.toml applies; a finding fails the gate.
run cargo audit
run python3 -B ci/test_commit_subjects.py
run python3 -B ci/commit_subjects.py --repo . --commit HEAD
