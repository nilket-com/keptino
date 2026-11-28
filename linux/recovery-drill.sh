#!/usr/bin/env bash
# The recovery drill (ADR 0033): disasters a user can survive, rehearsed on
# throwaway vaults against a RustFS node on this machine, through the Linux
# head's own storage code (the interop driver) and its own pepper derivation.
#   ./linux/recovery-drill.sh        about two minutes and 4 GiB of memory
# The lost security key is drilled by `cargo test -p keptino drill`.
#
#   1. A lost machine: a fresh home re-derives the pepper from the seed and
#      opens the bucket copy.
#   2. A wrong seed: the vault stays shut and nothing is written.
#   3. A local copy damaged beyond repair: the bucket copy is adopted.
#   4. A stale device: the newer bucket copy wins over its own older one.
#   5. A bucket copy damaged beyond repair: the local copy opens.
set -euo pipefail
if [[ ${KEPTINO_HEAVY_ENTRY:-} != "$$" && -x "$(dirname -- "$0")/../ci/heavy" ]]; then
	exec "$(dirname -- "$0")/../ci/heavy" bash "$0" "$@"
fi
cd "$(dirname "$0")/.."
root=$PWD
command -v rustfs >/dev/null || { echo "rustfs is not installed"; exit 2; }
work=$(mktemp -d)
rustfs_pid=
cleanup() {
	[[ -n $rustfs_pid ]] && kill "$rustfs_pid" 2>/dev/null
	[[ -n ${KEEP_WORK:-} ]] || rm -rf "$work"
}
trap cleanup EXIT
say() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*"; tail -5 "$work/driver.log" 2>/dev/null; exit 1; }

bucket=keptino-drill
region=us-east-1
access_key=rustfsadmin
secret_key=rustfsadmin
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
endpoint="http://127.0.0.1:$port"
mkdir -p "$work/volume"
RUSTFS_ACCESS_KEY=$access_key RUSTFS_SECRET_KEY=$secret_key \
	rustfs --address "127.0.0.1:$port" --region "$region" "$work/volume" >"$work/rustfs.log" 2>&1 &
rustfs_pid=$!
aws_curl() { # <method> <url> [file]
	local file=${3:-}
	curl -sS -o "$work/curl.out" -w '%{http_code}' --max-time 60 -X "$1" \
		--aws-sigv4 "aws:amz:$region:s3" -u "$access_key:$secret_key" \
		${file:+--data-binary "@$file"} "$2"
}
# The node answers before its access control is ready; retry the bucket.
code=
for _ in $(seq 100); do
	code=$(aws_curl PUT "$endpoint/$bucket" 2>/dev/null || true)
	[[ $code == 200 || $code == 409 ]] && break
	sleep 0.2
done
[[ $code == 200 || $code == 409 ]] || fail "RustFS did not create the bucket (HTTP $code)"
say "RustFS single node on $endpoint"

say 'Building the Linux driver and the pepper derivation'
cargo build -q -p interop --bin linux-vault
cargo build --release -q -p keptino --bin keptino
target_dir=${CARGO_TARGET_DIR:-$root/target}
driver=$target_dir/debug/linux-vault
keptino=$target_dir/release/keptino
mkdir -p "$work/bin"
# systemd-creds stands in as the file itself: the drill is about the seed
# and the copies, not the TPM.
printf '#!/bin/sh\nexec cat "$4"\n' >"$work/bin/systemd-creds"
chmod +x "$work/bin/systemd-creds"

seed="drill seed $$ $(date +%s)"
password='drill horse battery staple'
db=drill$$
derive_pepper() { printf '%s' "$1" | "$keptino" --derive-pepper 2>>"$work/driver.log"; }
# A machine: a home with a pepper and the bucket's credentials.
machine() { # <name> <pepper hex>
	local home=$work/$1
	mkdir -p "$home/.config/keptino"
	printf '%s\n' "$2" >"$home/.config/keptino/pepper.cred"
	printf 's3\n' >"$home/.config/keptino/storage-provider"
	printf '%s\0%s\0%s\0%s\0%s' "$endpoint" "$bucket" "$region" "$access_key" "$secret_key" \
		>"$home/.config/keptino/s3.cred"
}
on() { # <machine> <command> [entries json on stdin]
	env HOME="$work/$1" PATH="$work/bin:$PATH" "$driver" "$2" "$db" "$password" 2>>"$work/driver.log"
}
local_file() { printf '%s/%s/.config/keptino/%s.keptino' "$work" "$1" "$db"; }
password_of() { # <machine> <entry>
	on "$1" read </dev/null | python3 -c 'import json, sys; print({e["name"]: e["password"] for e in json.load(sys.stdin)}.get(sys.argv[1], ""))' "$2"
}
# Overwrites the first five of the twelve shards: one more than repair takes.
damage() { python3 - "$1" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
shard = len(data) // 12
data[:5 * shard] = bytes(5 * shard)
open(path, 'wb').write(data)
PY
}

say 'Before: machine A creates the vault from the seed'
pepper_a=$(derive_pepper "$seed")
[[ $pepper_a =~ ^[0-9a-f]{64}$ ]] || fail "no pepper derived"
machine a "$pepper_a"
printf '[{"name":"bank","username":"a","password":"one"}]' | on a create || fail "create"
printf '[{"name":"bank","username":"a","password":"two"}]' | on a write || fail "write"
ok "machine A saved revision 2"

say '1. A lost machine: the seed rebuilds the pepper on a fresh home'
pepper_b=$(derive_pepper "$seed")
[[ $pepper_b == "$pepper_a" ]] || fail "the seed derived a different pepper"
machine b "$pepper_b"
[[ $(password_of b bank) == two ]] || fail "the new machine did not open the bucket copy"
printf '[{"name":"bank","username":"a","password":"three"}]' | on b write || fail "write on B"
[[ -e $(local_file b) ]] || fail "the bucket copy was not kept locally after save"
ok "machine B opened the bucket copy with the rebuilt pepper and saved revision 3"

say '2. A wrong seed: the vault stays shut'
machine c "$(derive_pepper "$seed.")"
set +e
on c read </dev/null >/dev/null
rc=$?
set -e
[[ $rc == 4 ]] || fail "a wrong seed did not refuse the unlock (exit $rc)"
[[ ! -e $(local_file c) ]] || fail "a refused unlock wrote a local file"
ok "a seed one character off opens nothing and writes nothing"

say '3. A local copy damaged beyond repair: unlock refuses it; moving it aside recovers from the bucket'
damage "$(local_file b)"
set +e
on b read </dev/null >/dev/null
rc=$?
set -e
[[ $rc != 0 ]] || fail "a damaged local copy opened without failing closed"
mv "$(local_file b)" "$(local_file b).corrupt"
[[ $(password_of b bank) == three ]] || fail "moving aside the damaged local copy did not recover from the bucket"
printf '[{"name":"bank","username":"a","password":"three"}]' | on b write || fail "heal write on B"
[[ -e $(local_file b) ]] || fail "save did not restore the local copy"
ok "damaged local file failed closed; moving it aside recovered rev 3 from the bucket"

say '4. A stale device: the newer bucket copy wins'
[[ $(password_of a bank) == three ]] || fail "machine A kept its older copy"
ok "machine A adopted revision 3 over its own revision 2"

say '5. A bucket copy damaged beyond repair: the local copy opens'
cp "$(local_file b)" "$work/object"
damage "$work/object"
code=$(aws_curl PUT "$endpoint/$bucket/$db.keptino" "$work/object")
[[ $code == 200 ]] || fail "could not damage the bucket copy (HTTP $code)"
[[ $(password_of b bank) == three ]] || fail "the local copy did not open"
ok "machine B opened its local copy past the damaged bucket copy"

say 'All recovery drills passed'
