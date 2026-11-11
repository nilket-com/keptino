#!/usr/bin/env bash
# Proves the Android core and the Linux application read each other's
# vaults, using the Linux storage code unmodified against a mock Backblaze.
#
#   ./run.sh              debug KDF (4 MiB), a few seconds
#   ./run.sh release      release KDF (4 GiB of memory per unlock)
#   ./run.sh fixtures     both, and rewrite ../droid/tests/fixtures
#   ./run.sh check <file> [debug|release]
#                         have Linux open a vault file saved elsewhere (by
#                         the app on a device, say) with the fixture password
#                         and pepper, and print its entries
set -euo pipefail
cd "$(dirname "$0")"

PASSWORD='correct horse battery staple'
PEPPER_SEED='digisafe test pepper seed'
KEY_ID=mock-key-id
APP_KEY=mock-app-key

work=$(mktemp -d)
mock_pid=
cleanup() {
	[[ -n "$mock_pid" ]] && kill "$mock_pid" 2>/dev/null
	rm -rf -- "$work"
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }

# A CA the Linux code is told to trust, and a certificate for Backblaze's
# hosts signed by it.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
	-subj '/CN=DigiSafe test CA' -addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign' \
	-keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-subj '/CN=api.backblazeb2.com' -keyout "$work/tls.key" -out "$work/tls.csr" 2>/dev/null
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -days 2 \
	-extfile <(printf 'subjectAltName=DNS:api.backblazeb2.com,DNS:*.backblazeb2.com\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n') \
	-out "$work/tls.pem" 2>/dev/null

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 b2mock.py --dir "$work/bucket" --port "$port" --key-id "$KEY_ID" --app-key "$APP_KEY" \
	--tls-cert "$work/tls.pem" --tls-key "$work/tls.key" >"$work/mock.out" 2>"$work/mock.log" &
mock_pid=$!
for _ in $(seq 50); do
	grep -q listening "$work/mock.out" 2>/dev/null && break
	sleep 0.1
done
mock="http://127.0.0.1:$port"

# What linux/setup.sh stores, minus the TPM: `systemd-creds decrypt` is
# replaced by a script that prints the file.
say 'Deriving the pepper as linux/setup.sh does (4 GiB)'
pepper=$(printf '%s' "$PEPPER_SEED" | argon2 digipepper -id -t 4 -m 22 -p 1 -l 32 -r -v 13)
mkdir -p "$work/bin" "$work/home/.config/digisafe"
printf '#!/bin/sh\nexec cat "$4"\n' >"$work/bin/systemd-creds"
chmod +x "$work/bin/systemd-creds"
printf '%s\n' "$pepper" >"$work/home/.config/digisafe/digipepper.cred"
printf 'mock\0%s\0%s' "$KEY_ID" "$APP_KEY" >"$work/home/.config/digisafe/backblaze.cred"

linux() {
	env HOME="$work/home" PATH="$work/bin:$PATH" SSL_CERT_FILE="$work/ca.pem" \
		HTTPS_PROXY="$mock" https_proxy="$mock" NO_PROXY= no_proxy= \
		"$bin/linux-vault" "$@" 2>>"$work/linux.log"
}
android() { "$bin/android-vault" "$@"; }

# The phone's side of a sync, as plain B2 calls.
b2_token() {
	curl -fsS -u "$KEY_ID:$APP_KEY" "$mock/b2api/v2/b2_authorize_account" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["authorizationToken"])'
}
b2_download() { # <db> <file>
	curl -fsS -H "Authorization: $(b2_token)" "$mock/file/digisafe/$1.digisafe" | base64 -d >"$2"
}
b2_upload() { # <db> <file>
	local reply url token
	reply=$(curl -fsS -H "Authorization: $(b2_token)" -d '{"bucketId":"mockbucket0001"}' "$mock/b2api/v2/b2_get_upload_url")
	url=$(python3 -c 'import json, sys; print(json.load(sys.stdin)["uploadUrl"])' <<<"$reply")
	token=$(python3 -c 'import json, sys; print(json.load(sys.stdin)["authorizationToken"])' <<<"$reply")
	base64 -w 0 "$2" >"$work/upload.b64"
	curl -fsS -o /dev/null -H "Authorization: $token" -H "X-Bz-File-Name: $1.digisafe" \
		-H 'Content-Type: text/plain' -H "X-Bz-Content-Sha1: $(sha1sum <"$work/upload.b64" | cut -d' ' -f1)" \
		--data-binary "@$work/upload.b64" "$url"
}

same() { # <description> <json> <json>
	python3 - "$@" <<'PY'
import json, sys
what, left, right = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
key = lambda entry: entry["name"]
if sorted(left, key=key) != sorted(right, key=key):
	print(f"MISMATCH: {what}\n  {left}\n  {right}")
	sys.exit(1)
print(f"ok: {what} ({len(left)} entries)")
PY
}

expect() { # <description> <entries json> <name> <field> <value>
	python3 - "$@" <<'PY'
import json, sys
what, entries, name, field, value = sys.argv[1:]
found = [entry for entry in json.loads(entries) if entry["name"] == name]
if len(found) != 1 or found[0][field] != value:
	print(f"MISMATCH: {what}: {found}")
	sys.exit(1)
print(f"ok: {what}")
PY
}

roundtrip() { # <profile> <mem-kib> [fixture directory]
	local profile=$1 mem=$2 fixtures=${3:-} db="vault$1" flag=()
	[[ $profile == release ]] && flag=(--release)
	say "Building the $profile harness"
	cargo build --quiet --locked "${flag[@]}"
	bin=target/$profile
	local file="$work/home/.config/digisafe/$db.digisafe" phone="$work/phone-$db.digisafe"

	say "[$profile] Linux creates the vault and uploads it"
	linux write "$db" "$PASSWORD" <entries.json
	cmp <(base64 -d "$work/bucket/$db.digisafe") "$file"
	echo 'ok: the bucket holds base64 of the local file'
	local written
	written=$(linux read "$db" "$PASSWORD")
	same 'Linux reads back what it wrote' "$(cat entries.json)" "$written"
	if [[ -n $fixtures ]]; then
		cp "$file" "$fixtures/linux-$profile.digisafe"
	fi

	say "[$profile] Android downloads and opens it"
	b2_download "$db" "$phone"
	same 'Android reads the Linux vault' "$written" "$(android read "$phone" "$PASSWORD" "$pepper" "$mem")"
	if android read "$phone" 'wrong password' "$pepper" "$mem" >/dev/null 2>&1; then
		echo 'MISMATCH: a wrong password opened the vault'
		exit 1
	fi
	echo 'ok: Android refuses a wrong password'

	say "[$profile] Android edits one entry, adds one, saves and uploads"
	android write "$phone" "$PASSWORD" "$pepper" "$mem" <<'JSON'
[
	{"name": "bank", "password": "changed on the phone ☎", "note": "edited\non Android"},
	{"name": "phone-only", "username": "bob", "password": "new entry", "pin": "77", "note": "", "url": "", "tags": "phone, work"}
]
JSON
	b2_upload "$db" "$phone"
	local edited
	edited=$(android read "$phone" "$PASSWORD" "$pepper" "$mem")

	say "[$profile] Linux opens the newer remote copy"
	local seen
	seen=$(linux read "$db" "$PASSWORD")
	grep -q 'Remote database loaded\.' "$work/linux.log" || { echo 'MISMATCH: Linux did not take the remote copy'; exit 1; }
	same 'Linux reads the Android vault' "$edited" "$seen"
	expect 'the edit made on Android' "$seen" bank password 'changed on the phone ☎'
	expect 'fields Android left alone' "$seen" bank pin 4921
	expect 'the entry added on Android' "$seen" phone-only tags 'phone, work'
	expect 'untouched entries' "$seen" wifi password 'p@ss w0rd'

	say "[$profile] Linux edits and saves on top of it; Android reads that"
	linux write "$db" "$PASSWORD" <<'JSON'
[{"name": "phone-only", "username": "bob", "password": "changed on the desktop", "pin": "77", "note": "", "url": "", "tags": "phone, work"}]
JSON
	b2_download "$db" "$phone"
	local final
	final=$(android read "$phone" "$PASSWORD" "$pepper" "$mem")
	same 'Android reads the vault Linux saved over its own' "$(linux read "$db" "$PASSWORD")" "$final"
	expect 'the edit made on Linux' "$final" phone-only password 'changed on the desktop'
	expect 'the earlier Android edit' "$final" bank note $'edited\non Android'
}

check() { # <file> <profile>
	local profile=$2 db flag=()
	db=$(basename "$1" .digisafe)
	[[ $profile == release ]] && flag=(--release)
	cargo build --quiet --locked "${flag[@]}"
	bin=target/$profile
	# Only in the bucket, so Linux must fetch and decrypt it.
	base64 -w 0 "$1" >"$work/bucket/$db.digisafe"
	linux read "$db" "$PASSWORD" || { cat "$work/linux.log" >&2; exit 1; }
}

case "${1:-debug}" in
	check)
		check "${2:?vault file}" "${3:-debug}"
		exit 0
		;;
	debug) roundtrip debug 4096 ;;
	release) roundtrip release 4194304 ;;
	fixtures)
		fixtures=../droid/tests/fixtures
		mkdir -p "$fixtures"
		roundtrip debug 4096 "$fixtures"
		roundtrip release 4194304 "$fixtures"
		python3 - "$fixtures/manifest.json" "$PASSWORD" "$PEPPER_SEED" "$pepper" <<'PY'
import json, sys
path, password, seed, pepper = sys.argv[1:]
manifest = {
	"password": password,
	"pepper_seed": seed,
	"pepper_hex": pepper,
	"vaults": {"linux-debug.digisafe": {"mem_kib": 4096}, "linux-release.digisafe": {"mem_kib": 4194304}},
	"entries": json.load(open("entries.json")),
}
with open(path, "w") as file:
	json.dump(manifest, file, ensure_ascii=False, indent="\t")
	file.write("\n")
PY
		echo "Fixtures written to $fixtures"
		;;
	*) sed -n '2,11p' "$0" >&2; exit 2 ;;
esac
say 'All interoperability checks passed'
