#!/usr/bin/env bash
# Runs the Linux head against a RustFS single node through the `s3`
# provider: missing object, upload, download, overwrite, a save refused
# because the object changed underneath, and the oversize bound. Three ways:
#   ./linux/rustfs-check.sh                  a node on this machine over
#                                            loopback HTTP (debug build only)
#   ./linux/rustfs-check.sh --remote HOST    a node started over ssh on HOST
#                                            over TLS, with a certificate
#                                            authority minted for this run
#                                            and trusted for this run alone
#   ./linux/rustfs-check.sh URL BUCKET ACCESS_KEY SECRET_KEY
#                                            a node you run, with a
#                                            certificate this machine trusts
set -euo pipefail
cd "$(dirname "$0")/.."

remote_host=
if [[ ${1:-} == --remote ]]; then
	remote_host=${2:?host}
	shift 2
fi
endpoint=${1:-}
bucket=${2:-keptino-check}
access_key=${3:-rustfsadmin}
secret_key=${4:-rustfsadmin}
region=us-east-1
work=$(mktemp -d)
rustfs_pid=
remote_dir=
tunnel_pid=
cleanup() {
	[[ -n "$rustfs_pid" ]] && kill "$rustfs_pid" 2>/dev/null
	[[ -n "$tunnel_pid" ]] && kill "$tunnel_pid" 2>/dev/null
	if [[ -n $remote_dir ]]; then
		ssh -o BatchMode=yes "$remote_host" "pkill -f 'rustfs --address :$port' 2>/dev/null; rm -rf '$remote_dir'" 2>/dev/null || true
	fi
	[[ -n ${KEEP_WORK:-} ]] || rm -rf "$work"
}
trap cleanup EXIT
say() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
curl_ca=()

if [[ -n $remote_host ]]; then
	# A certificate authority for this run only: the node's certificate names
	# the host, this machine trusts the authority through SSL_CERT_FILE, and
	# both are gone when the run ends. No public certificate is involved.
	say "Minting a run-only certificate authority for $remote_host"
	host_ip=$(getent ahostsv4 "$remote_host" | awk 'NR==1 {print $1}')
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-subj '/CN=keptino rustfs check CA' -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-subj "/CN=$remote_host" -keyout "$work/rustfs_key.pem" -out "$work/tls.csr" 2>/dev/null
	openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -days 2 \
		-extfile <(printf 'subjectAltName=DNS:%s,IP:%s,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$remote_host" "${host_ip:-127.0.0.1}") \
		-out "$work/rustfs_cert.pem" 2>/dev/null
	port=19000
	remote_dir=$(ssh -o BatchMode=yes "$remote_host" 'mktemp -d /tmp/keptino-rustfs.XXXXXX')
	ssh -o BatchMode=yes "$remote_host" "mkdir -p '$remote_dir/tls' '$remote_dir/volume'"
	scp -q "$work/rustfs_cert.pem" "$work/rustfs_key.pem" "$remote_host:$remote_dir/tls/"
	if ! ssh -o BatchMode=yes "$remote_host" 'command -v rustfs >/dev/null'; then
		say "Copying this machine's rustfs binary to $remote_host"
		scp -q "$(command -v rustfs)" "$remote_host:$remote_dir/rustfs"
		remote_bin="$remote_dir/rustfs"
	else
		remote_bin=rustfs
	fi
	say "Starting RustFS on $remote_host:$port over TLS"
	# Fully detached, or ssh waits on the server's inherited channel.
	ssh -o BatchMode=yes "$remote_host" "RUSTFS_ACCESS_KEY='$access_key' RUSTFS_SECRET_KEY='$secret_key' setsid nohup '$remote_bin' --address :$port --console-address :19001 --region '$region' --tls-path '$remote_dir/tls' '$remote_dir/volume' >'$remote_dir/rustfs.log' 2>&1 </dev/null &" 
	endpoint="https://$remote_host:$port"
	export SSL_CERT_FILE="$work/ca.pem"
	curl_ca=(--cacert "$work/ca.pem")
	# A host firewall that admits ssh alone still gets a real TLS session to
	# the node: the same port is reached through an ssh tunnel, and the
	# certificate names localhost for that case.
	if ! timeout 3 bash -c "exec 3<>/dev/tcp/$remote_host/$port" 2>/dev/null; then
		say "Port $port is closed from here; tunneling it over ssh"
		ssh -o BatchMode=yes -N -L "$port:127.0.0.1:$port" "$remote_host" &
		tunnel_pid=$!
		endpoint="https://localhost:$port"
	fi
	for _ in $(seq 100); do
		# A bounded probe: a port that accepts but does not yet serve must not
		# hold the loop.
		code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${curl_ca[@]}" "$endpoint/" 2>/dev/null || true)
		[[ $code =~ ^(200|400|403)$ ]] && break
		sleep 0.5
	done
	[[ $code =~ ^(200|400|403)$ ]] || { echo "RustFS on $remote_host did not answer over TLS (last HTTP '$code')"; ssh -o BatchMode=yes "$remote_host" "tail -5 '$remote_dir/rustfs.log'"; exit 1; }
	ok "RustFS answers over TLS with the run-only certificate"
elif [[ -z $endpoint ]]; then
	command -v rustfs >/dev/null || { echo "rustfs is not installed"; exit 2; }
	port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
	mkdir -p "$work/volume"
	RUSTFS_ACCESS_KEY=$access_key RUSTFS_SECRET_KEY=$secret_key \
		rustfs --address "127.0.0.1:$port" --region "$region" "$work/volume" >"$work/rustfs.log" 2>&1 &
	rustfs_pid=$!
	endpoint="http://127.0.0.1:$port"
	for _ in $(seq 100); do
		curl -fsS -o /dev/null "$endpoint/" 2>/dev/null && break
		curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$endpoint/" 2>/dev/null | grep -qE '^(403|400)$' && break
		sleep 0.1
	done
	say "RustFS single node on $endpoint"
fi

# A bucket, through the S3 API with a signature from the shared crate's
# test driver would be ideal; curl with AWS SigV4 does for the check.
aws_curl() { # <method> <url> [file]
	local method=$1 url=$2 file=${3:-}
	if [[ -n $file ]]; then
		curl -sS -o "$work/curl.out" -w '%{http_code}' --max-time 120 -X "$method" --aws-sigv4 "aws:amz:$region:s3" \
			"${curl_ca[@]}" -u "$access_key:$secret_key" --data-binary "@$file" "$url"
	else
		curl -sS -o "$work/curl.out" -w '%{http_code}' --max-time 60 -X "$method" --aws-sigv4 "aws:amz:$region:s3" \
			"${curl_ca[@]}" -u "$access_key:$secret_key" "$url"
	fi
}
code=$(aws_curl PUT "$endpoint/$bucket")
[[ $code == 200 || $code == 409 ]] || { echo "cannot create bucket: HTTP $code"; cat "$work/curl.out"; exit 1; }
ok "bucket $bucket present"

say 'Building the Linux driver'
cargo build -q -p interop --bin linux-vault
bin=target/debug/linux-vault

# What setup.sh stores, minus the TPM: systemd-creds is replaced by a
# script that prints the file, as the interop harness does.
mkdir -p "$work/bin" "$work/home/.config/keptino"
printf '#!/bin/sh\nexec cat "$4"\n' >"$work/bin/systemd-creds"
chmod +x "$work/bin/systemd-creds"
# A fixed test pepper: the check is about the store, not the derivation.
printf '%s\n' "$(python3 -c 'print("ab"*32)')" >"$work/home/.config/keptino/pepper.cred"
printf 's3\n' >"$work/home/.config/keptino/storage-provider"
printf '%s\0%s\0%s\0%s\0%s' "$endpoint" "$bucket" "$region" "$access_key" "$secret_key" >"$work/home/.config/keptino/s3.cred"
db=check$$
password='correct horse battery staple'
linux() {
	# SSL_CERT_FILE, when set above, names the run-only authority.
	env HOME="$work/home" PATH="$work/bin:$PATH" "$bin" "$@" 2>>"$work/linux.log"
}

say 'Missing object: Unlock reports it and creates nothing (ADR 0018)'
set +e
printf '[]' | linux write "$db" "$password"
rc=$?
set -e
[[ $rc == 4 ]] || { echo "unlock of a missing name did not fail (exit $rc)"; tail -5 "$work/linux.log"; exit 1; }
grep -q "No vault named \"$db\" exists" "$work/linux.log" || { echo "the refusal did not name the missing vault"; tail -5 "$work/linux.log"; exit 1; }
code=$(aws_curl GET "$endpoint/$bucket/$db.keptino")
[[ $code == 404 ]] || { echo "unlock wrote to the bucket: HTTP $code"; exit 1; }
[[ ! -e $work/home/.config/keptino/$db.keptino && ! -e $work/home/.config/keptino/$db.revision ]] || { echo "unlock wrote a local file"; exit 1; }
ok 'unlock of a missing name wrote nothing'

say 'Create: the new vault reaches the bucket, then the local file at revision one'
printf '[{"name":"first","username":"a","password":"one"}]' | linux create "$db" "$password"
code=$(aws_curl GET "$endpoint/$bucket/$db.keptino")
[[ $code == 200 ]] || { echo "upload missing: HTTP $code"; cat "$work/linux.log"; exit 1; }
cp "$work/curl.out" "$work/first.b64"
# create uploads revision 1, and the entries save as revision 2.
[[ $(cat "$work/home/.config/keptino/$db.revision") == 2 ]] || { echo "unexpected revision record"; exit 1; }
linux read "$db" "$password" | grep -q '"first"' || { echo "the created vault did not reopen"; exit 1; }
ok 'created, saved and reopened'

say 'Create again: refused by the local file, then by the bucket object'
set +e
printf '[]' | linux create "$db" "$password"; rc_local=$?
mv "$work/home/.config/keptino" "$work/home/kept"
mkdir -p "$work/home/.config/keptino"
cp "$work/home/kept/"{pepper.cred,storage-provider,s3.cred} "$work/home/.config/keptino/"
printf '[]' | linux create "$db" "$password"; rc_bucket=$?
set -e
[[ $rc_local == 4 && $rc_bucket == 4 ]] || { echo "a second create was not refused ($rc_local, $rc_bucket)"; tail -5 "$work/linux.log"; exit 1; }
grep -q "was used here" "$work/linux.log" && grep -q "already exists in the bucket" "$work/linux.log" || { echo "the refusals did not name their reason"; tail -5 "$work/linux.log"; exit 1; }
[[ ! -e $work/home/.config/keptino/$db.keptino && ! -e $work/home/.config/keptino/$db.revision ]] || { echo "a refused create wrote a local file"; exit 1; }
rm -r "$work/home/.config/keptino"; mv "$work/home/kept" "$work/home/.config/keptino"
aws_curl GET "$endpoint/$bucket/$db.keptino" >/dev/null
cmp -s "$work/curl.out" "$work/first.b64" || { echo "a refused create changed the bucket"; exit 1; }
ok 'both duplicates refused, nothing written'

say 'Create precondition: does this store honor If-None-Match?'
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 "aws:amz:$region:s3" "${curl_ca[@]}" -u "$access_key:$secret_key" \
	-H 'If-None-Match: *' --data-binary "@$work/first.b64" "$endpoint/$bucket/$db.keptino")
if [[ $code == 412 || $code == 409 ]]; then
	ok "the store refuses a create-only PUT over an existing object ($code)"
else
	echo "note: the store answered HTTP $code to If-None-Match over an existing object; the fetch before create alone protects this store"
fi

say 'Download: the same vault opens from the bucket alone'
rm "$work/home/.config/keptino/$db.keptino" "$work/home/.config/keptino/$db.revision"
linux read "$db" "$password" | grep -q '"first"' || { echo "remote copy did not open"; cat "$work/linux.log"; exit 1; }
ok 'the bucket copy opened without a local file'

say 'Overwrite: a second save replaces the object'
printf '[{"name":"second","username":"b","password":"two"}]' | linux write "$db" "$password"
code=$(aws_curl GET "$endpoint/$bucket/$db.keptino")
[[ $code == 200 ]] && ! cmp -s "$work/curl.out" "$work/first.b64" || { echo "overwrite failed: HTTP $code"; exit 1; }
linux read "$db" "$password" | grep -q '"second"' || { echo "overwritten copy did not open"; exit 1; }
ok 'overwrite landed and reopens'

say 'Conflict: an object changed between the open and the save is not overwritten'
aws_curl GET "$endpoint/$bucket/$db.keptino" >/dev/null; cp "$work/curl.out" "$work/before.b64"
plant="cd '$PWD' && curl -sS -o /dev/null -X PUT --aws-sigv4 'aws:amz:$region:s3' ${curl_ca[*]} -u '$access_key:$secret_key' --data-binary '@$work/first.b64' '$endpoint/$bucket/$db.keptino'"
set +e
printf '[{"name":"third","username":"c","password":"three"}]' | KEPTINO_INTEROP_BETWEEN="$plant" linux write "$db" "$password"
rc=$?
set -e
[[ $rc == 3 ]] || { echo "the conflicting write was not refused (exit $rc)"; tail -5 "$work/linux.log"; exit 1; }
grep -q "changed since this session synced it" "$work/linux.log" || { echo "the refusal did not name the conflict"; tail -5 "$work/linux.log"; exit 1; }
aws_curl GET "$endpoint/$bucket/$db.keptino" >/dev/null
cmp -s "$work/curl.out" "$work/first.b64" || { echo "the planted copy was overwritten"; exit 1; }
ok 'the save over a changed object stayed local'

say 'Write precondition: does this store honor If-Match?'
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 "aws:amz:$region:s3" "${curl_ca[@]}" -u "$access_key:$secret_key" \
	-H 'If-Match: "0000000000000000000000000000dead"' --data-binary "@$work/before.b64" "$endpoint/$bucket/$db.keptino")
if [[ $code == 412 ]]; then
	ok 'the store refuses a PUT whose If-Match does not hold (412)'
else
	echo "note: the store answered HTTP $code to a stale If-Match; the fetch-and-compare guard alone protects this store"
fi
# Put the vault back as the last save left it, so the next step has a valid object.
aws_curl PUT "$endpoint/$bucket/$db.keptino" "$work/before.b64" >/dev/null

say 'Oversize: a body over the bound is refused'
head -c $((65 << 20)) /dev/zero | tr '\0' 'A' >"$work/big"
code=$(aws_curl PUT "$endpoint/$bucket/$db.keptino" "$work/big")
if [[ $code == 200 ]]; then
	rm -f "$work/home/.config/keptino/$db.keptino"
	if linux read "$db" "$password" >/dev/null 2>>"$work/linux.log"; then echo "an oversize object was accepted"; exit 1; fi
	grep -q "exceeds" "$work/linux.log" || { echo "oversize refusal not reported"; tail -3 "$work/linux.log"; exit 1; }
	ok 'the oversize object was refused before it was read in'
else
	ok "the store itself refused the oversize object (HTTP $code)"
fi
aws_curl DELETE "$endpoint/$bucket/$db.keptino" >/dev/null || true
say 'All RustFS checks passed'
