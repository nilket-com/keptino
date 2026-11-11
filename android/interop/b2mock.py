#!/usr/bin/env python3
"""A local stand-in for the Backblaze B2 calls DigiSafe makes.

Plain HTTP for the Android app (point its B2 base URL here; from the
emulator the host is 10.0.2.2). With --tls-cert/--tls-key it is also an
HTTPS proxy that answers for every host, so the unmodified Linux code,
which only knows https://api.backblazeb2.com, reaches it through
HTTPS_PROXY with the test CA in SSL_CERT_FILE.

Objects are files in --dir holding the uploaded body, as B2 would.
"""
import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BUCKET_ID = "mockbucket0001"
BUCKET_NAME = "digisafe"
ACCOUNT_TOKEN = "mock-account-token"
UPLOAD_TOKEN = "mock-upload-token"


class Handler(BaseHTTPRequestHandler):
	protocol_version = "HTTP/1.1"
	scheme = "http"

	def log_message(self, fmt, *args):
		sys.stderr.write("b2mock: " + fmt % args + "\n")

	def reply(self, status, payload, content_type="application/json"):
		body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
		self.send_response(status)
		self.send_header("Content-Type", content_type)
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def fail(self, status, code, message):
		self.reply(status, {"status": status, "code": code, "message": message})

	def base(self):
		return f"{self.scheme}://{self.headers.get('Host', 'localhost')}"

	def body(self):
		return self.rfile.read(int(self.headers.get("Content-Length", "0")))

	def authorized(self, token):
		if self.headers.get("Authorization") == token:
			return True
		self.fail(401, "unauthorized", "Invalid authorization token")
		return False

	def object_path(self, name):
		name = urllib.parse.unquote(name)
		if not name or "/" in name or name.startswith("."):
			return None
		return os.path.join(self.server.directory, name)

	def do_CONNECT(self):
		if self.server.tls is None:
			return self.fail(405, "method_not_allowed", "Started without TLS")
		self.send_response(200, "Connection established")
		self.end_headers()
		try:
			self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
		except (ssl.SSLError, OSError) as error:
			self.log_message("TLS handshake failed: %s", error)
			self.close_connection = True
			return
		self.rfile = self.connection.makefile("rb")
		self.wfile = self.connection.makefile("wb", 0)
		self.scheme = "https"

	def do_GET(self):
		path = urllib.parse.urlsplit(self.path).path
		if path == "/b2api/v2/b2_authorize_account":
			expected = base64.b64encode(self.server.credentials.encode()).decode()
			if self.headers.get("Authorization") != f"Basic {expected}":
				return self.fail(401, "bad_auth_token", "Invalid application key")
			return self.reply(200, {
				"accountId": "mockaccount",
				"authorizationToken": ACCOUNT_TOKEN,
				"apiUrl": self.base(),
				"downloadUrl": self.base(),
				"allowed": {"bucketId": BUCKET_ID, "bucketName": BUCKET_NAME},
			})
		prefix = f"/file/{BUCKET_NAME}/"
		if path.startswith(prefix):
			if not self.authorized(ACCOUNT_TOKEN):
				return
			target = self.object_path(path[len(prefix):])
			if target is None or not os.path.isfile(target):
				return self.fail(404, "not_found", "File with such name does not exist.")
			with open(target, "rb") as file:
				return self.reply(200, file.read(), "text/plain")
		self.fail(404, "not_found", "Unknown path")

	def do_POST(self):
		path = urllib.parse.urlsplit(self.path).path
		body = self.body()
		if path == "/b2api/v2/b2_get_upload_url":
			if not self.authorized(ACCOUNT_TOKEN):
				return
			try:
				bucket = json.loads(body).get("bucketId")
			except (ValueError, AttributeError):
				bucket = None
			if bucket != BUCKET_ID:
				return self.fail(400, "bad_bucket_id", "Unknown bucket")
			return self.reply(200, {
				"bucketId": BUCKET_ID,
				"uploadUrl": f"{self.base()}/b2api/v2/b2_upload_file/{BUCKET_ID}",
				"authorizationToken": UPLOAD_TOKEN,
			})
		if path == f"/b2api/v2/b2_upload_file/{BUCKET_ID}":
			if not self.authorized(UPLOAD_TOKEN):
				return
			target = self.object_path(self.headers.get("X-Bz-File-Name", ""))
			if target is None:
				return self.fail(400, "bad_request", "Bad file name")
			sha1 = hashlib.sha1(body).hexdigest()
			if self.headers.get("X-Bz-Content-Sha1") != sha1:
				return self.fail(400, "bad_request", "Sha1 did not match data received")
			temporary = target + ".part"
			with open(temporary, "wb") as file:
				file.write(body)
			os.replace(temporary, target)
			return self.reply(200, {
				"fileId": "mock-" + sha1,
				"fileName": os.path.basename(target),
				"contentLength": len(body),
				"contentSha1": sha1,
			})
		self.fail(404, "not_found", "Unknown path")


def main():
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("--dir", required=True, help="directory holding the bucket's objects")
	parser.add_argument("--port", type=int, default=8787)
	parser.add_argument("--bind", default="127.0.0.1")
	parser.add_argument("--key-id", default="mock-key-id")
	parser.add_argument("--app-key", default="mock-app-key")
	parser.add_argument("--tls-cert", help="certificate chain for HTTPS proxy mode")
	parser.add_argument("--tls-key")
	args = parser.parse_args()
	os.makedirs(args.dir, exist_ok=True)
	server = ThreadingHTTPServer((args.bind, args.port), Handler)
	server.daemon_threads = True
	server.directory = args.dir
	server.credentials = f"{args.key_id}:{args.app_key}"
	server.tls = None
	if args.tls_cert:
		server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		server.tls.load_cert_chain(args.tls_cert, args.tls_key)
	print(f"b2mock listening on {args.bind}:{server.server_port}", flush=True)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass


if __name__ == "__main__":
	main()
