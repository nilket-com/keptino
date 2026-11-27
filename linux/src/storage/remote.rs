use super::secret::SecretMemory;
use base64ct::{Base64, Encoding};
use libkeptino::s3;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::{
	fs, io,
	path::Path,
	process::Command,
	sync::Arc,
	time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;
const BAD_CREDENTIAL: &str = "Invalid storage credential. Run setup with --configure-storage.";
const B2_AUTH_URL: &str = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
	Backblaze,
	Aws,
	Gcs,
	R2,
	/// Any S3-compatible store at an endpoint the user names.
	S3,
}

impl Provider {
	fn selected(dir: &Path) -> Result<Self> {
		match fs::read_to_string(dir.join("storage-provider")) {
			Ok(name) => match name.trim_end_matches('\n') {
				"backblaze" => Ok(Self::Backblaze),
				"aws" => Ok(Self::Aws),
				"gcs" => Ok(Self::Gcs),
				"r2" => Ok(Self::R2),
				"s3" => Ok(Self::S3),
				_ => Err("Unknown storage provider. Run setup with --configure-storage.".into()),
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::Backblaze),
			Err(_) => Err("Cannot read the storage provider setting.".into()),
		}
	}

	fn name(self) -> &'static str {
		match self {
			Self::Backblaze => "backblaze",
			Self::Aws => "aws",
			Self::Gcs => "gcs",
			Self::R2 => "r2",
			Self::S3 => "s3",
		}
	}

	/// Hash of the encrypted credential file as written by setup.
	fn credential_file_hash(self, dir: &Path) -> Result<blake3::Hash> {
		let encrypted = fs::read(dir.join(format!("{}.cred", self.name())))
			.map_err(|_| format!("Cannot read the {} credential file.", self.name()))?;
		Ok(blake3::hash(&encrypted))
	}

	fn credentials(self, dir: &Path) -> Result<Zeroizing<Vec<u8>>> {
		let name = self.name();
		let output = Command::new(super::SYSTEMD_CREDS)
			.args(["decrypt", "--user", &format!("--name={name}")])
			.arg(dir.join(format!("{name}.cred")))
			.arg("-")
			.output()
			.map_err(|_| "Cannot run systemd-creds.")?;
		let bytes = Zeroizing::new(output.stdout);
		if !output.status.success() {
			return Err(format!("Cannot decrypt {name} credentials."));
		}
		Ok(bytes)
	}

	async fn request(
		self,
		credentials: &[u8],
		db_name: &str,
		body: Option<String>,
		precondition: Precondition<'_>,
	) -> Result<Response> {
		// Plaintext is refused, except that a debug build may talk to a store
		// on the loopback address, as `libkeptino::s3::validate_endpoint` allows
		// for the RustFS check; a release build never does.
		let loopback_http = cfg!(debug_assertions)
			&& self == Self::S3
			&& std::str::from_utf8(credentials)
				.ok()
				.and_then(|c| c.split('\0').next())
				.is_some_and(|e| {
					e.starts_with("http://127.0.0.1") || e.starts_with("http://localhost")
				});
		let client = Client::builder()
			.https_only(!loopback_http)
			.redirect(reqwest::redirect::Policy::none())
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|_| "Cannot initialize the storage connection.")?;
		let fields: Vec<_> = std::str::from_utf8(credentials)
			.map_err(|_| BAD_CREDENTIAL)?
			.split('\0')
			.collect();
		let key = format!("{db_name}.keptino");
		let req = match fields.as_slice() {
			[_, id, secret] if self == Self::Backblaze && !id.is_empty() && !secret.is_empty() => {
				backblaze_request(&client, id, secret, &s3::encode_segment(&key), body).await?
			}
			[bucket, location, id, secret] if matches!(self, Self::Aws | Self::Gcs | Self::R2) => {
				let (endpoint, region) = self.endpoint(location)?;
				let endpoint = s3::validate_endpoint(&endpoint).map_err(|_| BAD_CREDENTIAL)?;
				s3_request(
					&client,
					&endpoint,
					bucket,
					&key,
					region,
					id,
					secret,
					body,
					precondition,
				)?
			}
			[..] if self == Self::S3 => {
				let (endpoint, bucket, region, id, secret) = s3_fields(&fields)?;
				s3_request(
					&client,
					&endpoint,
					bucket,
					&key,
					region,
					id,
					secret,
					body,
					precondition,
				)?
			}
			_ => return Err(BAD_CREDENTIAL.into()),
		};
		req.send()
			.await
			.map_err(|_| format!("Could not reach {} storage.", self.name()))
	}

	fn endpoint(self, location: &str) -> Result<(String, &str)> {
		if location.is_empty()
			|| !location
				.bytes()
				.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
		{
			return Err(BAD_CREDENTIAL.into());
		}
		match self {
			Self::Aws => {
				let domain = if location.starts_with("cn-") {
					"amazonaws.com.cn"
				} else {
					"amazonaws.com"
				};
				Ok((format!("https://s3.{location}.{domain}"), location))
			}
			Self::Gcs => Ok(("https://storage.googleapis.com".into(), location)),
			Self::R2 if location.len() == 32 && location.bytes().all(|b| b.is_ascii_hexdigit()) => {
				Ok((
					format!("https://{location}.r2.cloudflarestorage.com"),
					"auto",
				))
			}
			_ => Err(BAD_CREDENTIAL.into()),
		}
	}

	async fn download(self, credentials: &[u8], db_name: &str) -> Result<Fetched> {
		let resp = self
			.request(credentials, db_name, None, Precondition::None)
			.await?;
		let status = resp.status();
		let etag = resp
			.headers()
			.get(reqwest::header::ETAG)
			.and_then(|v| v.to_str().ok())
			.map(str::to_owned);
		if status == StatusCode::NOT_FOUND {
			let bytes = bounded_body(resp, "storage response").await?;
			if self.missing_key(&bytes) {
				return Ok(Fetched {
					bytes: None,
					etag: None,
					conditional: self != Self::Backblaze,
				});
			}
		} else if status == StatusCode::OK {
			let body = bounded_body(resp, "vault download").await?;
			let text = std::str::from_utf8(&body).map_err(|_| "Invalid remote vault encoding.")?;
			let data = Base64::decode_vec(text).map_err(|_| "Invalid remote vault encoding.")?;
			return Ok(Fetched {
				bytes: Some(data),
				etag,
				conditional: self != Self::Backblaze,
			});
		}
		Err(format!(
			"{} download failed (HTTP {}).",
			self.name(),
			status.as_u16()
		))
	}

	fn missing_key(self, bytes: &[u8]) -> bool {
		if self == Self::Backblaze {
			#[derive(Deserialize)]
			struct StorageError {
				code: String,
			}
			serde_json::from_slice::<StorageError>(bytes).is_ok_and(|e| e.code == "not_found")
		} else {
			s3::is_missing_key(bytes)
		}
	}
}

/// What a fetch of the remote object came back with: the vault bytes, if
/// any, and the entity tag a later upload may condition on.
pub(super) struct Fetched {
	pub bytes: Option<Vec<u8>>,
	pub etag: Option<String>,
	/// Whether the store speaks S3, where a replacement must be conditioned
	/// on a strong entity tag from the very fetch that was compared.
	pub conditional: bool,
}

impl Fetched {
	/// The precondition a save over this fetch uses. An S3 object that came
	/// without a strong, quoted entity tag is not replaced at all: the save
	/// stays local rather than racing an unconditional write.
	pub fn precondition(&self) -> Result<Precondition<'_>> {
		match (&self.bytes, &self.etag, self.conditional) {
			(_, _, false) => Ok(Precondition::None),
			(None, _, true) => Ok(Precondition::Absent),
			(Some(_), Some(etag), true) if is_strong_etag(etag) => Ok(Precondition::Matches(etag)),
			(Some(_), _, true) => Err(
				"The store returned no usable entity tag for the vault object. Saved locally only; unlock again to retry."
					.into(),
			),
		}
	}
}

/// A strong entity tag: quoted, not weak (`W/`), not a wildcard, printable.
fn is_strong_etag(etag: &str) -> bool {
	etag.len() >= 3
		&& etag.starts_with('"')
		&& etag.ends_with('"')
		&& etag != "\"*\""
		&& etag[1..etag.len() - 1]
			.bytes()
			.all(|b| b.is_ascii_graphic() && b != b'"')
}

/// What an upload insists on at the store: the object as fetched, or its
/// absence. A store that ignores the header behaves as before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Precondition<'a> {
	None,
	/// `If-Match`: the object still has this entity tag.
	Matches(&'a str),
	/// `If-None-Match: *`: no object exists.
	Absent,
}

/// Vault objects are kilobytes to a few megabytes. This process cannot swap,
/// so a response is read in chunks and abandoned once it exceeds this bound
/// rather than trusting a Content-Length the server may omit.
const MAX_REMOTE_BYTES: usize = 64 << 20;

async fn bounded_body(mut resp: Response, what: &str) -> Result<Vec<u8>> {
	let too_large = || format!("The {what} exceeds {} MiB.", MAX_REMOTE_BYTES >> 20);
	if resp
		.content_length()
		.is_some_and(|len| len > MAX_REMOTE_BYTES as u64)
	{
		return Err(too_large());
	}
	let mut body = Vec::new();
	while let Some(chunk) = resp
		.chunk()
		.await
		.map_err(|_| format!("Incomplete {what}."))?
	{
		if body.len().saturating_add(chunk.len()) > MAX_REMOTE_BYTES {
			return Err(too_large());
		}
		body.extend_from_slice(&chunk);
	}
	Ok(body)
}

/// The storage session opened with this vault. The API credential is
/// decrypted once at unlock and kept in secret memory, so a save spawns no
/// helper and passes no plaintext through a pipe. The encrypted file is
/// hashed instead, so setup changing the configuration mid-session is still
/// noticed and forces a fresh unlock.
#[derive(Clone)]
pub(super) struct Remote {
	provider: Provider,
	credential: Arc<SecretMemory>,
	credential_file: blake3::Hash,
}

impl Remote {
	pub(super) async fn download(dir: &Path, db_name: &str) -> Result<(Self, Fetched)> {
		let provider = Provider::selected(dir)?;
		let credential_file = provider.credential_file_hash(dir)?;
		let credentials = provider.credentials(dir)?;
		let credential = SecretMemory::new(credentials.len().max(1))
			.and_then(|memory| memory.write(0, &credentials).map(|()| memory))
			.map_err(|_| "Cannot hold the storage credential in secret memory.")?;
		let remote = Self {
			provider,
			credential: Arc::new(credential),
			credential_file,
		};
		let fetched = provider.download(&credentials, db_name).await?;
		Ok((remote, fetched))
	}

	/// The session credential, after checking that setup has not replaced
	/// the provider or its credential file since unlock.
	fn session_credentials(&self, dir: &Path) -> Result<Zeroizing<Vec<u8>>> {
		if Provider::selected(dir)? != self.provider
			|| self.provider.credential_file_hash(dir)? != self.credential_file
		{
			return Err("Storage configuration changed. Unlock again before syncing.".into());
		}
		// A short-lived copy: the mapping's lock must not be held across a request.
		let mapped = self
			.credential
			.read()
			.map_err(|_| "Cannot read the storage credential from secret memory.")?;
		Ok(Zeroizing::new(mapped.to_vec()))
	}

	/// The current remote object, re-read with the configuration this vault
	/// was opened with, so a save can see what it is about to replace.
	pub(super) async fn fetch(&self, dir: &Path, db_name: &str) -> Result<Fetched> {
		let credentials = self.session_credentials(dir)?;
		self.provider.download(&credentials, db_name).await
	}

	/// Uploads over the object the save fetched, and no other: a store that
	/// honors the precondition answers 412 when the object changed meanwhile.
	pub(super) async fn upload(
		&self,
		dir: &Path,
		db_name: &str,
		bytes: &[u8],
		precondition: Precondition<'_>,
	) -> Result<()> {
		let credentials = self.session_credentials(dir)?;
		let response = self
			.provider
			.request(
				&credentials,
				db_name,
				Some(Base64::encode_string(bytes)),
				precondition,
			)
			.await?;
		// 412 is the precondition failing; S3 may answer 409 to a conditional
		// write that lost a race, or 404 to If-Match on an object deleted
		// meanwhile. Each means the object is not what was fetched.
		if precondition != Precondition::None
			&& matches!(
				response.status(),
				StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT | StatusCode::NOT_FOUND
			) {
			return Err("The remote vault changed since this session synced it. Saved locally only; unlock again to load the newer copy before uploading.".into());
		}
		if !response.status().is_success() {
			return Err(format!(
				"{} upload failed (HTTP {}).",
				self.provider.name(),
				response.status().as_u16()
			));
		}
		Ok(())
	}
}

/// The five fields of an `s3` credential, each checked as the request will
/// use it: endpoint, bucket, region, access key id, secret.
fn s3_fields<'a>(fields: &[&'a str]) -> Result<(s3::Endpoint, &'a str, &'a str, &'a str, &'a str)> {
	let [endpoint, bucket, region, id, secret] = fields else {
		return Err(BAD_CREDENTIAL.into());
	};
	let endpoint = s3::validate_endpoint(endpoint).map_err(|_| BAD_CREDENTIAL)?;
	s3::validate_bucket(bucket).map_err(|_| BAD_CREDENTIAL)?;
	if region.is_empty() || id.is_empty() || secret.is_empty() {
		return Err(BAD_CREDENTIAL.into());
	}
	Ok((endpoint, bucket, region, id, secret))
}

#[allow(clippy::too_many_arguments)]
fn s3_request(
	client: &Client,
	endpoint: &s3::Endpoint,
	bucket: &str,
	key: &str,
	region: &str,
	id: &str,
	secret: &str,
	body: Option<String>,
	precondition: Precondition<'_>,
) -> Result<RequestBuilder> {
	let method = if body.is_some() {
		s3::Method::Put
	} else {
		s3::Method::Get
	};
	let now = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or_default();
	let payload = body.as_deref().unwrap_or_default().as_bytes();
	let signed = s3::sign(
		method, endpoint, bucket, key, region, id, secret, payload, now,
	)
	.map_err(|_| BAD_CREDENTIAL)?;
	let mut req = client
		.request(
			if body.is_some() {
				Method::PUT
			} else {
				Method::GET
			},
			&signed.url,
		)
		.header("host", &signed.host)
		.header("x-amz-date", &signed.amz_date)
		.header("x-amz-content-sha256", &signed.content_sha256)
		.header("authorization", &signed.authorization);
	match precondition {
		Precondition::None => {}
		Precondition::Matches(etag) => req = req.header("if-match", etag),
		Precondition::Absent => req = req.header("if-none-match", "*"),
	}
	if let Some(body) = body {
		req = req.body(body);
	}
	Ok(req)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2Authorization {
	authorization_token: String,
	download_url: String,
	api_url: String,
	allowed: B2Bucket,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2Bucket {
	bucket_id: String,
	bucket_name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2Upload {
	authorization_token: String,
	upload_url: String,
}

async fn b2_json<T: serde::de::DeserializeOwned>(req: RequestBuilder) -> Result<T> {
	let resp = req.send().await.map_err(|_| "Could not reach Backblaze.")?;
	if !resp.status().is_success() {
		return Err(format!(
			"Backblaze request failed (HTTP {}).",
			resp.status().as_u16()
		));
	}
	resp.json()
		.await
		.map_err(|_| "Invalid Backblaze response. Check the bucket-scoped application key.".into())
}

async fn backblaze_request(
	client: &Client,
	id: &str,
	secret: &str,
	key: &str,
	body: Option<String>,
) -> Result<RequestBuilder> {
	let auth: B2Authorization =
		b2_json(client.get(B2_AUTH_URL).basic_auth(id, Some(secret))).await?;
	if let Some(body) = body {
		let upload: B2Upload = b2_json(
			client
				.post(format!("{}/b2api/v2/b2_get_upload_url", auth.api_url))
				.header("Authorization", auth.authorization_token)
				.json(&serde_json::json!({ "bucketId": auth.allowed.bucket_id })),
		)
		.await?;
		let checksum = hex::encode(Sha1::digest(body.as_bytes()));
		Ok(client
			.post(upload.upload_url)
			.header("Authorization", upload.authorization_token)
			.header("X-Bz-File-Name", key)
			.header("Content-Type", "text/plain")
			.header("X-Bz-Content-Sha1", checksum)
			.header("X-Bz-Info-Author", "Keptino")
			.header("X-Bz-Server-Side-Encryption", "AES256")
			.body(body))
	} else {
		Ok(client
			.get(format!(
				"{}/file/{}/{key}",
				auth.download_url, auth.allowed.bucket_name
			))
			.header("Authorization", auth.authorization_token))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signs_the_transmitted_path_and_body() {
		let client = Client::new();
		let endpoint = s3::validate_endpoint("https://s3.us-east-1.amazonaws.com").unwrap();
		for (body, precondition) in [
			(None, Precondition::None),
			(Some("ZmFrZQ=="), Precondition::Matches("\"abc\"")),
			(Some("ZmFrZQ=="), Precondition::Absent),
		] {
			let req = s3_request(
				&client,
				&endpoint,
				"vaults",
				"Team + 100% 🔑.digisafe",
				"us-east-1",
				"test-id",
				"test-secret",
				body.map(String::from),
				precondition,
			)
			.unwrap()
			.build()
			.unwrap();
			assert_eq!(
				req.url().path(),
				"/vaults/Team%20%2B%20100%25%20%F0%9F%94%91.digisafe"
			);
			assert_eq!(
				req.body().and_then(reqwest::Body::as_bytes),
				body.map(str::as_bytes)
			);
			let headers = req.headers();
			assert_eq!(headers["host"], "s3.us-east-1.amazonaws.com");
			assert!(
				headers["authorization"]
					.to_str()
					.unwrap()
					.starts_with("AWS4-HMAC-SHA256 Credential=test-id/")
			);
			assert_eq!(
				headers.get("if-match").map(|v| v.to_str().unwrap()),
				match precondition {
					Precondition::Matches(tag) => Some(tag),
					_ => None,
				}
			);
			assert_eq!(
				headers.get("if-none-match").map(|v| v.to_str().unwrap()),
				matches!(precondition, Precondition::Absent).then_some("*")
			);
		}
	}

	#[test]
	fn the_s3_credential_needs_all_five_fields_checked() {
		let parse = |credential: &str| {
			let fields: Vec<&str> = credential.split('\0').collect();
			s3_fields(&fields).map(|(endpoint, bucket, region, id, _)| {
				(
					endpoint.host().to_owned(),
					bucket.to_owned(),
					region.to_owned(),
					id.to_owned(),
				)
			})
		};
		assert_eq!(
			parse("https://strix:9000/\0keptino\0us-east-1\0id\0secret").unwrap(),
			(
				"strix:9000".to_string(),
				"keptino".into(),
				"us-east-1".into(),
				"id".into()
			)
		);
		for bad in [
			"https://host\0bucket\0us-east-1\0id",
			"ftp://host\0bucket\0us-east-1\0id\0secret",
			"https://host/x\0bucket\0us-east-1\0id\0secret",
			"https://host\0Bucket\0us-east-1\0id\0secret",
			"https://host\0bucket\0\0id\0secret",
			"https://host\0bucket\0us-east-1\0\0secret",
		] {
			assert_eq!(parse(bad).err().as_deref(), Some(BAD_CREDENTIAL), "{bad}");
		}
	}

	#[test]
	fn an_s3_object_is_replaced_only_under_a_strong_entity_tag() {
		let fetched = |bytes: Option<Vec<u8>>, etag: Option<&str>, conditional: bool| Fetched {
			bytes,
			etag: etag.map(str::to_owned),
			conditional,
		};
		assert_eq!(
			fetched(None, None, true).precondition().unwrap(),
			Precondition::Absent
		);
		assert_eq!(
			fetched(Some(vec![1]), Some("\"abc123\""), true)
				.precondition()
				.unwrap(),
			Precondition::Matches("\"abc123\"")
		);
		for unusable in [
			None,
			Some(""),
			Some("abc"),
			Some("W/\"abc\""),
			Some("\"*\""),
			Some("\"\""),
		] {
			let err = fetched(Some(vec![1]), unusable, true)
				.precondition()
				.unwrap_err();
			assert!(err.contains("no usable entity tag"), "{unusable:?}: {err}");
		}
		// Backblaze has its own API and no conditional write; nothing is required.
		assert_eq!(
			fetched(Some(vec![1]), None, false).precondition().unwrap(),
			Precondition::None
		);
	}

	#[test]
	fn only_provider_missing_object_errors_can_start_a_vault() {
		for provider in [Provider::Aws, Provider::Gcs, Provider::R2, Provider::S3] {
			assert!(provider.missing_key(b"<Error><Code>NoSuchKey</Code></Error>"));
			assert!(!provider.missing_key(b"<Error><Code>NoSuchBucket</Code></Error>"));
			assert!(!provider.missing_key(b""));
		}
		assert!(Provider::Backblaze.missing_key(br#"{"code":"not_found"}"#));
		assert!(!Provider::Backblaze.missing_key(br#"{"code":"unauthorized"}"#));
	}
}
