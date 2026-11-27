use super::secret::SecretMemory;
use aws_credential_types::Credentials;
use aws_sigv4::{
	http_request::{
		PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
		UriPathNormalizationMode, sign,
	},
	sign::v4,
};
use base64ct::{Base64, Encoding};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
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
const KEY_CHARS: &AsciiSet = &NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~');
const BAD_CREDENTIAL: &str = "Invalid storage credential. Run setup with --configure-storage.";
const B2_AUTH_URL: &str = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
	Backblaze,
	Aws,
	Gcs,
	R2,
}

impl Provider {
	fn selected(dir: &Path) -> Result<Self> {
		match fs::read_to_string(dir.join("storage-provider")) {
			Ok(name) => match name.trim_end_matches('\n') {
				"backblaze" => Ok(Self::Backblaze),
				"aws" => Ok(Self::Aws),
				"gcs" => Ok(Self::Gcs),
				"r2" => Ok(Self::R2),
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
	) -> Result<Response> {
		let client = Client::builder()
			.https_only(true)
			.redirect(reqwest::redirect::Policy::none())
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|_| "Cannot initialize the storage connection.")?;
		let fields: Vec<_> = std::str::from_utf8(credentials)
			.map_err(|_| BAD_CREDENTIAL)?
			.split('\0')
			.collect();
		let key = format!("{db_name}.keptino");
		let key = utf8_percent_encode(&key, KEY_CHARS).to_string();
		let req = match fields.as_slice() {
			[_, id, secret] if self == Self::Backblaze && !id.is_empty() && !secret.is_empty() => {
				backblaze_request(&client, id, secret, &key, body).await?
			}
			[bucket, location, id, secret]
				if self != Self::Backblaze && !id.is_empty() && !secret.is_empty() =>
			{
				let (endpoint, region) = self.endpoint(location)?;
				if bucket.is_empty()
					|| matches!(*bucket, "." | "..")
					|| !bucket.bytes().all(|b| {
						b.is_ascii_lowercase()
							|| b.is_ascii_digit()
							|| matches!(b, b'-' | b'.' | b'_')
					}) {
					return Err(BAD_CREDENTIAL.into());
				}
				let url = format!("{endpoint}/{bucket}/{key}");
				s3_request(&client, &url, region, id, secret, body, SystemTime::now())?
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

	async fn download(self, credentials: &[u8], db_name: &str) -> Result<Option<Vec<u8>>> {
		let resp = self.request(credentials, db_name, None).await?;
		let status = resp.status();
		if status == StatusCode::NOT_FOUND {
			let bytes = bounded_body(resp, "storage response").await?;
			if self.missing_key(&bytes) {
				return Ok(None);
			}
		} else if status == StatusCode::OK {
			let body = bounded_body(resp, "vault download").await?;
			let text = std::str::from_utf8(&body).map_err(|_| "Invalid remote vault encoding.")?;
			let data = Base64::decode_vec(text).map_err(|_| "Invalid remote vault encoding.")?;
			return Ok(Some(data));
		}
		Err(format!(
			"{} download failed (HTTP {}).",
			self.name(),
			status.as_u16()
		))
	}

	fn missing_key(self, bytes: &[u8]) -> bool {
		#[derive(Deserialize)]
		struct StorageError {
			#[serde(alias = "Code")]
			code: String,
		}
		if self == Self::Backblaze {
			serde_json::from_slice::<StorageError>(bytes).is_ok_and(|e| e.code == "not_found")
		} else {
			quick_xml::de::from_reader::<_, StorageError>(bytes)
				.is_ok_and(|e| e.code == "NoSuchKey")
		}
	}
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
	pub(super) async fn download(dir: &Path, db_name: &str) -> Result<(Self, Option<Vec<u8>>)> {
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
		let bytes = provider.download(&credentials, db_name).await?;
		Ok((remote, bytes))
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
	pub(super) async fn fetch(&self, dir: &Path, db_name: &str) -> Result<Option<Vec<u8>>> {
		let credentials = self.session_credentials(dir)?;
		self.provider.download(&credentials, db_name).await
	}

	pub(super) async fn upload(&self, dir: &Path, db_name: &str, bytes: &[u8]) -> Result<()> {
		let credentials = self.session_credentials(dir)?;
		let response = self
			.provider
			.request(&credentials, db_name, Some(Base64::encode_string(bytes)))
			.await?;
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

fn s3_request(
	client: &Client,
	url: &str,
	region: &str,
	id: &str,
	secret: &str,
	body: Option<String>,
	time: SystemTime,
) -> Result<RequestBuilder> {
	let method = if body.is_some() {
		Method::PUT
	} else {
		Method::GET
	};
	let identity = Credentials::new(id, secret, None, None, "Keptino").into();
	let mut settings = SigningSettings::default();
	settings.percent_encoding_mode = PercentEncodingMode::Single;
	settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
	settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
	let params = v4::SigningParams::builder()
		.identity(&identity)
		.region(region)
		.name("s3")
		.time(time)
		.settings(settings)
		.build()
		.map_err(|_| BAD_CREDENTIAL)?
		.into();
	let payload = body.as_deref().unwrap_or_default().as_bytes();
	let signable = SignableRequest::new(
		method.as_str(),
		url,
		std::iter::empty(),
		SignableBody::Bytes(payload),
	)
	.map_err(|_| "Invalid storage request.")?;
	let (headers, _) = sign(signable, &params)
		.map_err(|_| "Cannot sign storage request.")?
		.into_parts();
	let mut req = client.request(method, url);
	for (name, value) in headers.headers() {
		req = req.header(name, value);
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
		let key = utf8_percent_encode("Team + 100% 🔑.digisafe", KEY_CHARS);
		let url = format!("https://s3.us-east-1.amazonaws.com/vaults/{key}");
		// Fixed SigV4 vectors calculated independently for these wire bytes.
		for (body, expected_signature) in [
			(
				None,
				"fe72847b4acfb310f484520a7e04dc6f69a40fe7c9cc054ea5806b30069cf9ec",
			),
			(
				Some("ZmFrZQ=="),
				"b67ac51ee4dc1f4b74b74f490b96be2a7e57289d910ddf43f6f24b9a582e5e9e",
			),
		] {
			let req = s3_request(
				&client,
				&url,
				"us-east-1",
				"test-id",
				"test-secret",
				body.map(String::from),
				SystemTime::UNIX_EPOCH,
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
			assert!(
				req.headers()["authorization"]
					.to_str()
					.unwrap()
					.ends_with(expected_signature)
			);
		}
	}

	#[test]
	fn only_provider_missing_object_errors_can_start_a_vault() {
		for provider in [Provider::Aws, Provider::Gcs, Provider::R2] {
			assert!(provider.missing_key(b"<Error><Code>NoSuchKey</Code></Error>"));
			assert!(!provider.missing_key(b"<Error><Code>NoSuchBucket</Code></Error>"));
			assert!(!provider.missing_key(b""));
		}
		assert!(Provider::Backblaze.missing_key(br#"{"code":"not_found"}"#));
		assert!(!Provider::Backblaze.missing_key(br#"{"code":"unauthorized"}"#));
	}
}
