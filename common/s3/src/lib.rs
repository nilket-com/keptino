//! S3 Signature Version 4 for Keptino's object requests: path-style `GET`
//! and `PUT` of one object in one bucket, signed with `AWS4-HMAC-SHA256`,
//! single percent encoding, no path normalization and the payload's SHA-256
//! as the content hash. No I/O: a head hands the headers to its HTTP client.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// Not an `https://` URL with a host, or one with userinfo, a path, a
	/// query or a fragment.
	Endpoint,
	/// Not a bucket name: lowercase letters, digits, `-`, `.` and `_` only,
	/// and never `.` or `..`.
	Bucket,
	/// A region, key id or secret that is empty or carries a control byte.
	Credential,
	/// A time before 1970.
	Time,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Endpoint => {
				"The storage endpoint must be an https:// URL with a host and nothing else."
			}
			Self::Bucket => "Invalid bucket name.",
			Self::Credential => "Invalid storage credential.",
			Self::Time => "The clock is before 1970.",
		})
	}
}

impl std::error::Error for Error {}

/// An endpoint as `sign` uses it: scheme, host and optional port, no
/// trailing slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
	url: String,
	host: String,
}

impl Endpoint {
	pub fn url(&self) -> &str {
		&self.url
	}

	/// The `Host` header value: host with the port when one is given.
	pub fn host(&self) -> &str {
		&self.host
	}
}

/// Accepts `https://host` or `https://host:port`, with one trailing slash
/// allowed and removed, and nothing else: no userinfo, path, query or
/// fragment. A debug build also accepts `http://` on the loopback address,
/// for tests against a local store; a release build never does.
pub fn validate_endpoint(url: &str) -> Result<Endpoint, Error> {
	let url = url.strip_suffix('/').unwrap_or(url);
	let (scheme, rest) = url.split_once("://").ok_or(Error::Endpoint)?;
	if rest.is_empty()
		|| rest.contains(['/', '?', '#', '@', '\\', ' '])
		|| rest.bytes().any(|b| b.is_ascii_control() || b >= 0x80)
	{
		return Err(Error::Endpoint);
	}
	let (host, port) = match rest.rsplit_once(':') {
		Some((host, port)) if !host.contains(']') || host.ends_with(']') => (host, Some(port)),
		_ => (rest, None),
	};
	if host.is_empty()
		|| !host
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'[' | b']' | b':'))
	{
		return Err(Error::Endpoint);
	}
	if let Some(port) = port
		&& !port.parse::<u16>().is_ok_and(|p| p > 0)
	{
		return Err(Error::Endpoint);
	}
	// Plain HTTP only in a debug build and only to this machine, by exact
	// host, so `localhost.example` is not loopback.
	let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
	match scheme {
		"https" => {}
		"http" if cfg!(debug_assertions) && loopback => {}
		_ => return Err(Error::Endpoint),
	}
	// The scheme's default port is dropped, since the HTTP client omits it
	// from the `Host` it sends and the signed header must match the wire.
	let default_port = if scheme == "https" { "443" } else { "80" };
	let (url, authority) = match port {
		Some(p) if p == default_port => (format!("{scheme}://{host}"), host.to_owned()),
		_ => (url.to_owned(), rest.to_owned()),
	};
	Ok(Endpoint {
		url,
		host: authority,
	})
}

/// The bucket rule every provider shares: lowercase letters, digits, `-`,
/// `.` and `_`, at least one character, never `.` or `..`.
pub fn validate_bucket(bucket: &str) -> Result<(), Error> {
	if bucket.is_empty()
		|| matches!(bucket, "." | "..")
		|| !bucket.bytes().all(|b| {
			b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_')
		}) {
		return Err(Error::Bucket);
	}
	Ok(())
}

/// Percent-encodes a path segment the way SigV4 canonicalizes it: unreserved
/// characters stay, everything else is `%XX` uppercase. Applied once.
pub fn encode_segment(segment: &str) -> String {
	let mut out = String::with_capacity(segment.len());
	for byte in segment.bytes() {
		if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
			out.push(byte as char);
		} else {
			out.push_str(&format!("%{byte:02X}"));
		}
	}
	out
}

/// The headers of one signed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
	/// The full URL the request goes to.
	pub url: String,
	pub host: String,
	pub amz_date: String,
	pub content_sha256: String,
	pub authorization: String,
}

/// The method of an object request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
	Get,
	Put,
}

impl Method {
	fn as_str(self) -> &'static str {
		match self {
			Self::Get => "GET",
			Self::Put => "PUT",
		}
	}
}

/// Signs `method` on `/{bucket}/{key}` at `endpoint` for `time`, seconds
/// since the Unix epoch. `key` is the object key as text; it is encoded
/// here. The secret is used through a wiping buffer.
#[allow(clippy::too_many_arguments)]
pub fn sign(
	method: Method,
	endpoint: &Endpoint,
	bucket: &str,
	key: &str,
	region: &str,
	access_key: &str,
	secret: &str,
	payload: &[u8],
	time: u64,
) -> Result<Signed, Error> {
	validate_bucket(bucket)?;
	for field in [region, access_key, secret] {
		if field.is_empty() || field.bytes().any(|b| b.is_ascii_control() || b >= 0x80) {
			return Err(Error::Credential);
		}
	}
	let path = format!("/{bucket}/{}", encode_segment(key));
	let content_sha256 = hex(&Sha256::digest(payload));
	let (date, amz_date) = timestamp(time)?;
	let canonical_headers = format!(
		"host:{}\nx-amz-content-sha256:{content_sha256}\nx-amz-date:{amz_date}\n",
		endpoint.host
	);
	let signed_headers = "host;x-amz-content-sha256;x-amz-date";
	let canonical_request = format!(
		"{}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{content_sha256}",
		method.as_str()
	);
	let scope = format!("{date}/{region}/s3/aws4_request");
	let string_to_sign = format!(
		"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
		hex(&Sha256::digest(canonical_request.as_bytes()))
	);
	let signature = signature(secret, &date, region, "s3", &string_to_sign);
	Ok(Signed {
		url: format!("{}{path}", endpoint.url),
		host: endpoint.host.clone(),
		amz_date,
		content_sha256,
		authorization: format!(
			"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
		),
	})
}

/// The signing key chain and the final HMAC, as hex.
fn signature(
	secret: &str,
	date: &str,
	region: &str,
	service: &str,
	string_to_sign: &str,
) -> String {
	let mut key = Zeroizing::new(format!("AWS4{secret}").into_bytes());
	for part in [date, region, service, "aws4_request"] {
		let next = Zeroizing::new(hmac(&key, part.as_bytes()).to_vec());
		// A new wiping buffer each step, so the previous one is wiped on drop.
		key = next;
	}
	hex(&hmac(&key, string_to_sign.as_bytes()))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
	let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
	mac.update(data);
	mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `YYYYMMDD` and `YYYYMMDDTHHMMSSZ` for seconds since the epoch.
fn timestamp(seconds: u64) -> Result<(String, String), Error> {
	let days = seconds / 86_400;
	let rem = seconds % 86_400;
	let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
	// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
	let z = days as i64 + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let year = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = if mp < 10 { mp + 3 } else { mp - 9 };
	let year = if month <= 2 { year + 1 } else { year };
	if year < 1970 {
		return Err(Error::Time);
	}
	let date = format!("{year:04}{month:02}{day:02}");
	let amz_date = format!("{date}T{hour:02}{minute:02}{second:02}Z");
	Ok((date, amz_date))
}

/// Whether an S3 error body says the object does not exist: the XML error
/// document with `<Code>NoSuchKey</Code>`, read without an XML parser,
/// since the one element is all that matters.
pub fn is_missing_key(body: &[u8]) -> bool {
	let Ok(text) = std::str::from_utf8(body) else {
		return false;
	};
	text.split("<Code>")
		.skip(1)
		.any(|rest| rest.trim_start().starts_with("NoSuchKey<"))
		|| text.contains("<Code>NoSuchKey</Code>")
}

#[cfg(test)]
mod tests {
	use super::*;

	const TIME: u64 = 1_700_000_000;

	fn aws() -> Endpoint {
		validate_endpoint("https://s3.us-east-1.amazonaws.com").unwrap()
	}

	/// What the Linux head signed through the vendor crate before this
	/// crate existed, for the same inputs: not a byte may differ.
	#[test]
	fn matches_the_previous_linux_signer_byte_for_byte() {
		let get = sign(
			Method::Get,
			&aws(),
			"example-bucket",
			"main.keptino",
			"us-east-1",
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			b"",
			TIME,
		)
		.unwrap();
		assert_eq!(
			get.url,
			"https://s3.us-east-1.amazonaws.com/example-bucket/main.keptino"
		);
		assert_eq!(get.host, "s3.us-east-1.amazonaws.com");
		assert_eq!(get.amz_date, "20231114T221320Z");
		assert_eq!(
			get.content_sha256,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		);
		assert_eq!(
			get.authorization,
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231114/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0f39440617a19ce9081074bd543f32c2dfa237f2e687583c412fe33d8357ccad"
		);
		let put = sign(
			Method::Put,
			&aws(),
			"example-bucket",
			"main.keptino",
			"us-east-1",
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			b"aGVsbG8gd29ybGQ=",
			TIME,
		)
		.unwrap();
		assert_eq!(
			put.content_sha256,
			"dc9c1c09907c36f5379d615ae61c02b46ba254d92edb77cb63bdcc5247ccd01c"
		);
		assert!(put.authorization.ends_with(
			"Signature=3851ba1cec5f447087be48f954da92e05ca6222d2514df1177a2126b2b99a418"
		));
		// A custom endpoint with a port and a key with a space.
		let custom = sign(
			Method::Get,
			&validate_endpoint("https://strix.example:9000/").unwrap(),
			"keptino",
			"vault one.keptino",
			"us-east-1",
			"rustfsadmin",
			"rustfsadmin",
			b"",
			TIME,
		)
		.unwrap();
		assert_eq!(
			custom.url,
			"https://strix.example:9000/keptino/vault%20one.keptino"
		);
		assert_eq!(custom.host, "strix.example:9000");
		assert!(custom.authorization.ends_with(
			"Signature=86bdb29251ed0e5122b034c5cdaee04b7a994b4f6aa1f70452ba8fc63a5f06a8"
		));
	}

	/// The AWS Signature Version 4 test suite, `get-vanilla`: an outside
	/// vector for the key chain and the string to sign. It signs only `host`
	/// and `x-amz-date`, so it drives the pieces rather than `sign`.
	#[test]
	fn matches_the_aws_test_suite_key_chain() {
		let canonical_request = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
			hex(&Sha256::digest(canonical_request.as_bytes()))
		);
		assert_eq!(
			hex(&Sha256::digest(canonical_request.as_bytes())),
			"bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
		);
		assert_eq!(
			signature(
				"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
				"20150830",
				"us-east-1",
				"service",
				&string_to_sign
			),
			"5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
		);
		assert_eq!(timestamp(1_440_938_160).unwrap().1, "20150830T123600Z");
		assert_eq!(timestamp(0).unwrap().1, "19700101T000000Z");
		assert_eq!(timestamp(951_782_400).unwrap().0, "20000229", "a leap day");
	}

	#[test]
	fn endpoints_and_buckets_are_checked_as_the_decision_says() {
		assert_eq!(validate_endpoint("https://host").unwrap().host(), "host");
		assert_eq!(
			validate_endpoint("https://host:9000/").unwrap().url(),
			"https://host:9000"
		);
		assert_eq!(
			validate_endpoint("https://[::1]:9000").unwrap().host(),
			"[::1]:9000"
		);
		// The scheme's default port is not on the wire, so not in the signature.
		let default = validate_endpoint("https://host:443").unwrap();
		assert_eq!((default.url(), default.host()), ("https://host", "host"));
		assert_eq!(
			validate_endpoint("https://host:8443").unwrap().host(),
			"host:8443"
		);
		for bad in [
			"http://host",
			"https://",
			"https://user@host",
			"https://host/bucket",
			"https://host?x=1",
			"https://host#frag",
			"https://host:port",
			"https://ho st",
			"ftp://host",
			"host",
			"https://hóst",
		] {
			assert_eq!(validate_endpoint(bad), Err(Error::Endpoint), "{bad}");
		}
		// Loopback HTTP is for the debug build's tests only.
		assert_eq!(
			validate_endpoint("http://127.0.0.1:9000").is_ok(),
			cfg!(debug_assertions)
		);
		assert_eq!(
			validate_endpoint("http://10.0.0.1:9000"),
			Err(Error::Endpoint)
		);
		for bad in [
			"http://localhost.evil.com",
			"http://127.0.0.1.evil.com",
			"https://host:0",
			"https://host:99999",
		] {
			assert_eq!(validate_endpoint(bad), Err(Error::Endpoint), "{bad}");
		}
		for ok in ["keptino", "my-bucket.v2_x"] {
			assert_eq!(validate_bucket(ok), Ok(()));
		}
		for bad in ["", ".", "..", "Bucket", "a b", "a/b"] {
			assert_eq!(validate_bucket(bad), Err(Error::Bucket), "{bad}");
		}
		assert_eq!(
			sign(
				Method::Get,
				&aws(),
				"ok",
				"k",
				"",
				"id",
				"secret",
				b"",
				TIME
			)
			.err(),
			Some(Error::Credential)
		);
		assert_eq!(
			sign(
				Method::Get,
				&aws(),
				"ok",
				"k",
				"us-east-1",
				"id",
				"se\ncret",
				b"",
				TIME
			)
			.err(),
			Some(Error::Credential)
		);
		assert_eq!(encode_segment("a b/c~d.e"), "a%20b%2Fc~d.e");
	}

	#[test]
	fn missing_key_bodies_from_rustfs_and_aws_are_recognized() {
		let aws = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>main.keptino</Key><RequestId>X</RequestId><HostId>Y</HostId></Error>";
		let rustfs = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Resource>/keptino-test/main.keptino</Resource><RequestId></RequestId></Error>";
		assert!(is_missing_key(aws));
		assert!(is_missing_key(rustfs));
		assert!(!is_missing_key(b"<Error><Code>AccessDenied</Code></Error>"));
		assert!(!is_missing_key(
			b"<Error><Message>NoSuchKey</Message></Error>"
		));
		assert!(!is_missing_key(b"not xml"));
		assert!(!is_missing_key(&[0xff, 0xfe]));
	}
}
