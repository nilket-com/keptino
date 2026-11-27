//! The CTAP2 commands Keptino uses, as typed requests and responses over
//! canonical CBOR (CTAP 2.1 section 6): `authenticatorGetInfo`,
//! `authenticatorClientPin`, `authenticatorMakeCredential` and
//! `authenticatorGetAssertion`. A message on the wire is one command byte
//! followed by the CBOR map; a response is one status byte followed by the
//! CBOR map when the status is success.

use crate::fido::cbor::{self, Value};
use crate::fido::pin::{Point, Protocol};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The relying party every Keptino credential is made for. CTAP2 only, so
/// it is a name, not a domain anything serves.
pub const RP_ID: &str = "keptino.local";
pub const RP_NAME: &str = "Keptino";
pub const HMAC_SECRET: &str = "hmac-secret";
/// COSE algorithm ES256, the one every FIDO2 key supports.
pub const ALG_ES256: i64 = -7;
const COMMAND_MAKE_CREDENTIAL: u8 = 0x01;
const COMMAND_GET_ASSERTION: u8 = 0x02;
const COMMAND_GET_INFO: u8 = 0x04;
const COMMAND_CLIENT_PIN: u8 = 0x06;
pub const STATUS_OK: u8 = 0x00;
/// Permissions a PIN/UV auth token is requested with on a CTAP 2.1 key.
pub const PERMISSION_MAKE_CREDENTIAL: u64 = 0x01;
pub const PERMISSION_GET_ASSERTION: u64 = 0x02;
/// Authenticator data flags.
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

/// SHA-256 of the relying party id, as authenticator data carries it.
pub fn rp_id_hash() -> [u8; 32] {
	Sha256::digest(RP_ID.as_bytes()).into()
}

/// Why a message could not be read or a response was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
	/// The authenticator returned a CTAP status other than success.
	Status(u8),
	Cbor(cbor::Error),
	/// A field is missing or has the wrong shape.
	Shape(&'static str),
}

impl From<cbor::Error> for Error {
	fn from(err: cbor::Error) -> Self {
		Self::Cbor(err)
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Status(code) => write!(f, "The security key answered status 0x{code:02x}."),
			Self::Cbor(err) => write!(f, "The security key sent invalid CBOR: {err}"),
			Self::Shape(what) => write!(f, "The security key's answer is missing {what}."),
		}
	}
}

impl std::error::Error for Error {}

/// A CTAP status that means the credential is not this key's: a wrong key
/// answers this to an allow list it does not own, before any touch.
pub const STATUS_NO_CREDENTIALS: u8 = 0x2E;
pub const STATUS_PIN_INVALID: u8 = 0x31;
pub const STATUS_PIN_BLOCKED: u8 = 0x32;
pub const STATUS_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const STATUS_PIN_NOT_SET: u8 = 0x35;
pub const STATUS_PIN_REQUIRED: u8 = 0x36;
pub const STATUS_UV_BLOCKED: u8 = 0x3C;
pub const STATUS_OPERATION_DENIED: u8 = 0x27;
pub const STATUS_USER_ACTION_TIMEOUT: u8 = 0x2F;
pub const STATUS_KEEPALIVE_CANCEL: u8 = 0x2D;
pub const STATUS_UNSUPPORTED_EXTENSION: u8 = 0x16;
pub const STATUS_INVALID_PARAMETER: u8 = 0x02;

fn key(n: u64) -> Value {
	Value::Unsigned(n)
}

fn neg(n: i64) -> Value {
	Value::Negative(n)
}

fn map(pairs: Vec<(Value, Value)>) -> Value {
	Value::map(pairs).expect("fixed keys never repeat")
}

/// Encodes one command: the command byte, then the parameters.
fn message(command: u8, params: Option<&Value>) -> Vec<u8> {
	let mut out = vec![command];
	if let Some(params) = params {
		out.extend(cbor::encode(params));
	}
	out
}

/// Splits a response into its status and, on success, its CBOR map.
pub fn response(bytes: &[u8]) -> Result<Option<Value>, Error> {
	let (&status, body) = bytes.split_first().ok_or(Error::Shape("a status byte"))?;
	if status != STATUS_OK {
		return Err(Error::Status(status));
	}
	if body.is_empty() {
		return Ok(None);
	}
	Ok(Some(cbor::decode(body)?))
}

fn field<'a>(map: &'a Value, k: u64, what: &'static str) -> Result<&'a Value, Error> {
	map.get(&key(k)).ok_or(Error::Shape(what))
}

/// A COSE_Key for P-256 as `authenticatorClientPin` exchanges it: kty EC2,
/// alg ECDH-ES+HKDF-256, crv P-256, x, y.
pub fn cose_point(point: &Point) -> Value {
	map(vec![
		(key(1), key(2)),
		(key(3), neg(-25)),
		(neg(-1), key(1)),
		(neg(-2), Value::Bytes(point.x.to_vec())),
		(neg(-3), Value::Bytes(point.y.to_vec())),
	])
}

pub fn point_from_cose(value: &Value) -> Result<Point, Error> {
	let coordinate = |k: i64| -> Result<[u8; 32], Error> {
		value
			.get(&neg(k))
			.and_then(Value::as_bytes)
			.and_then(|b| b.try_into().ok())
			.ok_or(Error::Shape("a key agreement coordinate"))
	};
	if value.get(&key(1)).and_then(Value::as_u64) != Some(2)
		|| value.get(&neg(-1)).and_then(Value::as_u64) != Some(1)
	{
		return Err(Error::Shape("a P-256 key agreement key"));
	}
	Ok(Point {
		x: coordinate(-2)?,
		y: coordinate(-3)?,
	})
}

/// `authenticatorGetInfo`: no parameters.
pub fn get_info() -> Vec<u8> {
	message(COMMAND_GET_INFO, None)
}

/// What Keptino needs to know about a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
	pub versions: Vec<String>,
	pub extensions: Vec<String>,
	pub pin_protocols: Vec<Protocol>,
	/// `clientPin` option: `Some(true)` set, `Some(false)` supported but not
	/// set, `None` unsupported.
	pub client_pin: Option<bool>,
	/// `uv` option: built-in user verification, same three states.
	pub uv: Option<bool>,
	/// `pinUvAuthToken` option: a CTAP 2.1 key with permission-scoped tokens.
	pub pin_uv_auth_token: bool,
	pub max_cred_id_length: Option<u64>,
}

impl Info {
	pub fn parse(body: &Value) -> Result<Self, Error> {
		let strings = |v: &Value, what| -> Result<Vec<String>, Error> {
			v.as_array()
				.ok_or(Error::Shape(what))?
				.iter()
				.map(|s| s.as_text().map(str::to_owned).ok_or(Error::Shape(what)))
				.collect()
		};
		let versions = strings(field(body, 1, "versions")?, "versions")?;
		let extensions = match body.get(&key(2)) {
			Some(v) => strings(v, "extensions")?,
			None => Vec::new(),
		};
		let options = body.get(&key(4));
		let option = |name: &str| {
			options
				.and_then(|o| o.get(&Value::from(name)))
				.and_then(Value::as_bool)
		};
		let pin_protocols = match body.get(&key(6)) {
			Some(v) => v
				.as_array()
				.ok_or(Error::Shape("pinUvAuthProtocols"))?
				.iter()
				.filter_map(Value::as_u64)
				.filter_map(Protocol::from_number)
				.collect(),
			None => Vec::new(),
		};
		Ok(Self {
			versions,
			extensions,
			pin_protocols,
			client_pin: option("clientPin"),
			uv: option("uv"),
			pin_uv_auth_token: option("pinUvAuthToken") == Some(true),
			max_cred_id_length: body.get(&key(8)).and_then(Value::as_u64),
		})
	}

	pub fn speaks_ctap2(&self) -> bool {
		self.versions.iter().any(|v| v.starts_with("FIDO_2_"))
	}

	pub fn has_hmac_secret(&self) -> bool {
		self.extensions.iter().any(|e| e == HMAC_SECRET)
	}

	/// The newest PIN protocol both sides speak.
	pub fn best_protocol(&self) -> Option<Protocol> {
		if self.pin_protocols.contains(&Protocol::Two) {
			Some(Protocol::Two)
		} else if self.pin_protocols.contains(&Protocol::One) {
			Some(Protocol::One)
		} else {
			None
		}
	}
}

/// `authenticatorClientPin` subcommand `getKeyAgreement`.
pub fn get_key_agreement(protocol: Protocol) -> Vec<u8> {
	message(
		COMMAND_CLIENT_PIN,
		Some(&map(vec![
			(key(1), key(protocol.number())),
			(key(2), key(2)),
		])),
	)
}

pub fn key_agreement_from(body: &Value) -> Result<Point, Error> {
	point_from_cose(field(body, 1, "keyAgreement")?)
}

/// `authenticatorClientPin` subcommand `getPinToken` (CTAP 2.0), or
/// `getPinUvAuthTokenUsingPinWithPermissions` (CTAP 2.1) when `permissions`
/// is given: the PIN hash encrypted under the shared secret.
pub fn get_pin_token(
	protocol: Protocol,
	client: &Point,
	pin_hash_enc: &[u8],
	permissions: Option<u64>,
) -> Vec<u8> {
	let mut pairs = vec![
		(key(1), key(protocol.number())),
		(key(2), key(if permissions.is_some() { 9 } else { 5 })),
		(key(3), cose_point(client)),
		(key(6), Value::Bytes(pin_hash_enc.to_vec())),
	];
	if let Some(permissions) = permissions {
		pairs.push((key(9), key(permissions)));
		pairs.push((key(10), Value::from(RP_ID)));
	}
	message(COMMAND_CLIENT_PIN, Some(&map(pairs)))
}

/// The encrypted PIN/UV auth token from a `getPinToken` response.
pub fn pin_token_from(body: &Value) -> Result<Vec<u8>, Error> {
	field(body, 2, "pinUvAuthToken")?
		.as_bytes()
		.map(<[u8]>::to_vec)
		.ok_or(Error::Shape("pinUvAuthToken"))
}

/// `authenticatorMakeCredential` for a non-resident ES256 credential with
/// the `hmac-secret` extension. `pin_auth` is the token's tag over the
/// client data hash when user verification is in play.
pub fn make_credential(
	client_data_hash: &[u8; 32],
	user_id: &[u8],
	pin_auth: Option<(&[u8], Protocol)>,
	builtin_uv: bool,
) -> Vec<u8> {
	let mut options = vec![(Value::from("rk"), Value::Bool(false))];
	if builtin_uv {
		options.push((Value::from("uv"), Value::Bool(true)));
	}
	let mut pairs = vec![
		(key(1), Value::Bytes(client_data_hash.to_vec())),
		(
			key(2),
			map(vec![
				(Value::from("id"), Value::from(RP_ID)),
				(Value::from("name"), Value::from(RP_NAME)),
			]),
		),
		(
			key(3),
			map(vec![
				(Value::from("id"), Value::Bytes(user_id.to_vec())),
				(Value::from("name"), Value::from("vault")),
			]),
		),
		(
			key(4),
			Value::Array(vec![map(vec![
				(Value::from("alg"), neg(ALG_ES256)),
				(Value::from("type"), Value::from("public-key")),
			])]),
		),
		(
			key(6),
			map(vec![(Value::from(HMAC_SECRET), Value::Bool(true))]),
		),
		(key(7), map(options)),
	];
	if let Some((tag, protocol)) = pin_auth {
		pairs.push((key(8), Value::Bytes(tag.to_vec())));
		pairs.push((key(9), key(protocol.number())));
	}
	message(COMMAND_MAKE_CREDENTIAL, Some(&map(pairs)))
}

/// Authenticator data as both `makeCredential` and `getAssertion` return
/// it: rpIdHash, flags, counter, optional attested credential data, optional
/// extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthData {
	pub rp_id_hash: [u8; 32],
	pub flags: u8,
	pub counter: u32,
	pub credential_id: Option<Vec<u8>>,
	pub extensions: Option<Value>,
}

impl AuthData {
	pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
		let short = Error::Shape("authenticator data");
		let (hash, rest) = bytes.split_at_checked(32).ok_or(short.clone())?;
		let (&flags, rest) = rest.split_first().ok_or(short.clone())?;
		let (counter, mut rest) = rest.split_at_checked(4).ok_or(short.clone())?;
		let mut credential_id = None;
		if flags & FLAG_AT != 0 {
			// aaguid(16) | credIdLen(2) | credId | COSE public key (CBOR)
			let (_, after_aaguid) = rest.split_at_checked(16).ok_or(short.clone())?;
			let (len, after_len) = after_aaguid.split_at_checked(2).ok_or(short.clone())?;
			let len = u16::from_be_bytes([len[0], len[1]]) as usize;
			let (id, after_id) = after_len.split_at_checked(len).ok_or(short.clone())?;
			credential_id = Some(id.to_vec());
			// The public key is CBOR of unknown length; decode it to find
			// where it ends by trying prefixes is wasteful, so the key is
			// decoded together with what follows.
			rest = after_id;
			let (_, consumed) = decode_prefix(rest)?;
			rest = &rest[consumed..];
		}
		let extensions = if flags & FLAG_ED != 0 {
			let (value, consumed) = decode_prefix(rest)?;
			if consumed != rest.len() {
				return Err(Error::Shape("authenticator data without trailing bytes"));
			}
			Some(value)
		} else if rest.is_empty() {
			None
		} else {
			return Err(Error::Shape("authenticator data without trailing bytes"));
		};
		Ok(Self {
			rp_id_hash: hash.try_into().map_err(|_| short)?,
			flags,
			counter: u32::from_be_bytes([counter[0], counter[1], counter[2], counter[3]]),
			credential_id,
			extensions,
		})
	}

	pub fn user_present(&self) -> bool {
		self.flags & FLAG_UP != 0
	}

	pub fn user_verified(&self) -> bool {
		self.flags & FLAG_UV != 0
	}

	/// The `hmac-secret` extension output: the encrypted secret bytes.
	pub fn hmac_secret_output(&self) -> Option<&[u8]> {
		self.extensions
			.as_ref()?
			.get(&Value::from(HMAC_SECRET))?
			.as_bytes()
	}

	/// Whether `makeCredential` confirmed the extension.
	pub fn hmac_secret_enabled(&self) -> bool {
		self.extensions
			.as_ref()
			.and_then(|e| e.get(&Value::from(HMAC_SECRET)))
			.and_then(Value::as_bool)
			== Some(true)
	}
}

/// Decodes the one CBOR item at the start of `bytes` and reports how many
/// bytes it took, by probing the shortest prefix that decodes cleanly.
fn decode_prefix(bytes: &[u8]) -> Result<(Value, usize), Error> {
	let mut end = 1;
	while end <= bytes.len() {
		match cbor::decode(&bytes[..end]) {
			Ok(value) => return Ok((value, end)),
			Err(cbor::Error::Truncated) => end += 1,
			Err(err) => return Err(err.into()),
		}
	}
	Err(cbor::Error::Truncated.into())
}

/// The parts of a `makeCredential` response Keptino reads.
pub fn make_credential_from(body: &Value) -> Result<AuthData, Error> {
	let auth_data = field(body, 2, "authData")?
		.as_bytes()
		.ok_or(Error::Shape("authData"))?;
	AuthData::parse(auth_data)
}

/// The `hmac-secret` request for `getAssertion`: the client's key agreement
/// key, the salt encrypted under the shared secret, its tag, and the
/// protocol.
pub struct HmacSecretRequest {
	pub key_agreement: Point,
	pub salt_enc: Vec<u8>,
	pub salt_auth: Vec<u8>,
	pub protocol: Protocol,
}

/// `authenticatorGetAssertion` for one credential, with `hmac-secret` and
/// the `up` option on. `uv` is requested only when no PIN token is given and
/// built-in verification is wanted.
pub fn get_assertion(
	client_data_hash: &[u8; 32],
	credential_id: &[u8],
	hmac: &HmacSecretRequest,
	pin_auth: Option<(&[u8], Protocol)>,
	builtin_uv: bool,
) -> Vec<u8> {
	let mut options = vec![(Value::from("up"), Value::Bool(true))];
	if builtin_uv {
		options.push((Value::from("uv"), Value::Bool(true)));
	}
	let mut pairs = vec![
		(key(1), Value::from(RP_ID)),
		(key(2), Value::Bytes(client_data_hash.to_vec())),
		(
			key(3),
			Value::Array(vec![map(vec![
				(Value::from("id"), Value::Bytes(credential_id.to_vec())),
				(Value::from("type"), Value::from("public-key")),
			])]),
		),
		(
			key(4),
			map(vec![(
				Value::from(HMAC_SECRET),
				map(vec![
					(key(1), cose_point(&hmac.key_agreement)),
					(key(2), Value::Bytes(hmac.salt_enc.clone())),
					(key(3), Value::Bytes(hmac.salt_auth.clone())),
					(key(4), key(hmac.protocol.number())),
				]),
			)]),
		),
		(key(5), map(options)),
	];
	if let Some((tag, protocol)) = pin_auth {
		pairs.push((key(6), Value::Bytes(tag.to_vec())));
		pairs.push((key(7), key(protocol.number())));
	}
	message(COMMAND_GET_ASSERTION, Some(&map(pairs)))
}

/// The parts of a `getAssertion` response Keptino reads: the credential the
/// key chose and the authenticator data.
pub struct Assertion {
	pub credential_id: Option<Vec<u8>>,
	pub auth_data: AuthData,
}

pub fn assertion_from(body: &Value) -> Result<Assertion, Error> {
	let credential_id = body
		.get(&key(1))
		.and_then(|c| c.get(&Value::from("id")))
		.and_then(Value::as_bytes)
		.map(<[u8]>::to_vec);
	let auth_data = field(body, 2, "authData")?
		.as_bytes()
		.ok_or(Error::Shape("authData"))?;
	Ok(Assertion {
		credential_id,
		auth_data: AuthData::parse(auth_data)?,
	})
}

/// A client data hash for a ceremony: random, since Keptino has no client
/// data to bind; it still keeps a replayed answer from fitting a new request.
pub fn client_data_hash() -> Zeroizing<[u8; 32]> {
	let mut hash = Zeroizing::new([0u8; 32]);
	getrandom::fill(&mut *hash).expect("Random generation failed");
	hash
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_info_and_its_answer_round_trip() {
		assert_eq!(get_info(), vec![0x04]);
		let body = map(vec![
			(
				key(1),
				Value::Array(vec![
					Value::from("U2F_V2"),
					Value::from("FIDO_2_0"),
					Value::from("FIDO_2_1"),
				]),
			),
			(
				key(2),
				Value::Array(vec![Value::from("credProtect"), Value::from(HMAC_SECRET)]),
			),
			(key(3), Value::Bytes(vec![0; 16])),
			(
				key(4),
				map(vec![
					(Value::from("clientPin"), Value::Bool(true)),
					(Value::from("rk"), Value::Bool(true)),
					(Value::from("pinUvAuthToken"), Value::Bool(true)),
				]),
			),
			(key(6), Value::Array(vec![key(2), key(1)])),
			(key(8), key(128)),
		]);
		let wire = [vec![STATUS_OK], cbor::encode(&body)].concat();
		let info = Info::parse(&response(&wire).unwrap().unwrap()).unwrap();
		assert!(info.speaks_ctap2() && info.has_hmac_secret() && info.pin_uv_auth_token);
		assert_eq!(info.client_pin, Some(true));
		assert_eq!(info.uv, None);
		assert_eq!(info.best_protocol(), Some(Protocol::Two));
		assert_eq!(info.max_cred_id_length, Some(128));
		assert_eq!(response(&[0x31]), Err(Error::Status(0x31)));
		assert_eq!(response(&[]), Err(Error::Shape("a status byte")));
		assert_eq!(response(&[0x00]).unwrap(), None);
	}

	#[test]
	fn cose_points_round_trip_and_commands_carry_their_keys_in_order() {
		let point = Point {
			x: [1; 32],
			y: [2; 32],
		};
		assert_eq!(point_from_cose(&cose_point(&point)).unwrap(), point);
		let bad = map(vec![(key(1), key(1))]);
		assert!(point_from_cose(&bad).is_err());
		let ka = get_key_agreement(Protocol::Two);
		assert_eq!(ka[0], COMMAND_CLIENT_PIN);
		assert_eq!(
			cbor::decode(&ka[1..]).unwrap(),
			map(vec![(key(1), key(2)), (key(2), key(2))])
		);
		let token = get_pin_token(Protocol::Two, &point, &[9; 32], Some(0x03));
		let decoded = cbor::decode(&token[1..]).unwrap();
		assert_eq!(decoded.get(&key(2)), Some(&key(9)));
		assert_eq!(decoded.get(&key(9)), Some(&key(3)));
		assert_eq!(decoded.get(&key(10)), Some(&Value::from(RP_ID)));
		let legacy =
			cbor::decode(&get_pin_token(Protocol::One, &point, &[9; 16], None)[1..]).unwrap();
		assert_eq!(legacy.get(&key(2)), Some(&key(5)));
		assert!(legacy.get(&key(9)).is_none());
	}

	#[test]
	fn make_credential_and_get_assertion_encode_the_extension() {
		let mc = make_credential(&[3; 32], b"user", Some((&[7; 32], Protocol::Two)), false);
		assert_eq!(mc[0], COMMAND_MAKE_CREDENTIAL);
		let decoded = cbor::decode(&mc[1..]).unwrap();
		assert_eq!(
			decoded.get(&key(6)),
			Some(&map(vec![(Value::from(HMAC_SECRET), Value::Bool(true))]))
		);
		assert_eq!(decoded.get(&key(9)), Some(&key(2)));
		// Encoding is canonical: decoding what we sent is accepted as is.
		assert_eq!(cbor::encode(&decoded), mc[1..]);

		let hmac = HmacSecretRequest {
			key_agreement: Point {
				x: [1; 32],
				y: [2; 32],
			},
			salt_enc: vec![4; 48],
			salt_auth: vec![5; 32],
			protocol: Protocol::Two,
		};
		let ga = get_assertion(&[3; 32], b"cred", &hmac, None, true);
		assert_eq!(ga[0], COMMAND_GET_ASSERTION);
		let decoded = cbor::decode(&ga[1..]).unwrap();
		assert_eq!(decoded.get(&key(1)), Some(&Value::from(RP_ID)));
		let options = decoded.get(&key(5)).unwrap();
		assert_eq!(options.get(&Value::from("uv")), Some(&Value::Bool(true)));
		assert!(decoded.get(&key(6)).is_none());
		let ext = decoded
			.get(&key(4))
			.unwrap()
			.get(&Value::from(HMAC_SECRET))
			.unwrap();
		assert_eq!(ext.get(&key(4)), Some(&key(2)));
	}

	#[test]
	fn authenticator_data_parses_with_and_without_attested_credential() {
		let hash = rp_id_hash();
		let cose = cbor::encode(&cose_point(&Point {
			x: [1; 32],
			y: [2; 32],
		}));
		let mut attested = Vec::new();
		attested.extend_from_slice(&hash);
		attested.push(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED);
		attested.extend_from_slice(&7u32.to_be_bytes());
		attested.extend_from_slice(&[0xAA; 16]);
		attested.extend_from_slice(&3u16.to_be_bytes());
		attested.extend_from_slice(b"abc");
		attested.extend_from_slice(&cose);
		attested.extend(cbor::encode(&map(vec![(
			Value::from(HMAC_SECRET),
			Value::Bool(true),
		)])));
		let parsed = AuthData::parse(&attested).unwrap();
		assert_eq!(parsed.rp_id_hash, hash);
		assert_eq!(parsed.counter, 7);
		assert_eq!(parsed.credential_id.as_deref(), Some(b"abc".as_slice()));
		assert!(parsed.user_present() && parsed.user_verified() && parsed.hmac_secret_enabled());

		let mut plain = Vec::new();
		plain.extend_from_slice(&hash);
		plain.push(FLAG_UP | FLAG_ED);
		plain.extend_from_slice(&1u32.to_be_bytes());
		plain.extend(cbor::encode(&map(vec![(
			Value::from(HMAC_SECRET),
			Value::Bytes(vec![9; 32]),
		)])));
		let parsed = AuthData::parse(&plain).unwrap();
		assert!(parsed.credential_id.is_none());
		assert!(!parsed.user_verified());
		assert_eq!(parsed.hmac_secret_output(), Some([9u8; 32].as_slice()));

		let mut trailing = plain.clone();
		trailing.push(0);
		assert!(AuthData::parse(&trailing).is_err());
		assert!(AuthData::parse(&plain[..40]).is_err());
	}
}
