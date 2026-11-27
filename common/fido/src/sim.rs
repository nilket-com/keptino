//! A simulated security key for tests, behind the `test-support` feature:
//! CTAP2 with `hmac-secret`, both PIN protocols, a PIN with retries, optional
//! built-in user verification, and HID and NFC device shells. It is
//! deterministic from a seed: a credential id carries a tag under the seed,
//! so a fresh simulator from the same seed serves every credential one of its
//! earlier lives made, as a hardware key's wrapped handles do. The two
//! `hmac-secret` secrets per credential differ, as CTAP 2.1 requires.

use crate::cbor::{self, Value};
use crate::ceremony::{Ceremony, Input, Step};
use crate::ctap::{self, FLAG_AT, FLAG_ED, FLAG_UP, FLAG_UV, HMAC_SECRET};
use crate::pin::{self, Point, Protocol, SharedSecret};
use crate::{hid, nfc};
use hmac::{Hmac, Mac};
use p256::{PublicKey, Sec1Point, SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use zeroize::Zeroizing;

const STATUS_PIN_AUTH_INVALID: u8 = 0x33;
const STATUS_MISSING_PARAMETER: u8 = 0x14;
const STATUS_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const AAGUID: [u8; 16] = *b"keptino-sim-0001";

fn mac(seed: &[u8; 32], label: &str, data: &[u8]) -> [u8; 32] {
	let mut m = <Hmac<Sha256>>::new_from_slice(seed).expect("any key length");
	m.update(label.as_bytes());
	m.update(data);
	m.finalize().into_bytes().into()
}

struct Token {
	bytes: Zeroizing<Vec<u8>>,
	protocol: Protocol,
	permissions: u64,
}

/// The key itself, speaking raw CTAP messages.
pub struct Authenticator {
	seed: [u8; 32],
	pin: Option<Zeroizing<Vec<u8>>>,
	retries: u8,
	protocols: Vec<Protocol>,
	builtin_uv: bool,
	/// Whether the next user presence check succeeds.
	pub touch: bool,
	counter: u32,
	tokens: Vec<Token>,
	key_agreement: SecretKey,
	/// Credentials made in this life, for tests that count them.
	pub credentials_made: u32,
}

impl Authenticator {
	pub fn new(seed: [u8; 32]) -> Self {
		let scalar = mac(&seed, "key-agreement", &[]);
		Self {
			seed,
			pin: None,
			retries: 8,
			protocols: vec![Protocol::Two, Protocol::One],
			builtin_uv: false,
			touch: true,
			counter: 0,
			tokens: Vec::new(),
			key_agreement: SecretKey::from_slice(&scalar).expect("a nonzero scalar"),
			credentials_made: 0,
		}
	}

	pub fn with_pin(mut self, pin: &str) -> Self {
		self.pin = Some(Zeroizing::new(pin.as_bytes().to_vec()));
		self
	}

	pub fn with_builtin_uv(mut self) -> Self {
		self.builtin_uv = true;
		self
	}

	pub fn with_protocols(mut self, protocols: Vec<Protocol>) -> Self {
		self.protocols = protocols;
		self
	}

	pub fn retries_left(&self) -> u8 {
		self.retries
	}

	fn public_point(&self) -> Point {
		let encoded = self.key_agreement.public_key().to_sec1_point(false);
		let mut point = Point {
			x: [0; 32],
			y: [0; 32],
		};
		point.x.copy_from_slice(encoded.x().expect("uncompressed"));
		point.y.copy_from_slice(encoded.y().expect("uncompressed"));
		point
	}

	fn shared_with(&self, protocol: Protocol, client: &Point) -> Option<SharedSecret> {
		let encoded = Sec1Point::from_affine_coordinates(&client.x.into(), &client.y.into(), false);
		let peer = PublicKey::from_sec1_bytes(encoded.as_bytes()).ok()?;
		let z =
			p256::ecdh::diffie_hellman(self.key_agreement.to_nonzero_scalar(), peer.as_affine());
		Some(SharedSecret::derive(protocol, z.raw_secret_bytes()))
	}

	fn make_cred_id(&mut self) -> Vec<u8> {
		self.counter += 1;
		let nonce = &mac(&self.seed, "nonce", &self.counter.to_be_bytes())[..16];
		let tag = &mac(&self.seed, "cred", nonce)[..16];
		[nonce, tag].concat()
	}

	fn owns(&self, cred_id: &[u8]) -> bool {
		cred_id.len() == 32 && mac(&self.seed, "cred", &cred_id[..16])[..16] == cred_id[16..]
	}

	fn cred_random(&self, cred_id: &[u8], uv: bool) -> [u8; 32] {
		mac(&self.seed, if uv { "uv" } else { "nouv" }, cred_id)
	}

	/// Handles one CTAP message: status byte, then the CBOR body on success.
	pub fn handle(&mut self, message: &[u8]) -> Vec<u8> {
		let Some((&command, body)) = message.split_first() else {
			return vec![STATUS_MISSING_PARAMETER];
		};
		let params = if body.is_empty() {
			None
		} else {
			match cbor::decode(body) {
				Ok(v) => Some(v),
				Err(_) => return vec![STATUS_CBOR_UNEXPECTED_TYPE],
			}
		};
		let result = match command {
			0x04 => Ok(self.get_info()),
			0x06 => self.client_pin(params.as_ref()),
			0x01 => self.make_credential(params.as_ref()),
			0x02 => self.get_assertion(params.as_ref()),
			_ => Err(0x01),
		};
		match result {
			Ok(value) => [vec![ctap::STATUS_OK], cbor::encode(&value)].concat(),
			Err(status) => vec![status],
		}
	}

	fn get_info(&self) -> Value {
		let mut options = vec![
			(Value::from("rk"), Value::Bool(true)),
			(Value::from("clientPin"), Value::Bool(self.pin.is_some())),
			(Value::from("pinUvAuthToken"), Value::Bool(true)),
		];
		if self.builtin_uv {
			options.push((Value::from("uv"), Value::Bool(true)));
		}
		Value::map(vec![
			(
				Value::from(1u64),
				Value::Array(vec![Value::from("FIDO_2_0"), Value::from("FIDO_2_1")]),
			),
			(
				Value::from(2u64),
				Value::Array(vec![Value::from(HMAC_SECRET)]),
			),
			(Value::from(3u64), Value::Bytes(AAGUID.to_vec())),
			(Value::from(4u64), Value::map(options).unwrap()),
			(
				Value::from(6u64),
				Value::Array(
					self.protocols
						.iter()
						.map(|p| Value::from(p.number()))
						.collect(),
				),
			),
			(Value::from(8u64), Value::from(128u64)),
		])
		.unwrap()
	}

	fn client_pin(&mut self, params: Option<&Value>) -> Result<Value, u8> {
		let params = params.ok_or(STATUS_MISSING_PARAMETER)?;
		let protocol = params
			.get(&Value::from(1u64))
			.and_then(Value::as_u64)
			.and_then(Protocol::from_number)
			.filter(|p| self.protocols.contains(p))
			.ok_or(ctap::STATUS_INVALID_PARAMETER)?;
		let subcommand = params.get(&Value::from(2u64)).and_then(Value::as_u64);
		match subcommand {
			Some(2) => Ok(Value::map(vec![(
				Value::from(1u64),
				ctap::cose_point(&self.public_point()),
			)])
			.unwrap()),
			Some(sub @ (5 | 9)) => {
				let Some(pin) = self.pin.clone() else {
					return Err(ctap::STATUS_PIN_NOT_SET);
				};
				if self.retries == 0 {
					return Err(ctap::STATUS_PIN_BLOCKED);
				}
				let client = params
					.get(&Value::from(3u64))
					.ok_or(STATUS_MISSING_PARAMETER)
					.and_then(|c| {
						ctap::point_from_cose(c).map_err(|_| ctap::STATUS_INVALID_PARAMETER)
					})?;
				let shared = self
					.shared_with(protocol, &client)
					.ok_or(ctap::STATUS_INVALID_PARAMETER)?;
				let enc = params
					.get(&Value::from(6u64))
					.and_then(Value::as_bytes)
					.ok_or(STATUS_MISSING_PARAMETER)?;
				let offered = shared
					.decrypt(enc)
					.map_err(|_| ctap::STATUS_INVALID_PARAMETER)?;
				if offered.len() != 16 || *offered != pin::pin_hash(&pin)[..] {
					self.retries -= 1;
					return Err(if self.retries == 0 {
						ctap::STATUS_PIN_BLOCKED
					} else {
						ctap::STATUS_PIN_INVALID
					});
				}
				self.retries = 8;
				let permissions = if sub == 9 {
					params
						.get(&Value::from(9u64))
						.and_then(Value::as_u64)
						.ok_or(STATUS_MISSING_PARAMETER)?
				} else {
					ctap::PERMISSION_MAKE_CREDENTIAL | ctap::PERMISSION_GET_ASSERTION
				};
				self.counter += 1;
				let token =
					Zeroizing::new(mac(&self.seed, "token", &self.counter.to_be_bytes()).to_vec());
				let enc = shared
					.encrypt(&token, [0x5A; 16])
					.map_err(|_| ctap::STATUS_INVALID_PARAMETER)?;
				self.tokens.push(Token {
					bytes: token,
					protocol,
					permissions,
				});
				Ok(Value::map(vec![(Value::from(2u64), Value::Bytes(enc))]).unwrap())
			}
			_ => Err(ctap::STATUS_INVALID_PARAMETER),
		}
	}

	/// Checks a `pinUvAuthParam` against the tokens issued: `Ok(true)` when
	/// one matches with the permission, `Ok(false)` when none was given.
	fn verify_pin_auth(
		&self,
		params: &Value,
		param_key: u64,
		protocol_key: u64,
		cdh: &[u8],
		permission: u64,
	) -> Result<Option<usize>, u8> {
		let Some(param) = params
			.get(&Value::from(param_key))
			.and_then(Value::as_bytes)
		else {
			return Ok(None);
		};
		let protocol = params
			.get(&Value::from(protocol_key))
			.and_then(Value::as_u64)
			.and_then(Protocol::from_number)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let valid = self.tokens.iter().position(|t| {
			t.protocol == protocol
				&& t.permissions & permission != 0
				&& pin::authenticate(protocol, &t.bytes, cdh) == param
		});
		if let Some(index) = valid {
			Ok(Some(index))
		} else {
			Err(STATUS_PIN_AUTH_INVALID)
		}
	}

	fn make_credential(&mut self, params: Option<&Value>) -> Result<Value, u8> {
		let params = params.ok_or(STATUS_MISSING_PARAMETER)?;
		let cdh = params
			.get(&Value::from(1u64))
			.and_then(Value::as_bytes)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let rp_id = params
			.get(&Value::from(2u64))
			.and_then(|rp| rp.get(&Value::from("id")))
			.and_then(Value::as_text)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let wants_hmac = params
			.get(&Value::from(6u64))
			.and_then(|e| e.get(&Value::from(HMAC_SECRET)))
			.and_then(Value::as_bool)
			== Some(true);
		let token = self.verify_pin_auth(params, 8, 9, cdh, ctap::PERMISSION_MAKE_CREDENTIAL)?;
		let verified = token.is_some();
		if self.pin.is_some() && !verified {
			return Err(ctap::STATUS_PIN_REQUIRED);
		}
		let builtin = params
			.get(&Value::from(7u64))
			.and_then(|o| o.get(&Value::from("uv")))
			.and_then(Value::as_bool)
			== Some(true);
		if builtin && !self.builtin_uv {
			return Err(ctap::STATUS_INVALID_PARAMETER);
		}
		if !self.touch {
			return Err(ctap::STATUS_OPERATION_DENIED);
		}
		// CTAP 2.1 6.1.2: a completed makeCredential clears the token's
		// permissions and its user flags; the token must be fetched again.
		if let Some(index) = token {
			self.tokens[index].permissions = 0;
		}
		let uv = verified || (builtin && self.builtin_uv);
		let cred_id = self.make_cred_id();
		self.credentials_made += 1;
		let mut auth_data = Vec::new();
		auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
		auth_data.push(
			FLAG_UP | FLAG_AT | if uv { FLAG_UV } else { 0 } | if wants_hmac { FLAG_ED } else { 0 },
		);
		auth_data.extend_from_slice(&self.counter.to_be_bytes());
		auth_data.extend_from_slice(&AAGUID);
		auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
		auth_data.extend_from_slice(&cred_id);
		auth_data.extend(cbor::encode(&ctap::cose_point(&self.public_point())));
		if wants_hmac {
			auth_data.extend(cbor::encode(
				&Value::map(vec![(Value::from(HMAC_SECRET), Value::Bool(true))]).unwrap(),
			));
		}
		Ok(Value::map(vec![
			(Value::from(1u64), Value::from("none")),
			(Value::from(2u64), Value::Bytes(auth_data)),
			(Value::from(3u64), Value::map(vec![]).unwrap()),
		])
		.unwrap())
	}

	fn get_assertion(&mut self, params: Option<&Value>) -> Result<Value, u8> {
		let params = params.ok_or(STATUS_MISSING_PARAMETER)?;
		let rp_id = params
			.get(&Value::from(1u64))
			.and_then(Value::as_text)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let cdh = params
			.get(&Value::from(2u64))
			.and_then(Value::as_bytes)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let allow = params
			.get(&Value::from(3u64))
			.and_then(Value::as_array)
			.ok_or(STATUS_MISSING_PARAMETER)?;
		let cred_id = allow
			.iter()
			.filter_map(|c| c.get(&Value::from("id")).and_then(Value::as_bytes))
			.find(|id| self.owns(id))
			.map(<[u8]>::to_vec)
			.ok_or(ctap::STATUS_NO_CREDENTIALS)?;
		let token = self.verify_pin_auth(params, 6, 7, cdh, ctap::PERMISSION_GET_ASSERTION)?;
		let verified = token.is_some();
		let options = params.get(&Value::from(5u64));
		let builtin = options
			.and_then(|o| o.get(&Value::from("uv")))
			.and_then(Value::as_bool)
			== Some(true);
		if builtin && !self.builtin_uv {
			return Err(ctap::STATUS_INVALID_PARAMETER);
		}
		if !self.touch {
			return Err(ctap::STATUS_OPERATION_DENIED);
		}
		// CTAP 2.1 6.2.2: a completed getAssertion clears the token's
		// permissions and user flags too.
		if let Some(index) = token {
			self.tokens[index].permissions = 0;
		}
		let uv = verified || (builtin && self.builtin_uv);
		let mut extensions = None;
		if let Some(request) = params
			.get(&Value::from(4u64))
			.and_then(|e| e.get(&Value::from(HMAC_SECRET)))
		{
			let client = request
				.get(&Value::from(1u64))
				.ok_or(STATUS_MISSING_PARAMETER)
				.and_then(|c| {
					ctap::point_from_cose(c).map_err(|_| ctap::STATUS_INVALID_PARAMETER)
				})?;
			let salt_enc = request
				.get(&Value::from(2u64))
				.and_then(Value::as_bytes)
				.ok_or(STATUS_MISSING_PARAMETER)?;
			let salt_auth = request
				.get(&Value::from(3u64))
				.and_then(Value::as_bytes)
				.ok_or(STATUS_MISSING_PARAMETER)?;
			let protocol = request
				.get(&Value::from(4u64))
				.and_then(Value::as_u64)
				.and_then(Protocol::from_number)
				.unwrap_or(Protocol::One);
			let shared = self
				.shared_with(protocol, &client)
				.ok_or(ctap::STATUS_INVALID_PARAMETER)?;
			if shared.authenticate(salt_enc) != salt_auth {
				return Err(ctap::STATUS_INVALID_PARAMETER);
			}
			let salts = shared
				.decrypt(salt_enc)
				.map_err(|_| ctap::STATUS_INVALID_PARAMETER)?;
			if salts.len() != 32 && salts.len() != 64 {
				return Err(ctap::STATUS_INVALID_PARAMETER);
			}
			let cred_random = self.cred_random(&cred_id, uv);
			let mut output = Vec::new();
			for salt in salts.as_chunks::<32>().0 {
				let mut m = <Hmac<Sha256>>::new_from_slice(&cred_random).expect("any key length");
				m.update(salt);
				output.extend_from_slice(&m.finalize().into_bytes());
			}
			let enc = shared
				.encrypt(&output, [0xA5; 16])
				.map_err(|_| ctap::STATUS_INVALID_PARAMETER)?;
			extensions =
				Some(Value::map(vec![(Value::from(HMAC_SECRET), Value::Bytes(enc))]).unwrap());
		}
		self.counter += 1;
		let mut auth_data = Vec::new();
		auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
		auth_data.push(
			FLAG_UP | if uv { FLAG_UV } else { 0 } | if extensions.is_some() { FLAG_ED } else { 0 },
		);
		auth_data.extend_from_slice(&self.counter.to_be_bytes());
		if let Some(extensions) = &extensions {
			auth_data.extend(cbor::encode(extensions));
		}
		Ok(Value::map(vec![
			(
				Value::from(1u64),
				Value::map(vec![
					(Value::from("id"), Value::Bytes(cred_id)),
					(Value::from("type"), Value::from("public-key")),
				])
				.unwrap(),
			),
			(Value::from(2u64), Value::Bytes(auth_data)),
			(Value::from(3u64), Value::Bytes(vec![0; 64])),
		])
		.unwrap())
	}
}

/// The key behind a CTAPHID interface: packets in, packets out.
pub struct HidDevice {
	pub key: Authenticator,
	cid: u32,
	inbound: Option<hid::Reassembler>,
	outbound: VecDeque<[u8; hid::PACKET_SIZE]>,
	/// KEEPALIVE packets sent before every CBOR response.
	pub keepalives: u8,
	/// CANCEL packets received.
	pub cancels: u32,
}

impl HidDevice {
	pub fn new(key: Authenticator) -> Self {
		Self {
			key,
			cid: 0x0100_0001,
			inbound: None,
			outbound: VecDeque::new(),
			keepalives: 0,
			cancels: 0,
		}
	}

	/// The channel the head should use, as an INIT would allocate it.
	pub fn cid(&self) -> u32 {
		self.cid
	}

	pub fn write(&mut self, packet: &[u8; hid::PACKET_SIZE]) {
		let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
		if cid == hid::BROADCAST_CID && packet[4] == 0x80 | hid::Command::Init.code() {
			let nonce = &packet[7..15];
			let mut payload = nonce.to_vec();
			payload.extend_from_slice(&self.cid.to_be_bytes());
			payload.extend_from_slice(&[2, 1, 0, 0, hid::CAPABILITY_CBOR]);
			self.outbound
				.extend(hid::frame(hid::BROADCAST_CID, hid::Command::Init, &payload).unwrap());
			return;
		}
		if packet[4] == 0x80 | hid::Command::Cancel.code() {
			self.cancels += 1;
			self.inbound = None;
			return;
		}
		let reassembler = self
			.inbound
			.get_or_insert_with(|| hid::Reassembler::new(self.cid));
		match reassembler.push(packet) {
			Ok(hid::Event::Message {
				command: hid::Command::Cbor,
				payload,
			}) => {
				self.inbound = None;
				let response = self.key.handle(&payload);
				for _ in 0..self.keepalives {
					self.outbound.extend(
						hid::frame(
							self.cid,
							hid::Command::KeepAlive,
							&[hid::KEEPALIVE_UPNEEDED],
						)
						.unwrap(),
					);
				}
				self.outbound
					.extend(hid::frame(self.cid, hid::Command::Cbor, &response).unwrap());
			}
			Ok(hid::Event::Message {
				command: hid::Command::Ping,
				payload,
			}) => {
				self.inbound = None;
				self.outbound
					.extend(hid::frame(self.cid, hid::Command::Ping, &payload).unwrap());
			}
			Ok(hid::Event::Incomplete) => {}
			Ok(_) | Err(_) => {
				self.inbound = None;
				self.outbound
					.extend(hid::frame(self.cid, hid::Command::Error, &[0x01]).unwrap());
			}
		}
	}

	pub fn read(&mut self) -> Option<[u8; hid::PACKET_SIZE]> {
		self.outbound.pop_front()
	}
}

/// The key behind an NFC interface: APDUs in, responses out.
pub struct NfcDevice {
	pub key: Authenticator,
	selected: bool,
	chain: Vec<u8>,
	/// Response bytes not yet delivered, handed out 256 at a time.
	pending: Vec<u8>,
	/// How many `91 00` answers precede each real response.
	pub polls: u8,
	polls_left: u8,
	held: Option<Vec<u8>>,
}

impl NfcDevice {
	pub fn new(key: Authenticator) -> Self {
		Self {
			key,
			selected: false,
			chain: Vec::new(),
			pending: Vec::new(),
			polls: 0,
			polls_left: 0,
			held: None,
		}
	}

	pub fn transceive(&mut self, apdu: &[u8]) -> Vec<u8> {
		if apdu == nfc::select() {
			self.selected = true;
			return [b"FIDO_2_0".as_slice(), &[0x90, 0x00]].concat();
		}
		if !self.selected || apdu.len() < 4 {
			return vec![0x6A, 0x82];
		}
		let (cla, ins) = (apdu[0], apdu[1]);
		if cla == 0x00 && ins == 0xC0 {
			return self.deliver();
		}
		if cla == 0x80 && ins == 0x11 {
			if self.polls_left > 0 {
				self.polls_left -= 1;
				return vec![0x91, 0x00];
			}
			if let Some(response) = self.held.take() {
				self.pending = response;
				return self.deliver();
			}
			return vec![0x6A, 0x88];
		}
		if ins != 0x10 {
			return vec![0x6D, 0x00];
		}
		let data = if apdu.len() > 4 {
			let lc = apdu[4] as usize;
			&apdu[5..5 + lc.min(apdu.len() - 5)]
		} else {
			&[]
		};
		self.chain.extend_from_slice(data);
		if cla & 0x10 != 0 {
			return vec![0x90, 0x00];
		}
		let message = std::mem::take(&mut self.chain);
		let response = self.key.handle(&message);
		if self.polls > 0 {
			self.polls_left = self.polls;
			self.held = Some(response);
			return vec![0x91, 0x00];
		}
		self.pending = response;
		self.deliver()
	}

	fn deliver(&mut self) -> Vec<u8> {
		let take = self.pending.len().min(256);
		let mut out: Vec<u8> = self.pending.drain(..take).collect();
		let left = self.pending.len();
		if left == 0 {
			out.extend_from_slice(&[0x90, 0x00]);
		} else {
			out.extend_from_slice(&[0x61, if left >= 256 { 0 } else { left as u8 }]);
		}
		out
	}
}

/// A simulated device of either transport, and a driver that runs a ceremony
/// against it the way a head would.
pub enum Device {
	Hid(HidDevice),
	Nfc(NfcDevice),
}

impl Device {
	pub fn key(&self) -> &Authenticator {
		match self {
			Self::Hid(d) => &d.key,
			Self::Nfc(d) => &d.key,
		}
	}

	pub fn key_mut(&mut self) -> &mut Authenticator {
		match self {
			Self::Hid(d) => &mut d.key,
			Self::Nfc(d) => &mut d.key,
		}
	}

	pub fn transport(&self) -> crate::ceremony::Transport {
		match self {
			Self::Hid(d) => crate::ceremony::Transport::Hid { cid: d.cid() },
			Self::Nfc(_) => crate::ceremony::Transport::Nfc,
		}
	}

	/// Runs the ceremony from `step` to its end. `pin` answers a PIN prompt;
	/// with none, the prompt is answered by aborting.
	pub fn drive(&mut self, ceremony: &mut Ceremony, mut step: Step, pin: Option<&str>) -> Step {
		for _ in 0..4096 {
			step = match step {
				Step::Write(packets) => {
					let Self::Hid(device) = self else {
						return Step::Failed(crate::ceremony::Failure::Mismatch);
					};
					for packet in &packets {
						device.write(packet);
					}
					Step::Read
				}
				Step::Read => {
					let Self::Hid(device) = self else {
						return Step::Failed(crate::ceremony::Failure::Mismatch);
					};
					let Some(packet) = device.read() else {
						return Step::Failed(crate::ceremony::Failure::Hid(hid::Error::BadLength));
					};
					ceremony.feed(Input::Packet(packet))
				}
				Step::Transceive(apdu) => {
					let Self::Nfc(device) = self else {
						return Step::Failed(crate::ceremony::Failure::Mismatch);
					};
					// A head selects the applet once before any ceremony.
					if !device.selected {
						let answer = device.transceive(&nfc::select());
						assert_eq!(
							nfc::parse_select_response(&answer),
							Ok(nfc::Version::Fido20)
						);
					}
					let response = device.transceive(&apdu);
					ceremony.feed(Input::Apdu(response))
				}
				Step::NeedPin => match pin {
					Some(pin) => ceremony.feed(Input::Pin(Zeroizing::new(pin.to_owned()))),
					None => ceremony.abort(),
				},
				done @ (Step::Done(_) | Step::Failed(_)) => return done,
			};
		}
		Step::Failed(crate::ceremony::Failure::Mismatch)
	}
}
