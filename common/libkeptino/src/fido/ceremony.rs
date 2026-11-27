//! The two ceremonies a head drives against a security key: enroll (make a
//! credential, then assert once to wrap the roaming secret into a key slot)
//! and assert (open one of a vault's slots). Each is a state machine. The
//! head owns the device: a `Step` tells it what to write, read or transceive
//! next, or to ask the user for the PIN, and it feeds back what it got. The
//! head can abort at any step. Nothing here holds a lock or waits.

use crate::fido::ctap::{self, Assertion, AuthData, HmacSecretRequest, Info};
use crate::fido::pin::{self, KeyAgreement, Point, Protocol, SharedSecret};
use crate::fido::{hid, nfc};
use crate::roaming::{KeySlot, MalformedSlot, SLOT_SALT_SIZE, UvMode};
use zeroize::Zeroizing;

/// Which transport the head is using; the ceremony frames for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
	/// CTAPHID on an allocated channel.
	Hid { cid: u32 },
	/// ISO 7816 APDUs after a successful SELECT.
	Nfc,
}

/// What the head does next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
	/// Write these packets to the HID device, in order, then `Read`.
	Write(Vec<[u8; hid::PACKET_SIZE]>),
	/// Read one packet from the HID device and feed it back.
	Read,
	/// Send this APDU and feed the whole response back.
	Transceive(Vec<u8>),
	/// Ask the user for the key's PIN and feed it back; nothing is pending
	/// on the device meanwhile.
	NeedPin,
	Done(Outcome),
	Failed(Failure),
}

/// A ceremony's result. Names only: the roaming secret is in a wiping
/// buffer and the slot holds it sealed.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	/// The new slot for the vault's meta set.
	Enrolled(KeySlot),
	/// Which slot opened and the roaming secret it held.
	Asserted {
		slot: usize,
		roaming: Zeroizing<[u8; 32]>,
	},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
	/// The head aborted, or the user canceled on the key.
	Canceled,
	/// The key does not speak CTAP2.
	NotFido2,
	/// The key has no `hmac-secret` extension.
	NoHmacSecret,
	/// The key offers no PIN protocol this build speaks.
	NoPinProtocol,
	/// User verification was wanted and the key has neither a PIN set nor
	/// built-in verification.
	NoUserVerification,
	WrongPin,
	PinBlocked,
	/// The key refused or timed out waiting for a touch.
	Denied,
	/// No slot belongs to this key, or none opened in its mode.
	NoCredential,
	/// The assertion did not match the request: relying party, flags or
	/// credential.
	Mismatch,
	Hid(hid::Error),
	Nfc(nfc::Error),
	Ctap(ctap::Error),
	Pin(pin::Error),
	Slot(MalformedSlot),
}

impl std::fmt::Display for Failure {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Canceled => f.write_str("Canceled."),
			Self::NotFido2 => f.write_str("This security key does not support FIDO2."),
			Self::NoHmacSecret => {
				f.write_str("This security key cannot protect a vault: no hmac-secret.")
			}
			Self::NoPinProtocol => {
				f.write_str("This security key offers no PIN protocol this build speaks.")
			}
			Self::NoUserVerification => f.write_str(
				"User verification needs a PIN set on the key or built-in verification.",
			),
			Self::WrongPin => f.write_str("Wrong PIN."),
			Self::PinBlocked => {
				f.write_str("The PIN is blocked; unplug the key and try again, or reset it.")
			}
			Self::Denied => f.write_str("The security key did not confirm the touch."),
			Self::NoCredential => f.write_str("No enrolled security key answered."),
			Self::Mismatch => f.write_str("The security key's answer did not match the request."),
			Self::Hid(err) => write!(f, "{err}"),
			Self::Nfc(err) => write!(f, "{err}"),
			Self::Ctap(err) => write!(f, "{err}"),
			Self::Pin(err) => write!(f, "{err}"),
			Self::Slot(_) => f.write_str("The key slot is malformed."),
		}
	}
}

impl From<ctap::Error> for Failure {
	fn from(err: ctap::Error) -> Self {
		match err {
			ctap::Error::Status(ctap::STATUS_KEEPALIVE_CANCEL) => Self::Canceled,
			ctap::Error::Status(ctap::STATUS_PIN_INVALID) => Self::WrongPin,
			ctap::Error::Status(
				ctap::STATUS_PIN_BLOCKED | ctap::STATUS_PIN_AUTH_BLOCKED | ctap::STATUS_UV_BLOCKED,
			) => Self::PinBlocked,
			ctap::Error::Status(ctap::STATUS_PIN_NOT_SET | ctap::STATUS_PIN_REQUIRED) => {
				Self::NoUserVerification
			}
			ctap::Error::Status(
				ctap::STATUS_OPERATION_DENIED | ctap::STATUS_USER_ACTION_TIMEOUT,
			) => Self::Denied,
			ctap::Error::Status(ctap::STATUS_NO_CREDENTIALS) => Self::NoCredential,
			other => Self::Ctap(other),
		}
	}
}

impl From<pin::Error> for Failure {
	fn from(err: pin::Error) -> Self {
		Self::Pin(err)
	}
}

/// What the head feeds back after a step.
pub enum Input {
	Packet([u8; hid::PACKET_SIZE]),
	Apdu(Vec<u8>),
	Pin(Zeroizing<String>),
}

/// How user verification will be obtained for this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verification {
	/// Touch only; no verification.
	None,
	/// A PIN/UV auth token from the key's PIN.
	PinToken,
	/// The key verifies the user itself (fingerprint); `uv` option.
	BuiltIn,
}

enum Goal {
	Enroll {
		uv_mode: UvMode,
		roaming: Zeroizing<[u8; 32]>,
	},
	Assert {
		slots: Vec<KeySlot>,
	},
}

/// Where the ceremony is between two device exchanges.
enum Phase {
	GetInfo,
	KeyAgreement,
	AwaitPin,
	PinToken,
	MakeCredential {
		client_data_hash: Zeroizing<[u8; 32]>,
	},
	Assert {
		slot: usize,
		client_data_hash: Zeroizing<[u8; 32]>,
		salt: [u8; SLOT_SALT_SIZE],
		cred_id: Vec<u8>,
		uv_mode: UvMode,
	},
	Finished,
}

/// One running ceremony.
pub struct Ceremony {
	transport: Transport,
	goal: Goal,
	phase: Phase,
	info: Option<Info>,
	protocol: Option<Protocol>,
	verification: Verification,
	/// The key agreement in flight until the key's point arrives.
	agreement: Option<KeyAgreement>,
	client_point: Option<Point>,
	shared: Option<SharedSecret>,
	pin_token: Option<Zeroizing<Vec<u8>>>,
	/// The PIN hash, kept while a ceremony may need a second token: a key
	/// clears a token's permissions once a command has used it.
	pin_hash: Option<Zeroizing<[u8; 16]>>,
	/// The assertion that wraps the secret, waiting for a fresh token after
	/// the credential was made.
	pending_wrap: Option<(Vec<u8>, [u8; SLOT_SALT_SIZE], UvMode)>,
	/// The credential made by `MakeCredential`, for the enroll assertion.
	new_credential: Option<Vec<u8>>,
	/// Inbound reassembly for the message in flight.
	hid_in: Option<hid::Reassembler>,
	nfc_in: Option<nfc::ResponseAssembler>,
	/// APDU chunks still to send before the response is expected.
	nfc_out: std::collections::VecDeque<Vec<u8>>,
	/// How many exchanges this ceremony may still make; a bound, not a plan.
	budget: u32,
}

const EXCHANGE_BUDGET: u32 = 64;
/// Keptino's user handle: one per vault is not needed, the credential is
/// non-resident and the id is never shown.
const USER_ID: &[u8] = b"keptino";

impl Ceremony {
	/// Starts enrolling a key: a new credential, then one assertion in
	/// `uv_mode` wraps `roaming` into the slot returned by `Done`.
	pub fn enroll(
		transport: Transport,
		uv_mode: UvMode,
		roaming: Zeroizing<[u8; 32]>,
	) -> (Self, Step) {
		let mut ceremony = Self::new(transport, Goal::Enroll { uv_mode, roaming });
		let step = ceremony.send(ctap::get_info());
		(ceremony, step)
	}

	/// Starts opening one of `slots` on the key present.
	pub fn assert(transport: Transport, slots: Vec<KeySlot>) -> (Self, Step) {
		let mut ceremony = Self::new(transport, Goal::Assert { slots });
		let step = ceremony.send(ctap::get_info());
		(ceremony, step)
	}

	fn new(transport: Transport, goal: Goal) -> Self {
		Self {
			transport,
			goal,
			phase: Phase::GetInfo,
			info: None,
			protocol: None,
			verification: Verification::None,
			agreement: None,
			client_point: None,
			shared: None,
			pin_token: None,
			pin_hash: None,
			pending_wrap: None,
			new_credential: None,
			hid_in: None,
			nfc_in: None,
			nfc_out: std::collections::VecDeque::new(),
			budget: EXCHANGE_BUDGET,
		}
	}

	/// Aborts: the head gets the HID cancel packet to write, if any, and the
	/// ceremony is finished as canceled. Nothing on the vault side changed.
	pub fn abort(&mut self) -> Step {
		let pending = !matches!(self.phase, Phase::Finished) && self.hid_in.is_some();
		self.phase = Phase::Finished;
		self.hid_in = None;
		self.nfc_in = None;
		self.nfc_out.clear();
		// Session secrets go now, not when the ceremony is dropped.
		self.pin_token = None;
		self.pin_hash = None;
		self.shared = None;
		self.agreement = None;
		match self.transport {
			Transport::Hid { cid } if pending => Step::Write(vec![hid::cancel(cid)]),
			_ => Step::Failed(Failure::Canceled),
		}
	}

	/// Whether a `Done` or `Failed` step has been returned.
	pub fn is_finished(&self) -> bool {
		matches!(self.phase, Phase::Finished)
	}

	/// Feeds back what the last step asked for and returns the next.
	pub fn feed(&mut self, input: Input) -> Step {
		if self.is_finished() {
			return Step::Failed(Failure::Canceled);
		}
		match input {
			Input::Pin(pin) => self.on_pin(pin),
			Input::Packet(packet) => match self.on_packet(&packet) {
				Ok(Some(response)) => self.on_response(response),
				Ok(None) => Step::Read,
				Err(failure) => self.fail(failure),
			},
			Input::Apdu(apdu) => match self.on_apdu(&apdu) {
				Ok(Some(response)) => self.on_response(response),
				Ok(None) => self.next_nfc_step(),
				Err(failure) => self.fail(failure),
			},
		}
	}

	fn fail(&mut self, failure: Failure) -> Step {
		self.phase = Phase::Finished;
		self.hid_in = None;
		self.nfc_in = None;
		self.nfc_out.clear();
		self.pin_token = None;
		self.pin_hash = None;
		self.shared = None;
		Step::Failed(failure)
	}

	fn finish(&mut self, outcome: Outcome) -> Step {
		self.phase = Phase::Finished;
		self.pin_token = None;
		self.pin_hash = None;
		self.shared = None;
		Step::Done(outcome)
	}

	/// Frames one CTAP message for the transport and returns the step that
	/// sends it.
	fn send(&mut self, message: Vec<u8>) -> Step {
		if self.budget == 0 {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a bounded exchange")));
		}
		self.budget -= 1;
		match self.transport {
			Transport::Hid { cid } => match hid::frame(cid, hid::Command::Cbor, &message) {
				Ok(packets) => {
					self.hid_in = Some(hid::Reassembler::new(cid));
					Step::Write(packets)
				}
				Err(err) => self.fail(Failure::Hid(err)),
			},
			Transport::Nfc => {
				self.nfc_out = nfc::ctap_message(&message).into();
				self.nfc_in = Some(nfc::ResponseAssembler::new());
				self.next_nfc_step()
			}
		}
	}

	fn next_nfc_step(&mut self) -> Step {
		match self.nfc_out.pop_front() {
			Some(apdu) => Step::Transceive(apdu),
			None => self.fail(Failure::Nfc(nfc::Error::Short)),
		}
	}

	/// One HID packet in: the whole CTAP response once complete.
	fn on_packet(&mut self, packet: &[u8; hid::PACKET_SIZE]) -> Result<Option<Vec<u8>>, Failure> {
		let reassembler = self
			.hid_in
			.as_mut()
			.ok_or(Failure::Hid(hid::Error::UnexpectedContinuation))?;
		match reassembler.push(packet).map_err(Failure::Hid)? {
			hid::Event::Incomplete | hid::Event::KeepAlive(_) => Ok(None),
			hid::Event::Message {
				command: hid::Command::Cbor,
				payload,
			} => {
				self.hid_in = None;
				Ok(Some(payload))
			}
			hid::Event::Message { .. } => Err(Failure::Hid(hid::Error::UnknownCommand(0))),
			hid::Event::Error(code) => Err(Failure::Hid(hid::Error::UnknownCommand(code))),
		}
	}

	/// One APDU response in: the whole CTAP response once complete. A chained
	/// chunk's acknowledgment is `90 00` with no data and more to send.
	fn on_apdu(&mut self, response: &[u8]) -> Result<Option<Vec<u8>>, Failure> {
		if !self.nfc_out.is_empty() {
			// An acknowledgment of a chained chunk; the next chunk follows.
			return match response {
				[0x90, 0x00] => Ok(None),
				[.., hi, lo] => Err(Failure::Nfc(nfc::Error::Status(u16::from_be_bytes([
					*hi, *lo,
				])))),
				_ => Err(Failure::Nfc(nfc::Error::Short)),
			};
		}
		let assembler = self
			.nfc_in
			.as_mut()
			.ok_or(Failure::Nfc(nfc::Error::Short))?;
		match assembler.push(response).map_err(Failure::Nfc)? {
			nfc::Step::Done(payload) => {
				self.nfc_in = None;
				Ok(Some(payload))
			}
			nfc::Step::MoreData { le } => {
				self.nfc_out.push_back(nfc::iso_get_response(le));
				Ok(None)
			}
			nfc::Step::Pending => {
				self.nfc_out.push_back(nfc::get_response());
				Ok(None)
			}
		}
	}

	/// A complete CTAP response for the phase in flight.
	fn on_response(&mut self, response: Vec<u8>) -> Step {
		let body = match ctap::response(&response) {
			Ok(body) => body,
			Err(err) => return self.on_status(err),
		};
		let Some(body) = body else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a response body")));
		};
		match std::mem::replace(&mut self.phase, Phase::Finished) {
			Phase::GetInfo => self.after_info(body),
			Phase::KeyAgreement => self.after_key_agreement(body),
			Phase::PinToken => self.after_pin_token(body),
			Phase::MakeCredential { client_data_hash } => {
				self.after_make_credential(body, &client_data_hash)
			}
			Phase::Assert {
				slot,
				client_data_hash,
				salt,
				cred_id,
				uv_mode,
			} => self.after_assertion(body, slot, &client_data_hash, &salt, &cred_id, uv_mode),
			Phase::AwaitPin | Phase::Finished => {
				self.fail(Failure::Ctap(ctap::Error::Shape("an expected phase")))
			}
		}
	}

	/// An error status: most end the ceremony; `NO_CREDENTIALS` during an
	/// assertion moves to the next slot.
	fn on_status(&mut self, err: ctap::Error) -> Step {
		if let (ctap::Error::Status(ctap::STATUS_NO_CREDENTIALS), Phase::Assert { slot, .. }) =
			(&err, &self.phase)
		{
			let next = *slot + 1;
			return self.assert_slot(next);
		}
		self.fail(err.into())
	}

	fn after_info(&mut self, body: crate::fido::cbor::Value) -> Step {
		let info = match Info::parse(&body) {
			Ok(info) => info,
			Err(err) => return self.fail(err.into()),
		};
		if !info.speaks_ctap2() {
			return self.fail(Failure::NotFido2);
		}
		if !info.has_hmac_secret() {
			return self.fail(Failure::NoHmacSecret);
		}
		let Some(protocol) = info.best_protocol() else {
			return self.fail(Failure::NoPinProtocol);
		};
		// A PIN token is needed when the user is to be verified by PIN, and
		// always for makeCredential on a key that has a PIN set.
		let wants_uv = match &self.goal {
			Goal::Enroll { uv_mode, .. } => *uv_mode == UvMode::Verified,
			Goal::Assert { slots } => slots.iter().any(|s| s.uv_mode == UvMode::Verified),
		};
		let enrolling = matches!(self.goal, Goal::Enroll { .. });
		// A key that cannot verify the user skips the verified slots when
		// asserting; it only fails an enrollment that asked for verification.
		self.verification = match (info.client_pin, info.uv) {
			(Some(true), _) if wants_uv || enrolling => Verification::PinToken,
			(_, Some(true)) if wants_uv => Verification::BuiltIn,
			_ if wants_uv && enrolling => return self.fail(Failure::NoUserVerification),
			_ => Verification::None,
		};
		self.protocol = Some(protocol);
		self.info = Some(info);
		// hmac-secret always needs the key agreement, PIN or not.
		let agreement = KeyAgreement::new();
		self.client_point = Some(agreement.public());
		self.agreement = Some(agreement);
		self.phase = Phase::KeyAgreement;
		self.send(ctap::get_key_agreement(protocol))
	}

	fn after_key_agreement(&mut self, body: crate::fido::cbor::Value) -> Step {
		let (Some(agreement), Some(protocol)) = (self.agreement.take(), self.protocol) else {
			return self.fail(Failure::Ctap(ctap::Error::Shape(
				"a key agreement in flight",
			)));
		};
		let point = match ctap::key_agreement_from(&body) {
			Ok(point) => point,
			Err(err) => return self.fail(err.into()),
		};
		match agreement.agree(protocol, &point) {
			Ok(shared) => self.shared = Some(shared),
			Err(err) => return self.fail(err.into()),
		}
		if self.verification == Verification::PinToken {
			self.phase = Phase::AwaitPin;
			return Step::NeedPin;
		}
		self.proceed()
	}

	fn on_pin(&mut self, pin: Zeroizing<String>) -> Step {
		if !matches!(self.phase, Phase::AwaitPin) {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a PIN prompt")));
		}
		let (Some(shared), Some(protocol), Some(client), Some(info)) =
			(&self.shared, self.protocol, self.client_point, &self.info)
		else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a key agreement")));
		};
		let _ = (shared, protocol, client, info);
		self.pin_hash = Some(pin::pin_hash(pin.as_bytes()));
		let permission = match self.goal {
			Goal::Enroll { .. } => ctap::PERMISSION_MAKE_CREDENTIAL,
			Goal::Assert { .. } => ctap::PERMISSION_GET_ASSERTION,
		};
		self.request_token(permission)
	}

	/// Asks the key for a PIN/UV auth token with `permission`, from the PIN
	/// hash kept since the prompt. A CTAP 2.1 key scopes the token to that
	/// permission and clears it after one use, so each command that needs
	/// one asks again.
	fn request_token(&mut self, permission: u64) -> Step {
		let (Some(shared), Some(protocol), Some(client), Some(info), Some(hash)) = (
			&self.shared,
			self.protocol,
			self.client_point,
			&self.info,
			&self.pin_hash,
		) else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a key agreement")));
		};
		let enc = match shared.encrypt(&**hash, random_iv()) {
			Ok(enc) => enc,
			Err(err) => return self.fail(err.into()),
		};
		let permissions = info.pin_uv_auth_token.then_some(permission);
		let message = ctap::get_pin_token(protocol, &client, &enc, permissions);
		self.phase = Phase::PinToken;
		self.send(message)
	}

	fn after_pin_token(&mut self, body: crate::fido::cbor::Value) -> Step {
		let Some(shared) = &self.shared else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a key agreement")));
		};
		let token = match ctap::pin_token_from(&body)
			.map_err(Failure::from)
			.and_then(|enc| shared.decrypt(&enc).map_err(Failure::from))
		{
			Ok(token) => token,
			Err(err) => return self.fail(err),
		};
		self.pin_token = Some(token);
		match self.pending_wrap.take() {
			Some((cred_id, salt, uv_mode)) => self.send_assertion(0, cred_id, salt, uv_mode),
			None => self.proceed(),
		}
	}

	/// With the key agreement and any token in hand: make the credential, or
	/// start on the first slot.
	fn proceed(&mut self) -> Step {
		match &self.goal {
			Goal::Enroll { .. } => {
				let client_data_hash = ctap::client_data_hash();
				let message = ctap::make_credential(
					&client_data_hash,
					USER_ID,
					self.pin_auth(&client_data_hash)
						.as_ref()
						.map(|(tag, p)| (tag.as_slice(), *p)),
					self.verification == Verification::BuiltIn,
				);
				self.phase = Phase::MakeCredential { client_data_hash };
				self.send(message)
			}
			Goal::Assert { .. } => self.assert_slot(0),
		}
	}

	/// The PIN/UV auth param for a command, when a token is held.
	fn pin_auth(&self, client_data_hash: &[u8; 32]) -> Option<(Vec<u8>, Protocol)> {
		let token = self.pin_token.as_ref()?;
		let protocol = self.protocol?;
		Some((
			pin::authenticate(protocol, token, client_data_hash),
			protocol,
		))
	}

	fn after_make_credential(
		&mut self,
		body: crate::fido::cbor::Value,
		_client_data_hash: &[u8; 32],
	) -> Step {
		let auth_data = match ctap::make_credential_from(&body) {
			Ok(data) => data,
			Err(err) => return self.fail(err.into()),
		};
		if auth_data.rp_id_hash != ctap::rp_id_hash() || !auth_data.hmac_secret_enabled() {
			return self.fail(Failure::Mismatch);
		}
		let Some(cred_id) = auth_data.credential_id.clone() else {
			return self.fail(Failure::Mismatch);
		};
		let uv_mode = match &self.goal {
			Goal::Enroll { uv_mode, .. } => *uv_mode,
			Goal::Assert { .. } => return self.fail(Failure::Mismatch),
		};
		self.new_credential = Some(cred_id.clone());
		let mut salt = [0u8; SLOT_SALT_SIZE];
		getrandom::fill(&mut salt).expect("Random generation failed");
		// The token that made the credential is spent; the assertion that
		// wraps the secret under PIN verification needs a fresh one.
		if uv_mode == UvMode::Verified && self.verification == Verification::PinToken {
			self.pending_wrap = Some((cred_id, salt, uv_mode));
			return self.request_token(ctap::PERMISSION_GET_ASSERTION);
		}
		self.send_assertion(0, cred_id, salt, uv_mode)
	}

	/// Starts the assertion for slot `index`, or fails when none is left.
	fn assert_slot(&mut self, index: usize) -> Step {
		let Goal::Assert { slots } = &self.goal else {
			return self.fail(Failure::Mismatch);
		};
		let Some(slot) = slots.get(index) else {
			return self.fail(Failure::NoCredential);
		};
		// A slot wanting verification on a key that cannot verify is skipped.
		if slot.uv_mode == UvMode::Verified && self.verification == Verification::None {
			return self.assert_slot(index + 1);
		}
		let (cred_id, salt, uv_mode) = (slot.cred_id.clone(), slot.salt, slot.uv_mode);
		self.send_assertion(index, cred_id, salt, uv_mode)
	}

	fn send_assertion(
		&mut self,
		slot: usize,
		cred_id: Vec<u8>,
		salt: [u8; SLOT_SALT_SIZE],
		uv_mode: UvMode,
	) -> Step {
		let (Some(shared), Some(protocol), Some(client)) =
			(&self.shared, self.protocol, self.client_point)
		else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a key agreement")));
		};
		let salt_enc = match shared.encrypt(&salt, random_iv()) {
			Ok(enc) => enc,
			Err(err) => return self.fail(err.into()),
		};
		let hmac = HmacSecretRequest {
			key_agreement: client,
			salt_auth: shared.authenticate(&salt_enc),
			salt_enc,
			protocol,
		};
		let client_data_hash = ctap::client_data_hash();
		let verified = uv_mode == UvMode::Verified;
		let pin_auth = if verified && self.verification == Verification::PinToken {
			self.pin_auth(&client_data_hash)
		} else {
			None
		};
		let message = ctap::get_assertion(
			&client_data_hash,
			&cred_id,
			&hmac,
			pin_auth.as_ref().map(|(tag, p)| (tag.as_slice(), *p)),
			verified && self.verification == Verification::BuiltIn,
		);
		self.phase = Phase::Assert {
			slot,
			client_data_hash,
			salt,
			cred_id,
			uv_mode,
		};
		self.send(message)
	}

	fn after_assertion(
		&mut self,
		body: crate::fido::cbor::Value,
		slot: usize,
		_client_data_hash: &[u8; 32],
		salt: &[u8; SLOT_SALT_SIZE],
		cred_id: &[u8],
		uv_mode: UvMode,
	) -> Step {
		let Assertion {
			credential_id,
			auth_data,
		} = match ctap::assertion_from(&body) {
			Ok(assertion) => assertion,
			Err(err) => return self.fail(err.into()),
		};
		if !assertion_matches(&auth_data, credential_id.as_deref(), cred_id, uv_mode) {
			return self.fail(Failure::Mismatch);
		}
		let Some(shared) = &self.shared else {
			return self.fail(Failure::Ctap(ctap::Error::Shape("a key agreement")));
		};
		let output = match auth_data
			.hmac_secret_output()
			.ok_or(Failure::Mismatch)
			.and_then(|enc| shared.decrypt(enc).map_err(Failure::from))
		{
			Ok(output) => output,
			Err(err) => return self.fail(err),
		};
		// One salt was sent, so exactly one 32-byte output comes back.
		if output.len() != 32 {
			return self.fail(Failure::Mismatch);
		}
		let mut hmac_secret = Zeroizing::new([0u8; 32]);
		hmac_secret.copy_from_slice(&output);
		match &self.goal {
			Goal::Enroll { uv_mode, roaming } => {
				match KeySlot::wrap(*uv_mode, cred_id, *salt, &hmac_secret, roaming) {
					Ok(slot) => self.finish(Outcome::Enrolled(slot)),
					Err(err) => self.fail(Failure::Slot(err)),
				}
			}
			Goal::Assert { slots } => match slots[slot].unwrap(&hmac_secret) {
				Some(roaming) => self.finish(Outcome::Asserted { slot, roaming }),
				// The key answered for this credential but in the other mode,
				// or the slot was altered: try the next one.
				None => self.assert_slot(slot + 1),
			},
		}
	}
}

/// The checks before an assertion's extension output is believed: it is for
/// our relying party, the user was present, verified exactly when the slot
/// says so, and it names our credential if it names one.
fn assertion_matches(
	auth_data: &AuthData,
	answered_id: Option<&[u8]>,
	cred_id: &[u8],
	uv_mode: UvMode,
) -> bool {
	auth_data.rp_id_hash == ctap::rp_id_hash()
		&& auth_data.user_present()
		&& auth_data.user_verified() == (uv_mode == UvMode::Verified)
		&& answered_id.is_none_or(|id| id == cred_id)
}

fn random_iv() -> [u8; 16] {
	let mut iv = [0u8; 16];
	getrandom::fill(&mut iv).expect("Random generation failed");
	iv
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fido::sim::{Authenticator, Device, HidDevice, NfcDevice};

	const SEED: [u8; 32] = [0x42; 32];
	const ROAMING: [u8; 32] = [0x33; 32];

	fn roaming() -> Zeroizing<[u8; 32]> {
		Zeroizing::new(ROAMING)
	}

	fn enroll_on(device: &mut Device, uv_mode: UvMode, pin: Option<&str>) -> Step {
		let (mut ceremony, step) = Ceremony::enroll(device.transport(), uv_mode, roaming());
		device.drive(&mut ceremony, step, pin)
	}

	fn assert_on(device: &mut Device, slots: Vec<KeySlot>, pin: Option<&str>) -> Step {
		let (mut ceremony, step) = Ceremony::assert(device.transport(), slots);
		device.drive(&mut ceremony, step, pin)
	}

	fn slot_of(step: Step) -> KeySlot {
		match step {
			Step::Done(Outcome::Enrolled(slot)) => slot,
			other => panic!("expected an enrolled slot, got {other:?}"),
		}
	}

	#[test]
	fn a_touch_only_key_enrolls_and_asserts_over_hid_and_nfc() {
		for mut device in [
			Device::Hid(HidDevice::new(Authenticator::new(SEED))),
			Device::Nfc(NfcDevice::new(Authenticator::new(SEED))),
		] {
			let slot = slot_of(enroll_on(&mut device, UvMode::TouchOnly, None));
			assert_eq!(slot.uv_mode, UvMode::TouchOnly);
			assert_eq!(slot.cred_id.len(), 32);
			assert_eq!(device.key().credentials_made, 1);
			match assert_on(&mut device, vec![slot.clone()], None) {
				Step::Done(Outcome::Asserted { slot: 0, roaming }) => assert_eq!(*roaming, ROAMING),
				other => panic!("{other:?}"),
			}
			// A fresh life of the same key still serves the credential.
			let mut again = Device::Hid(HidDevice::new(Authenticator::new(SEED)));
			assert!(matches!(
				assert_on(&mut again, vec![slot.clone()], None),
				Step::Done(Outcome::Asserted { slot: 0, .. })
			));
			// Another key does not own it and says so without a touch.
			let mut other = Device::Hid(HidDevice::new(Authenticator::new([0x43; 32])));
			assert_eq!(
				assert_on(&mut other, vec![slot.clone()], None),
				Step::Failed(Failure::NoCredential)
			);
			assert_eq!(other.key().credentials_made, 0);
		}
	}

	#[test]
	fn a_pin_key_enrolls_in_both_modes_and_each_slot_opens_only_in_its_mode() {
		let mut device = Device::Hid(HidDevice::new(Authenticator::new(SEED).with_pin("1234")));
		let verified = slot_of(enroll_on(&mut device, UvMode::Verified, Some("1234")));
		let touch = slot_of(enroll_on(&mut device, UvMode::TouchOnly, Some("1234")));
		assert_eq!(verified.uv_mode, UvMode::Verified);
		assert_eq!(touch.uv_mode, UvMode::TouchOnly);
		assert_ne!(verified.cred_id, touch.cred_id);

		// Both slots on the vault: the verified one is first and opens with the PIN.
		match assert_on(
			&mut device,
			vec![verified.clone(), touch.clone()],
			Some("1234"),
		) {
			Step::Done(Outcome::Asserted { slot: 0, roaming }) => assert_eq!(*roaming, ROAMING),
			other => panic!("{other:?}"),
		}
		// A verified slot in the list means the PIN is asked for; declining
		// it cancels the whole unlock rather than falling back silently. A
		// head that wants touch only passes the touch slots alone.
		assert_eq!(
			assert_on(&mut device, vec![verified.clone(), touch.clone()], None),
			Step::Failed(Failure::Canceled)
		);
		match assert_on(&mut device, vec![touch.clone()], None) {
			Step::Done(Outcome::Asserted { slot: 0, .. }) => {}
			other => panic!("{other:?}"),
		}
		// A flipped mode never unwraps: the key answers for the credential in
		// the other mode and the tag fails, so the slot is passed over.
		let mut flipped = touch.clone();
		flipped.uv_mode = UvMode::Verified;
		assert_eq!(
			assert_on(&mut device, vec![flipped], Some("1234")),
			Step::Failed(Failure::NoCredential)
		);
		// A wrong PIN is reported and a retry is spent.
		assert_eq!(
			assert_on(&mut device, vec![verified.clone()], Some("9999")),
			Step::Failed(Failure::WrongPin)
		);
		assert_eq!(device.key().retries_left(), 7);
		// Enrolling without the PIN on a key that has one cannot make a credential.
		assert_eq!(
			enroll_on(&mut device, UvMode::TouchOnly, None),
			Step::Failed(Failure::Canceled)
		);
	}

	#[test]
	fn protocol_one_and_builtin_verification_work_too() {
		let key = Authenticator::new(SEED)
			.with_pin("0000")
			.with_protocols(vec![Protocol::One]);
		let mut device = Device::Nfc(NfcDevice::new(key));
		let slot = slot_of(enroll_on(&mut device, UvMode::Verified, Some("0000")));
		assert!(matches!(
			assert_on(&mut device, vec![slot], Some("0000")),
			Step::Done(Outcome::Asserted { slot: 0, .. })
		));

		let mut biometric = Device::Hid(HidDevice::new(Authenticator::new(SEED).with_builtin_uv()));
		let slot = slot_of(enroll_on(&mut biometric, UvMode::Verified, None));
		assert_eq!(slot.uv_mode, UvMode::Verified);
		assert!(matches!(
			assert_on(&mut biometric, vec![slot], None),
			Step::Done(Outcome::Asserted { slot: 0, .. })
		));

		// Verification wanted, but the key has neither a PIN nor built-in UV:
		// enrollment fails, while an assertion passes over the verified slot.
		let mut bare = Device::Hid(HidDevice::new(Authenticator::new(SEED)));
		assert_eq!(
			enroll_on(&mut bare, UvMode::Verified, None),
			Step::Failed(Failure::NoUserVerification)
		);
		let touch = slot_of(enroll_on(&mut bare, UvMode::TouchOnly, None));
		let verified = slot_of(enroll_on(&mut biometric, UvMode::Verified, None));
		assert!(matches!(
			assert_on(&mut bare, vec![verified, touch], None),
			Step::Done(Outcome::Asserted { slot: 1, .. })
		));
	}

	#[test]
	fn keepalives_chaining_and_pending_answers_are_handled() {
		let mut hid = HidDevice::new(Authenticator::new(SEED));
		hid.keepalives = 3;
		let mut device = Device::Hid(hid);
		let slot = slot_of(enroll_on(&mut device, UvMode::TouchOnly, None));

		let mut nfc = NfcDevice::new(Authenticator::new(SEED));
		nfc.polls = 2;
		let mut device = Device::Nfc(nfc);
		assert!(matches!(
			assert_on(&mut device, vec![slot], None),
			Step::Done(Outcome::Asserted { slot: 0, .. })
		));
	}

	#[test]
	fn a_denied_touch_and_an_abort_leave_nothing_behind() {
		let mut key = Authenticator::new(SEED);
		key.touch = false;
		let mut device = Device::Hid(HidDevice::new(key));
		assert_eq!(
			enroll_on(&mut device, UvMode::TouchOnly, None),
			Step::Failed(Failure::Denied)
		);
		assert_eq!(device.key().credentials_made, 0);

		// Abort while a message is in flight: the cancel packet goes out, the
		// ceremony is finished, and feeding it anything more is refused.
		let mut device = HidDevice::new(Authenticator::new(SEED));
		let (mut ceremony, step) = Ceremony::enroll(
			Transport::Hid { cid: device.cid() },
			UvMode::TouchOnly,
			roaming(),
		);
		let Step::Write(packets) = step else { panic!() };
		for packet in &packets {
			device.write(packet);
		}
		let step = ceremony.abort();
		let Step::Write(cancel) = step else {
			panic!("{step:?}")
		};
		for packet in &cancel {
			device.write(packet);
		}
		assert_eq!(device.cancels, 1);
		assert!(ceremony.is_finished());
		assert_eq!(
			ceremony.feed(Input::Pin(Zeroizing::new("1".into()))),
			Step::Failed(Failure::Canceled)
		);
		assert_eq!(device.key.credentials_made, 0);
		// Abort on NFC has nothing to write.
		let (mut ceremony, _) = Ceremony::assert(Transport::Nfc, vec![]);
		assert_eq!(ceremony.abort(), Step::Failed(Failure::Canceled));
	}

	#[test]
	fn a_key_without_hmac_secret_or_fido2_is_refused_early() {
		// A simulator always has them; a hand-built info answer does not.
		let (mut ceremony, _) = Ceremony::assert(Transport::Nfc, vec![]);
		let info = crate::fido::cbor::Value::map(vec![(
			crate::fido::cbor::Value::from(1u64),
			crate::fido::cbor::Value::Array(vec![crate::fido::cbor::Value::from("U2F_V2")]),
		)])
		.unwrap();
		let response = [
			vec![ctap::STATUS_OK],
			crate::fido::cbor::encode(&info),
			vec![0x90, 0x00],
		]
		.concat();
		assert_eq!(
			ceremony.feed(Input::Apdu(response)),
			Step::Failed(Failure::NotFido2)
		);
		assert!(ceremony.is_finished());
	}
}
