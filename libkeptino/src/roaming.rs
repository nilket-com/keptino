//! Key slots: one enrolled security key's wrapped copy of a vault's roaming
//! secret, carried as a meta entry `fido_slot_1` to `fido_slot_4`. A slot is
//! opened with the 32 bytes the key's `hmac-secret` extension returns for the
//! slot's salt in the slot's user verification mode; anything else fails the
//! tag in microseconds, long before a key derivation arena is allocated.

use crate::crypto::{self, NONCE_SIZE, ROAMING_SIZE};
use base64ct::{Base64, Encoding};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// The one slot layout this build writes and reads.
pub const SLOT_VERSION: u8 = 1;
/// How many slots a vault may carry.
pub const MAX_SLOTS: usize = 4;
/// Meta entry name prefix; the slot number 1 to 4 follows.
pub const SLOT_PREFIX: &str = "fido_slot_";
/// A credential id is at least one byte and at most this many.
pub const MAX_CRED_ID: usize = 256;
/// The salt sent to the key as `hmac-secret` salt1.
pub const SLOT_SALT_SIZE: usize = 32;
/// The `hmac-secret` output the key returns for that salt.
pub const HMAC_SECRET_SIZE: usize = 32;
const WRAPPED_SIZE: usize = ROAMING_SIZE + 16;
const KEY_DOMAIN: &[u8] = b"keptino-fido2-slot-v1";
const AAD_DOMAIN: &[u8] = b"keptino-fido2-slot-aad-v1";

/// Whether the key verified the user (PIN or built-in) when it released
/// the secret. A CTAP 2.1 key keeps two secrets per credential and picks
/// by this, so a slot wrapped one way never unwraps the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UvMode {
	TouchOnly,
	Verified,
}

impl UvMode {
	pub fn byte(self) -> u8 {
		match self {
			Self::TouchOnly => 0,
			Self::Verified => 1,
		}
	}

	fn from_byte(byte: u8) -> Option<Self> {
		match byte {
			0 => Some(Self::TouchOnly),
			1 => Some(Self::Verified),
			_ => None,
		}
	}
}

/// One enrolled security key's wrapped copy of the roaming secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
	pub uv_mode: UvMode,
	pub cred_id: Vec<u8>,
	pub salt: [u8; SLOT_SALT_SIZE],
	nonce: [u8; NONCE_SIZE],
	wrapped: [u8; WRAPPED_SIZE],
}

/// A slot entry that is not one this build can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MalformedSlot;

impl KeySlot {
	/// Wraps `roaming` for a key that returned `hmac_secret` for `salt` in
	/// `uv_mode`. The nonce is random; the salt was random when the slot was
	/// made and travels with it.
	pub fn wrap(
		uv_mode: UvMode,
		cred_id: &[u8],
		salt: [u8; SLOT_SALT_SIZE],
		hmac_secret: &[u8; HMAC_SECRET_SIZE],
		roaming: &[u8; ROAMING_SIZE],
	) -> Result<Self, MalformedSlot> {
		if cred_id.is_empty() || cred_id.len() > MAX_CRED_ID {
			return Err(MalformedSlot);
		}
		let mut nonce = [0u8; NONCE_SIZE];
		getrandom::fill(&mut nonce).expect("Nonce generation failed");
		let key = sealing_key(uv_mode, &salt, hmac_secret);
		let aad = aad(uv_mode, cred_id, &salt);
		let sealed = crypto::encrypt(roaming, &key, &nonce, &aad);
		let mut wrapped = [0u8; WRAPPED_SIZE];
		wrapped.copy_from_slice(&sealed);
		Ok(Self {
			uv_mode,
			cred_id: cred_id.to_vec(),
			salt,
			nonce,
			wrapped,
		})
	}

	/// The roaming secret, if `hmac_secret` is what the enrolled key returns
	/// for this slot in its mode.
	pub fn unwrap(
		&self,
		hmac_secret: &[u8; HMAC_SECRET_SIZE],
	) -> Option<Zeroizing<[u8; ROAMING_SIZE]>> {
		let key = sealing_key(self.uv_mode, &self.salt, hmac_secret);
		let aad = aad(self.uv_mode, &self.cred_id, &self.salt);
		let plain = crypto::decrypt(self.wrapped.to_vec(), &key, &self.nonce, &aad)?;
		let mut roaming = Zeroizing::new([0u8; ROAMING_SIZE]);
		roaming.copy_from_slice(&plain);
		Some(roaming)
	}

	/// The meta entry value: base64 of version, mode, credential id with its
	/// length, salt, nonce and the sealed secret.
	pub fn encode(&self) -> String {
		let mut bytes =
			Vec::with_capacity(4 + self.cred_id.len() + SLOT_SALT_SIZE + NONCE_SIZE + WRAPPED_SIZE);
		bytes.push(SLOT_VERSION);
		bytes.push(self.uv_mode.byte());
		bytes.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
		bytes.extend_from_slice(&self.cred_id);
		bytes.extend_from_slice(&self.salt);
		bytes.extend_from_slice(&self.nonce);
		bytes.extend_from_slice(&self.wrapped);
		Base64::encode_string(&bytes)
	}

	pub fn decode(text: &str) -> Result<Self, MalformedSlot> {
		let bytes = Base64::decode_vec(text).map_err(|_| MalformedSlot)?;
		let (&version, rest) = bytes.split_first().ok_or(MalformedSlot)?;
		if version != SLOT_VERSION {
			return Err(MalformedSlot);
		}
		let (&mode, rest) = rest.split_first().ok_or(MalformedSlot)?;
		let uv_mode = UvMode::from_byte(mode).ok_or(MalformedSlot)?;
		let (len, rest) = rest.split_at_checked(2).ok_or(MalformedSlot)?;
		let len = u16::from_be_bytes([len[0], len[1]]) as usize;
		if len == 0 || len > MAX_CRED_ID {
			return Err(MalformedSlot);
		}
		let (cred_id, rest) = rest.split_at_checked(len).ok_or(MalformedSlot)?;
		let (salt, rest) = rest.split_at_checked(SLOT_SALT_SIZE).ok_or(MalformedSlot)?;
		let (nonce, wrapped) = rest.split_at_checked(NONCE_SIZE).ok_or(MalformedSlot)?;
		if wrapped.len() != WRAPPED_SIZE {
			return Err(MalformedSlot);
		}
		Ok(Self {
			uv_mode,
			cred_id: cred_id.to_vec(),
			salt: salt.try_into().map_err(|_| MalformedSlot)?,
			nonce: nonce.try_into().map_err(|_| MalformedSlot)?,
			wrapped: wrapped.try_into().map_err(|_| MalformedSlot)?,
		})
	}

	/// The meta entry name of slot `index`, counted from zero.
	pub fn entry_name(index: usize) -> String {
		format!("{SLOT_PREFIX}{}", index + 1)
	}
}

/// SHA3-256 over the domain, the version, the mode, the salt and the
/// `hmac-secret` output. Every field is fixed-size, so the input is
/// unambiguous without lengths.
fn sealing_key(
	uv_mode: UvMode,
	salt: &[u8; SLOT_SALT_SIZE],
	hmac_secret: &[u8; HMAC_SECRET_SIZE],
) -> Zeroizing<[u8; crypto::KEY_SIZE]> {
	let mut hasher = Sha3_256::new();
	hasher.update(KEY_DOMAIN);
	hasher.update([SLOT_VERSION, uv_mode.byte()]);
	hasher.update(salt);
	hasher.update(hmac_secret);
	let mut key = Zeroizing::new([0u8; crypto::KEY_SIZE]);
	key.copy_from_slice(&hasher.finalize());
	key
}

/// The associated data: domain, version, mode, then each variable field
/// behind a two-byte big-endian length, so the layout is injective.
fn aad(uv_mode: UvMode, cred_id: &[u8], salt: &[u8; SLOT_SALT_SIZE]) -> Vec<u8> {
	let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 6 + cred_id.len() + SLOT_SALT_SIZE);
	out.extend_from_slice(AAD_DOMAIN);
	out.push(SLOT_VERSION);
	out.push(uv_mode.byte());
	out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
	out.extend_from_slice(cred_id);
	out.extend_from_slice(&(SLOT_SALT_SIZE as u16).to_be_bytes());
	out.extend_from_slice(salt);
	out
}

/// Reads the slots of an envelope's meta pairs: `fido_slot_1` onward,
/// contiguous, at most four. A gap, a fifth slot or a malformed value is
/// `Err`, so a damaged or tampered slot set never opens as a smaller one.
pub fn slots_from_meta<'a>(
	pairs: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<KeySlot>, MalformedSlot> {
	let mut found: Vec<Option<KeySlot>> = vec![None; MAX_SLOTS];
	for (name, value) in pairs {
		let Some(number) = name.strip_prefix(SLOT_PREFIX) else {
			continue;
		};
		let index = match number.parse::<usize>() {
			Ok(n) if (1..=MAX_SLOTS).contains(&n) && number == n.to_string() => n - 1,
			_ => return Err(MalformedSlot),
		};
		if found[index].is_some() {
			return Err(MalformedSlot);
		}
		found[index] = Some(KeySlot::decode(value)?);
	}
	let mut slots = Vec::new();
	let mut ended = false;
	for slot in found {
		match (slot, ended) {
			(Some(slot), false) => slots.push(slot),
			(None, _) => ended = true,
			(Some(_), true) => return Err(MalformedSlot),
		}
	}
	Ok(slots)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn slot(uv_mode: UvMode, hmac_secret: &[u8; 32], roaming: &[u8; 32]) -> KeySlot {
		KeySlot::wrap(
			uv_mode,
			b"credential-id-bytes",
			[7u8; SLOT_SALT_SIZE],
			hmac_secret,
			roaming,
		)
		.unwrap()
	}

	#[test]
	fn a_slot_wraps_round_trips_and_unwraps_only_for_its_key_and_mode() {
		let roaming = [0x33u8; ROAMING_SIZE];
		let secret = [0x44u8; HMAC_SECRET_SIZE];
		let slot = slot(UvMode::Verified, &secret, &roaming);
		assert_eq!(*slot.unwrap(&secret).unwrap(), roaming);
		let text = slot.encode();
		let again = KeySlot::decode(&text).unwrap();
		assert_eq!(again, slot);
		assert_eq!(*again.unwrap(&secret).unwrap(), roaming);
		assert!(
			slot.unwrap(&[0x45u8; HMAC_SECRET_SIZE]).is_none(),
			"another key"
		);
		let mut flipped = slot.clone();
		flipped.uv_mode = UvMode::TouchOnly;
		assert!(flipped.unwrap(&secret).is_none(), "flipped mode");
		let mut other_id = slot.clone();
		other_id.cred_id[0] ^= 1;
		assert!(other_id.unwrap(&secret).is_none(), "altered credential id");
		let mut other_salt = slot.clone();
		other_salt.salt[0] ^= 1;
		assert!(other_salt.unwrap(&secret).is_none(), "altered salt");
	}

	#[test]
	fn malformed_slots_are_refused() {
		assert_eq!(
			KeySlot::wrap(UvMode::TouchOnly, b"", [0; 32], &[0; 32], &[0; 32]),
			Err(MalformedSlot)
		);
		assert_eq!(
			KeySlot::wrap(
				UvMode::TouchOnly,
				&[0; MAX_CRED_ID + 1],
				[0; 32],
				&[0; 32],
				&[0; 32]
			),
			Err(MalformedSlot)
		);
		let good = slot(UvMode::TouchOnly, &[1; 32], &[2; 32]).encode();
		assert_eq!(KeySlot::decode("not base64!"), Err(MalformedSlot));
		assert_eq!(KeySlot::decode(""), Err(MalformedSlot));
		let mut bytes = Base64::decode_vec(&good).unwrap();
		bytes[0] = 2;
		assert_eq!(
			KeySlot::decode(&Base64::encode_string(&bytes)),
			Err(MalformedSlot),
			"version"
		);
		bytes[0] = 1;
		bytes[1] = 2;
		assert_eq!(
			KeySlot::decode(&Base64::encode_string(&bytes)),
			Err(MalformedSlot),
			"mode"
		);
		bytes[1] = 0;
		bytes.pop();
		assert_eq!(
			KeySlot::decode(&Base64::encode_string(&bytes)),
			Err(MalformedSlot),
			"short"
		);
	}

	#[test]
	fn slots_are_read_in_order_and_gaps_duplicates_and_a_fifth_are_refused() {
		let a = slot(UvMode::TouchOnly, &[1; 32], &[9; 32]);
		let b = slot(UvMode::Verified, &[2; 32], &[9; 32]);
		let (ea, eb) = (a.encode(), b.encode());
		let read = |pairs: &[(&str, &str)]| slots_from_meta(pairs.iter().copied());
		assert_eq!(read(&[("db_name", "x")]).unwrap(), vec![]);
		assert_eq!(
			read(&[("fido_slot_2", &eb), ("fido_slot_1", &ea)]).unwrap(),
			vec![a.clone(), b.clone()]
		);
		assert_eq!(read(&[("fido_slot_2", &eb)]), Err(MalformedSlot), "gap");
		assert_eq!(
			read(&[("fido_slot_1", &ea), ("fido_slot_1", &eb)]),
			Err(MalformedSlot),
			"duplicate"
		);
		assert_eq!(read(&[("fido_slot_5", &ea)]), Err(MalformedSlot), "fifth");
		assert_eq!(
			read(&[("fido_slot_01", &ea)]),
			Err(MalformedSlot),
			"odd number"
		);
		assert_eq!(read(&[("fido_slot_x", &ea)]), Err(MalformedSlot));
		assert_eq!(read(&[("fido_slot_1", "bad")]), Err(MalformedSlot));
		assert_eq!(KeySlot::entry_name(0), "fido_slot_1");
		assert_eq!(KeySlot::entry_name(3), "fido_slot_4");
	}
}
