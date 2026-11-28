//! PIN/UV auth protocols 1 and 2 (CTAP 2.1 section 6.5): the key agreement
//! with the authenticator, and the encryption and authentication of what
//! crosses it. Protocol 1 hashes the shared point and uses a zero IV; protocol
//! 2 derives separate HMAC and AES keys with HKDF and sends a random IV.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
	PublicKey, Sec1Point,
	ecdh::EphemeralSecret,
	elliptic_curve::{Generate, sec1::ToSec1Point},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Which protocol the authenticator and client agreed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
	One,
	Two,
}

impl Protocol {
	pub fn number(self) -> u64 {
		match self {
			Self::One => 1,
			Self::Two => 2,
		}
	}

	pub fn from_number(n: u64) -> Option<Self> {
		match n {
			1 => Some(Self::One),
			2 => Some(Self::Two),
			_ => None,
		}
	}

	/// How many bytes `authenticate` yields: protocol 1 truncates to 16.
	pub fn tag_len(self) -> usize {
		match self {
			Self::One => 16,
			Self::Two => 32,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// The authenticator's key agreement point is not on the curve.
	BadPeerKey,
	/// A plaintext or ciphertext length the protocol cannot handle.
	BadLength,
	/// The protocol number is not 1 or 2.
	BadProtocol,
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::BadPeerKey => "The security key sent an invalid key agreement key.",
			Self::BadLength => "A PIN protocol message has an invalid length.",
			Self::BadProtocol => "The security key offers no PIN protocol this build speaks.",
		})
	}
}

impl std::error::Error for Error {}

/// A P-256 point as the two coordinates a COSE key carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
	pub x: [u8; 32],
	pub y: [u8; 32],
}

/// The client's half of one key agreement, used once.
pub struct KeyAgreement {
	secret: EphemeralSecret,
	public: Point,
}

impl KeyAgreement {
	/// A fresh ephemeral key from the OS random source.
	pub fn new() -> Self {
		let secret = EphemeralSecret::generate();
		let public = point_of(&secret.public_key());
		Self { secret, public }
	}

	pub fn public(&self) -> Point {
		self.public
	}

	/// Completes the agreement with the authenticator's point.
	pub fn agree(self, protocol: Protocol, peer: &Point) -> Result<SharedSecret, Error> {
		let encoded = Sec1Point::from_affine_coordinates(&peer.x.into(), &peer.y.into(), false);
		let peer_key =
			PublicKey::from_sec1_bytes(encoded.as_bytes()).map_err(|_| Error::BadPeerKey)?;
		let shared = self.secret.diffie_hellman(&peer_key);
		let z: &[u8] = shared.raw_secret_bytes();
		Ok(SharedSecret::derive(protocol, z))
	}
}

impl Default for KeyAgreement {
	fn default() -> Self {
		Self::new()
	}
}

fn point_of(key: &PublicKey) -> Point {
	let encoded = key.to_sec1_point(false);
	let mut point = Point {
		x: [0; 32],
		y: [0; 32],
	};
	point
		.x
		.copy_from_slice(encoded.x().expect("uncompressed point"));
	point
		.y
		.copy_from_slice(encoded.y().expect("uncompressed point"));
	point
}

/// The agreed secret: 32 bytes for protocol 1, an HMAC key and an AES key of
/// 32 bytes each for protocol 2.
pub struct SharedSecret {
	protocol: Protocol,
	bytes: Zeroizing<Vec<u8>>,
}

impl SharedSecret {
	/// From the raw shared point coordinate `z`; the authenticator side of
	/// the simulator derives it the same way.
	pub fn derive(protocol: Protocol, z: &[u8]) -> Self {
		let bytes = match protocol {
			Protocol::One => Zeroizing::new(Sha256::digest(z).to_vec()),
			Protocol::Two => {
				let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
				let mut out = Zeroizing::new(vec![0u8; 64]);
				hkdf.expand(b"CTAP2 HMAC key", &mut out[..32])
					.expect("32 bytes is a valid HKDF length");
				hkdf.expand(b"CTAP2 AES key", &mut out[32..])
					.expect("32 bytes is a valid HKDF length");
				out
			}
		};
		Self { protocol, bytes }
	}

	pub fn protocol(&self) -> Protocol {
		self.protocol
	}

	fn hmac_key(&self) -> &[u8] {
		&self.bytes[..32]
	}

	fn aes_key(&self) -> &[u8] {
		match self.protocol {
			Protocol::One => &self.bytes[..32],
			Protocol::Two => &self.bytes[32..],
		}
	}

	/// AES-256-CBC without padding; `plaintext` is a multiple of 16 bytes.
	/// Protocol 1 uses a zero IV; protocol 2 prepends the given random IV.
	pub fn encrypt(&self, plaintext: &[u8], iv: [u8; 16]) -> Result<Vec<u8>, Error> {
		if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
			return Err(Error::BadLength);
		}
		let iv = match self.protocol {
			Protocol::One => [0u8; 16],
			Protocol::Two => iv,
		};
		let mut buffer = plaintext.to_vec();
		Aes256CbcEnc::new(self.aes_key().into(), &iv.into())
			.encrypt_padded_mut::<NoPadding>(&mut buffer, plaintext.len())
			.map_err(|_| Error::BadLength)?;
		match self.protocol {
			Protocol::One => Ok(buffer),
			Protocol::Two => Ok([iv.as_slice(), &buffer].concat()),
		}
	}

	pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
		let (iv, body) = match self.protocol {
			Protocol::One => ([0u8; 16], ciphertext),
			Protocol::Two => {
				let (iv, body) = ciphertext.split_at_checked(16).ok_or(Error::BadLength)?;
				(iv.try_into().map_err(|_| Error::BadLength)?, body)
			}
		};
		if body.is_empty() || !body.len().is_multiple_of(16) {
			return Err(Error::BadLength);
		}
		let mut buffer = Zeroizing::new(body.to_vec());
		Aes256CbcDec::new(self.aes_key().into(), &iv.into())
			.decrypt_padded_mut::<NoPadding>(&mut buffer)
			.map_err(|_| Error::BadLength)?;
		Ok(buffer)
	}

	/// HMAC-SHA-256 over `message`, truncated to 16 bytes in protocol 1.
	pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
		authenticate(self.protocol, self.hmac_key(), message)
	}
}

/// HMAC-SHA-256 under `key`, truncated to the protocol's tag length. Also
/// how a PIN/UV auth token signs a command's client data hash.
pub fn authenticate(protocol: Protocol, key: &[u8], message: &[u8]) -> Vec<u8> {
	let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes any key length");
	mac.update(message);
	let mut tag = mac.finalize().into_bytes().to_vec();
	tag.truncate(protocol.tag_len());
	tag
}

/// The 16 bytes of the PIN the authenticator compares: the left half of
/// SHA-256 over the PIN's UTF-8 bytes.
pub fn pin_hash(pin: &[u8]) -> Zeroizing<[u8; 16]> {
	let digest = Sha256::digest(pin);
	let mut out = Zeroizing::new([0u8; 16]);
	out.copy_from_slice(&digest[..16]);
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pair(protocol: Protocol) -> (SharedSecret, SharedSecret) {
		let client = KeyAgreement::new();
		let authenticator = KeyAgreement::new();
		let client_public = client.public();
		let auth_public = authenticator.public();
		(
			client.agree(protocol, &auth_public).unwrap(),
			authenticator.agree(protocol, &client_public).unwrap(),
		)
	}

	#[test]
	fn both_sides_agree_and_messages_round_trip_in_both_protocols() {
		for protocol in [Protocol::One, Protocol::Two] {
			let (client, authenticator) = pair(protocol);
			assert_eq!(client.bytes, authenticator.bytes);
			assert_eq!(
				client.bytes.len(),
				if protocol == Protocol::One { 32 } else { 64 }
			);
			let plaintext = [7u8; 32];
			let sealed = client.encrypt(&plaintext, [9u8; 16]).unwrap();
			assert_eq!(
				sealed.len(),
				if protocol == Protocol::One { 32 } else { 48 }
			);
			assert_eq!(*authenticator.decrypt(&sealed).unwrap(), plaintext.to_vec());
			let tag = client.authenticate(&sealed);
			assert_eq!(tag.len(), protocol.tag_len());
			assert_eq!(authenticator.authenticate(&sealed), tag);
			assert_eq!(client.encrypt(&[1u8; 15], [0; 16]), Err(Error::BadLength));
			assert_eq!(client.encrypt(&[], [0; 16]), Err(Error::BadLength));
			assert!(client.decrypt(&[1u8; 17]).is_err());
			assert_eq!(client.protocol(), protocol);
		}
		assert_eq!(Protocol::from_number(3), None);
		assert_eq!(Protocol::from_number(2), Some(Protocol::Two));
		assert_eq!(Protocol::One.number(), 1);
	}

	#[test]
	fn a_point_off_the_curve_is_refused() {
		let client = KeyAgreement::new();
		let bad = Point {
			x: [1; 32],
			y: [2; 32],
		};
		assert!(matches!(
			client.agree(Protocol::Two, &bad),
			Err(Error::BadPeerKey)
		));
	}

	/// RFC 4231 test case 2 for HMAC-SHA-256: key "Jefe", data "what do ya
	/// want for nothing?". An external vector, so client and simulator cannot
	/// share a mistake in the primitive.
	#[test]
	fn hmac_matches_rfc_4231() {
		let full = authenticate(Protocol::Two, b"Jefe", b"what do ya want for nothing?");
		assert_eq!(
			hex::encode(&full),
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
		);
		let short = authenticate(Protocol::One, b"Jefe", b"what do ya want for nothing?");
		assert_eq!(hex::encode(&short), "5bdcc146bf60754e6a042426089575c7");
	}

	/// NIST SP 800-38A F.2.5, CBC-AES256.Encrypt, first block, driven through
	/// a protocol 2 secret whose AES half is the NIST key.
	#[test]
	fn aes_cbc_matches_nist_sp_800_38a() {
		let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
			.unwrap();
		let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
			.unwrap()
			.try_into()
			.unwrap();
		let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
		let secret = SharedSecret {
			protocol: Protocol::Two,
			bytes: Zeroizing::new([vec![0u8; 32], key].concat()),
		};
		let sealed = secret.encrypt(&plaintext, iv).unwrap();
		assert_eq!(
			hex::encode(&sealed[16..]),
			"f58c4c04d6e5f1ba779eabfb5f7bfbd6"
		);
		assert_eq!(*secret.decrypt(&sealed).unwrap(), plaintext);
	}

	/// RFC 5869 test case 1 through the protocol 2 key schedule's HKDF: the
	/// crate's HKDF output for the RFC inputs matches the RFC.
	#[test]
	fn hkdf_matches_rfc_5869() {
		let ikm = [0x0bu8; 22];
		let salt = hex::decode("000102030405060708090a0b0c").unwrap();
		let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
		let mut okm = [0u8; 42];
		hkdf.expand(&info, &mut okm).unwrap();
		assert_eq!(
			hex::encode(okm),
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
		);
	}

	#[test]
	fn the_pin_hash_is_the_left_half_of_sha256() {
		let digest = Sha256::digest(b"1234");
		assert_eq!(*pin_hash(b"1234"), digest[..16]);
	}
}
