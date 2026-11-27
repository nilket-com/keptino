//! Key derivation, compression and the cipher, byte-identical on both
//! platforms. The master key is derived into a destination the head owns,
//! so it lands directly in secret memory, and from an Argon2 arena the head
//! may allocate itself, so Android can keep it out of dumps.

use crate::format::KdfParams;
pub use argon2::Block;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
	XChaCha20Poly1305,
	aead::{AeadInPlace, KeyInit},
};
use sha3::{Digest, Sha3_256};
use std::{
	fmt,
	io::{Read, Write},
};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const PEPPER_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdfError {
	/// The cost is outside what Argon2 accepts.
	Params,
	/// The arena for this many KiB could not be allocated.
	Memory(u32),
	/// A pepper seed must not be empty.
	EmptySeed,
}

impl fmt::Display for KdfError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Params => f.write_str("Unsupported key derivation parameters."),
			Self::Memory(kib) => {
				write!(f, "Cannot allocate {} MiB for key derivation.", kib / 1024)
			}
			Self::EmptySeed => f.write_str("The pepper seed must not be empty."),
		}
	}
}

impl std::error::Error for KdfError {}

/// A compressed payload that is not an LZ4 frame or does not decompress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorruptPayload;

/// Wipes every block in place; the arena keeps its length for reuse.
fn wipe(blocks: &mut [Block]) {
	blocks.iter_mut().for_each(Zeroize::zeroize);
}

/// An Argon2 arena for `kdf`, allocated fallibly: on a phone, 4 GiB being
/// unavailable is an expected condition, not a crash.
pub fn arena(kdf: KdfParams) -> Result<Vec<Block>, KdfError> {
	let mut blocks = Vec::new();
	blocks
		.try_reserve_exact(kdf.m_cost as usize)
		.map_err(|_| KdfError::Memory(kdf.m_cost))?;
	blocks.resize(kdf.m_cost as usize, Block::default());
	Ok(blocks)
}

/// The master key: SHA3-256 of salt, pepper and password, through Argon2id
/// salted with salt and pepper, then SHA3-256 with pepper and salt again.
/// `out` receives the key; every intermediate is wiped.
pub fn derive_master_key(
	password: &[u8],
	pepper: &[u8; PEPPER_SIZE],
	salt: &[u8; SALT_SIZE],
	kdf: KdfParams,
	out: &mut [u8; KEY_SIZE],
) -> Result<(), KdfError> {
	let mut blocks = arena(kdf)?;
	let result = derive_master_key_in(password, pepper, salt, kdf, &mut blocks, out);
	wipe(&mut blocks);
	result
}

/// The pepper `linux/setup.sh` derives from the seed with
/// `argon2 digipepper -id -t 4 -m 22 -p 1 -l 32 -r -v 13`: Argon2id over the
/// raw seed, salt `digipepper`, four passes, `mem_kib` of memory.
pub fn derive_pepper(
	seed: &[u8],
	mem_kib: u32,
	out: &mut [u8; PEPPER_SIZE],
) -> Result<(), KdfError> {
	let cost = pepper_cost(seed, mem_kib)?;
	let mut blocks = arena(cost)?;
	let result = derive_pepper_in(seed, mem_kib, &mut blocks, out);
	wipe(&mut blocks);
	result
}

/// As [`derive_pepper`], with an arena the caller allocated for
/// `KdfParams { m_cost: mem_kib, t_cost: 4, p_cost: 1 }`.
pub fn derive_pepper_in(
	seed: &[u8],
	mem_kib: u32,
	blocks: &mut Vec<Block>,
	out: &mut [u8; PEPPER_SIZE],
) -> Result<(), KdfError> {
	let cost = pepper_cost(seed, mem_kib)?;
	let result = argon2id(seed, b"digipepper", cost, blocks, out);
	wipe(blocks);
	result
}

fn pepper_cost(seed: &[u8], mem_kib: u32) -> Result<KdfParams, KdfError> {
	if seed.is_empty() {
		return Err(KdfError::EmptySeed);
	}
	Ok(KdfParams {
		m_cost: mem_kib,
		t_cost: 4,
		p_cost: 1,
	})
}

/// Argon2id version 0x13 into `out`, over a caller-provided arena.
fn argon2id(
	password: &[u8],
	salt: &[u8],
	cost: KdfParams,
	blocks: &mut Vec<Block>,
	out: &mut [u8],
) -> Result<(), KdfError> {
	let params = ParamsBuilder::new()
		.m_cost(cost.m_cost)
		.t_cost(cost.t_cost)
		.p_cost(cost.p_cost)
		.output_len(out.len())
		.build()
		.map_err(|_| KdfError::Params)?;
	Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
		.hash_password_into_with_memory(password, salt, out, blocks.as_mut_slice())
		.map_err(|_| KdfError::Params)
}

/// As [`derive_master_key`], with an arena the caller allocated (see
/// [`arena`]); the arena is wiped before returning.
pub fn derive_master_key_in(
	password: &[u8],
	pepper: &[u8; PEPPER_SIZE],
	salt: &[u8; SALT_SIZE],
	kdf: KdfParams,
	blocks: &mut Vec<Block>,
	out: &mut [u8; KEY_SIZE],
) -> Result<(), KdfError> {
	let mut pre_hasher = Sha3_256::new();
	pre_hasher.update(salt);
	pre_hasher.update(pepper);
	pre_hasher.update(password);
	let mut pre_hash = pre_hasher.finalize();
	let mut derivation_salt = Zeroizing::new([0u8; SALT_SIZE + PEPPER_SIZE]);
	derivation_salt[..SALT_SIZE].copy_from_slice(salt);
	derivation_salt[SALT_SIZE..].copy_from_slice(pepper);
	// The Argon2 output lands straight in the caller's destination, is read
	// from there for the final hash, and is overwritten by it: no intermediate
	// copy of the key material exists outside memory the caller controls.
	let derived = argon2id(&pre_hash, &*derivation_salt, kdf, blocks, out);
	pre_hash.zeroize();
	// Wiped on every path, including a refused cost, since the caller may
	// reuse the arena.
	wipe(blocks);
	derived?;
	let mut post_hasher = Sha3_256::new();
	post_hasher.update(out.as_slice());
	post_hasher.update(pepper);
	post_hasher.update(salt);
	let mut post_hash = post_hasher.finalize();
	out.copy_from_slice(&post_hash);
	post_hash.zeroize();
	Ok(())
}

/// Grows by copying into a new wiping allocation, so a realloc never
/// abandons plaintext in the allocator's old buffer.
#[derive(Default)]
struct WipingWriter(Zeroizing<Vec<u8>>);

impl Write for WipingWriter {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		let required = self
			.0
			.len()
			.checked_add(bytes.len())
			.ok_or_else(|| std::io::Error::other("Plaintext size overflow"))?;
		if required > self.0.capacity() {
			let capacity = required.max(self.0.capacity().saturating_mul(2));
			let mut next = Zeroizing::new(Vec::with_capacity(capacity));
			next.extend_from_slice(&self.0);
			self.0 = next;
		}
		self.0.extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

/// An LZ4 frame at level 9.
pub fn compress(msg: &[u8]) -> Zeroizing<Vec<u8>> {
	let mut encoder = lz4::EncoderBuilder::new()
		.level(9)
		.build(WipingWriter::default())
		.expect("LZ4 encoder");
	encoder.write_all(msg).expect("LZ4 write to memory");
	let (writer, result) = encoder.finish();
	result.expect("LZ4 finish to memory");
	writer.0
}

/// Decompresses at most `budget` bytes; a stream that would go past the
/// budget is refused, so a compressed payload cannot expand without bound
/// into locked memory.
pub fn decompress(msg: &[u8], budget: usize) -> Result<Zeroizing<Vec<u8>>, CorruptPayload> {
	let mut writer = WipingWriter::default();
	let mut remaining = budget;
	let mut decoder = lz4::Decoder::new(msg).map_err(|_| CorruptPayload)?;
	// std::io::copy's ordinary scratch buffer would retain plaintext.
	let mut scratch = Zeroizing::new([0u8; 8192]);
	loop {
		let size = decoder.read(&mut *scratch).map_err(|_| CorruptPayload)?;
		if size == 0 {
			break;
		}
		remaining = remaining.checked_sub(size).ok_or(CorruptPayload)?;
		writer
			.write_all(&scratch[..size])
			.map_err(|_| CorruptPayload)?;
	}
	Ok(writer.0)
}

/// XChaCha20-Poly1305; the tag is appended.
pub fn encrypt(msg: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], aad: &[u8]) -> Vec<u8> {
	let cipher = XChaCha20Poly1305::new(key.into());
	let mut buffer = Zeroizing::new(Vec::with_capacity(msg.len() + 16));
	buffer.extend_from_slice(msg);
	cipher
		.encrypt_in_place(nonce.into(), aad, &mut *buffer)
		.expect("encryption of an in-memory buffer");
	std::mem::take(&mut *buffer)
}

/// `None` when the key, nonce, associated data or ciphertext do not match.
pub fn decrypt(
	msg: Vec<u8>,
	key: &[u8; KEY_SIZE],
	nonce: &[u8; NONCE_SIZE],
	aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
	let cipher = XChaCha20Poly1305::new(key.into());
	let mut buffer = Zeroizing::new(msg);
	cipher
		.decrypt_in_place(nonce.into(), aad, &mut *buffer)
		.ok()?;
	Some(buffer)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn compression_and_cipher_roundtrip_and_reject_damage() {
		let plaintext = b"synthetic vault record\n".repeat(10000);
		let compressed = compress(&plaintext);
		assert!(compressed.len() < plaintext.len() / 10);
		assert_eq!(
			&compressed[..4],
			&[0x04, 0x22, 0x4d, 0x18],
			"LZ4 frame magic"
		);
		let key = [42u8; KEY_SIZE];
		let nonce = [7u8; NONCE_SIZE];
		let encrypted = encrypt(&compressed, &key, &nonce, b"");
		assert_eq!(encrypted.len(), compressed.len() + 16);
		let decoded = decompress(
			&decrypt(encrypted.clone(), &key, &nonce, b"").unwrap(),
			1 << 30,
		)
		.unwrap();
		assert_eq!(&*decoded, &plaintext[..]);
		assert!(decrypt(encrypted.clone(), &key, &nonce, b"aad").is_none());
		let mut damaged = encrypted;
		damaged[0] ^= 1;
		assert!(decrypt(damaged, &key, &nonce, b"").is_none());
		assert_eq!(decompress(b"not lz4", 1 << 30), Err(CorruptPayload));
	}

	#[test]
	fn derivation_is_deterministic_and_cost_bound() {
		let pepper = [9u8; PEPPER_SIZE];
		let salt = [3u8; SALT_SIZE];
		let mut first = [0u8; KEY_SIZE];
		let mut second = [0u8; KEY_SIZE];
		derive_master_key(b"master", &pepper, &salt, KdfParams::DEBUG, &mut first).unwrap();
		let mut blocks = arena(KdfParams::DEBUG).unwrap();
		derive_master_key_in(
			b"master",
			&pepper,
			&salt,
			KdfParams::DEBUG,
			&mut blocks,
			&mut second,
		)
		.unwrap();
		assert_eq!(first, second);
		assert!(
			blocks
				.iter()
				.all(|block| block.as_ref().iter().all(|w| *w == 0)),
			"the arena is wiped"
		);
		let mut other = [0u8; KEY_SIZE];
		derive_master_key(
			b"master",
			&pepper,
			&salt,
			KdfParams {
				m_cost: 8192,
				t_cost: 1,
				p_cost: 1,
			},
			&mut other,
		)
		.unwrap();
		assert_ne!(first, other, "a different cost is a different key");
		derive_master_key(
			b"master",
			&[8; PEPPER_SIZE],
			&salt,
			KdfParams::DEBUG,
			&mut other,
		)
		.unwrap();
		assert_ne!(first, other, "a different pepper is a different key");
		assert_eq!(
			derive_master_key(
				b"x",
				&pepper,
				&salt,
				KdfParams {
					m_cost: 4096,
					t_cost: 0,
					p_cost: 1
				},
				&mut other
			),
			Err(KdfError::Params)
		);
	}

	#[test]
	fn the_pepper_matches_the_argon2_command_line_tool() {
		// printf 'correct horse' | argon2 digipepper -id -t 4 -m 12 -p 1 -l 32 -r -v 13
		let expected = include_str!("../../../android/droid/tests/fixtures/pepper_m12.hex")
			.trim()
			.to_owned();
		let mut pepper = [0u8; PEPPER_SIZE];
		derive_pepper(b"correct horse", 4096, &mut pepper).unwrap();
		assert_eq!(hex::encode(pepper), expected);
		let mut blocks = arena(KdfParams {
			m_cost: 4096,
			t_cost: 4,
			p_cost: 1,
		})
		.unwrap();
		let mut again = [0u8; PEPPER_SIZE];
		derive_pepper_in(b"correct horse", 4096, &mut blocks, &mut again).unwrap();
		assert_eq!(again, pepper);
		assert_eq!(blocks.len(), 4096, "the arena keeps its size");
		assert_eq!(
			derive_pepper(b"", 4096, &mut again),
			Err(KdfError::EmptySeed)
		);
	}
}
