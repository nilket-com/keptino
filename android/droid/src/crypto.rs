//! Key derivation, compression and encryption, byte-compatible with the
//! Linux application.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
	XChaCha20Poly1305,
	aead::{AeadInPlace, KeyInit},
};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const PEPPER_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
/// Argon2 memory of release builds of the Linux application: 4 GiB.
pub const RELEASE_MEM_KIB: u32 = 1 << 22;
/// Argon2 memory of debug builds of the Linux application: 4 MiB.
pub const DEBUG_MEM_KIB: u32 = 1 << 12;

pub type Key = Zeroizing<[u8; KEY_SIZE]>;

fn argon2id(password: &[u8], salt: &[u8], t_cost: u32, mem_kib: u32) -> Result<Key> {
	let params = ParamsBuilder::new()
		.m_cost(mem_kib)
		.t_cost(t_cost)
		.p_cost(1)
		.output_len(KEY_SIZE)
		.build()
		.map_err(|e| Error::Kdf(e.to_string()))?;
	let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
	// Allocate fallibly: the default path aborts the process when 4 GiB is
	// unavailable, which on a phone is an expected condition.
	let mut blocks = Vec::new();
	blocks
		.try_reserve_exact(mem_kib as usize)
		.map_err(|_| Error::Kdf(format!("cannot allocate {} MiB", mem_kib / 1024)))?;
	blocks.resize(mem_kib as usize, argon2::Block::default());
	let mut out = Zeroizing::new([0u8; KEY_SIZE]);
	let result = hasher.hash_password_into_with_memory(password, salt, &mut *out, &mut blocks);
	for block in &mut blocks {
		*block = argon2::Block::default();
	}
	result.map_err(|e| Error::Kdf(e.to_string()))?;
	Ok(out)
}

/// The pepper `linux/setup.sh` derives from the pepper seed with
/// `argon2 digipepper -id -t 4 -m 22 -p 1 -l 32 -r -v 13`.
pub fn derive_pepper(seed: &[u8], mem_kib: u32) -> Result<Zeroizing<[u8; PEPPER_SIZE]>> {
	if seed.is_empty() {
		return Err(Error::Invalid("empty pepper seed"));
	}
	argon2id(seed, b"digipepper", 4, mem_kib)
}

pub fn derive_master_key(
	password: &[u8],
	pepper: &[u8; PEPPER_SIZE],
	salt: &[u8; SALT_SIZE],
	mem_kib: u32,
) -> Result<Key> {
	let mut pre_hasher = Sha3_256::new();
	pre_hasher.update(salt);
	pre_hasher.update(pepper);
	pre_hasher.update(password);
	let mut pre_hash = pre_hasher.finalize();
	let mut derivation_salt = Zeroizing::new([0u8; SALT_SIZE + PEPPER_SIZE]);
	derivation_salt[..SALT_SIZE].copy_from_slice(salt);
	derivation_salt[SALT_SIZE..].copy_from_slice(pepper);
	let main_hash = argon2id(&pre_hash, &*derivation_salt, 1, mem_kib);
	pre_hash.zeroize();
	let main_hash = main_hash?;
	let mut post_hasher = Sha3_256::new();
	post_hasher.update(main_hash.as_slice());
	post_hasher.update(pepper);
	post_hasher.update(salt);
	let mut post_hash = post_hasher.finalize();
	let mut key = Zeroizing::new([0u8; KEY_SIZE]);
	key.copy_from_slice(&post_hash);
	post_hash.zeroize();
	Ok(key)
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

/// LZ4 frame at level 9, as the Linux application writes it.
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

pub fn decompress(msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
	let corrupt = |_| Error::Corrupt("compressed database");
	let mut writer = WipingWriter::default();
	let mut decoder = lz4::Decoder::new(msg).map_err(corrupt)?;
	let mut scratch = Zeroizing::new([0u8; 8192]);
	loop {
		let size = decoder.read(&mut *scratch).map_err(corrupt)?;
		if size == 0 {
			break;
		}
		writer.write_all(&scratch[..size]).map_err(corrupt)?;
	}
	Ok(writer.0)
}

pub fn encrypt(msg: &[u8], key: &Key, nonce: &[u8; NONCE_SIZE]) -> Vec<u8> {
	let cipher = XChaCha20Poly1305::new((&**key).into());
	let mut buffer = Zeroizing::new(Vec::with_capacity(msg.len() + 16));
	buffer.extend_from_slice(msg);
	cipher
		.encrypt_in_place(nonce.into(), b"", &mut *buffer)
		.expect("Encryption of an in-memory buffer");
	std::mem::take(&mut *buffer)
}

pub fn decrypt(msg: Vec<u8>, key: &Key, nonce: &[u8; NONCE_SIZE]) -> Result<Zeroizing<Vec<u8>>> {
	let cipher = XChaCha20Poly1305::new((&**key).into());
	let mut buffer = Zeroizing::new(msg);
	cipher
		.decrypt_in_place(nonce.into(), b"", &mut *buffer)
		.map_err(|_| Error::Decryption)?;
	Ok(buffer)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn compression_and_cipher_roundtrip_and_reject_damage() {
		let plaintext = b"synthetic vault record\n".repeat(10000);
		let compressed = compress(&plaintext);
		assert!(compressed.len() < plaintext.len() / 10);
		// LZ4 frame magic.
		assert_eq!(&compressed[..4], &[0x04, 0x22, 0x4d, 0x18]);
		let key = Zeroizing::new([42u8; KEY_SIZE]);
		let nonce = [7u8; NONCE_SIZE];
		let encrypted = encrypt(&compressed, &key, &nonce);
		assert_eq!(encrypted.len(), compressed.len() + 16);
		let decoded = decompress(&decrypt(encrypted.clone(), &key, &nonce).unwrap()).unwrap();
		assert_eq!(&*decoded, &plaintext);
		let mut damaged = encrypted;
		damaged[0] ^= 1;
		assert_eq!(decrypt(damaged, &key, &nonce).unwrap_err(), Error::Decryption);
		assert!(decompress(b"not lz4").is_err());
	}

	#[test]
	fn pepper_matches_the_argon2_command_line_tool() {
		// printf 'correct horse' | argon2 digipepper -id -t 4 -m 12 -p 1 -l 32 -r -v 13
		let pepper = derive_pepper(b"correct horse", DEBUG_MEM_KIB).unwrap();
		assert_eq!(hex::encode(*pepper), include_str!("../tests/fixtures/pepper_m12.hex").trim());
		assert!(derive_pepper(b"", DEBUG_MEM_KIB).is_err());
	}
}
