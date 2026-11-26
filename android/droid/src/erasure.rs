//! Reed-Solomon 8:4 with a `len u64 LE | blake3 | shard` header per shard.

use crate::error::{Error, Result};
use keptino_erasure::ReedSolomon;

const DATA_SHARDS: usize = 8;
const PARITY_SHARDS: usize = 4;
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
const MIN_SHARD_SIZE: usize = 4096;
const HEADER_SIZE: usize = 8 + 32;

pub fn encode(data: &[u8]) -> Vec<u8> {
	let shard_size = data.len().div_ceil(DATA_SHARDS).max(MIN_SHARD_SIZE);
	let mut padded = data.to_vec();
	padded.resize(shard_size * DATA_SHARDS, 0);
	let mut shards: Vec<Vec<u8>> = padded.chunks_exact(shard_size).map(<[u8]>::to_vec).collect();
	shards.resize(TOTAL_SHARDS, vec![0; shard_size]);
	ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
		.and_then(|rs| rs.encode(&mut shards))
		.expect("Fixed erasure geometry");
	let mut output = Vec::with_capacity(TOTAL_SHARDS * (HEADER_SIZE + shard_size));
	for shard in shards {
		output.extend_from_slice(&(data.len() as u64).to_le_bytes());
		output.extend_from_slice(blake3::hash(&shard).as_bytes());
		output.extend_from_slice(&shard);
	}
	output
}

pub fn decode(encoded: &[u8]) -> Result<Vec<u8>> {
	let chunk_size = encoded.len() / TOTAL_SHARDS;
	if chunk_size <= HEADER_SIZE || !encoded.len().is_multiple_of(TOTAL_SHARDS) {
		return Err(Error::Corrupt("not a vault file"));
	}
	let shard_size = chunk_size - HEADER_SIZE;
	let mut lengths = Vec::with_capacity(TOTAL_SHARDS);
	let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(TOTAL_SHARDS);
	for chunk in encoded.chunks_exact(chunk_size) {
		let (header, shard) = chunk.split_at(HEADER_SIZE);
		if blake3::hash(shard).as_bytes() == &header[8..] {
			lengths.push(u64::from_le_bytes(header[..8].try_into().unwrap()));
			shards.push(Some(shard.to_vec()));
		} else {
			shards.push(None);
		}
	}
	// The length is outside the checksum, so trust the most common copy.
	let original_len = lengths
		.iter()
		.max_by_key(|len| lengths.iter().filter(|other| other == len).count())
		.copied()
		.ok_or(Error::Corrupt("no intact shard"))?;
	if original_len > (shard_size * DATA_SHARDS) as u64 {
		return Err(Error::Corrupt("length exceeds shards"));
	}
	ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
		.and_then(|rs| rs.reconstruct_data(&mut shards))
		.map_err(|_| Error::Corrupt("too many damaged shards"))?;
	let mut recovered: Vec<u8> = shards.into_iter().take(DATA_SHARDS).flatten().flatten().collect();
	recovered.truncate(original_len as usize);
	Ok(recovered)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn restores_linux_vault_files_byte_for_byte() {
		for original in [
			include_bytes!("../tests/fixtures/linux-debug.keptino").as_slice(),
			include_bytes!("../tests/fixtures/linux-debug-v2.keptino").as_slice(),
			include_bytes!("../tests/fixtures/linux-debug-unmarked.keptino").as_slice(),
			include_bytes!("../tests/fixtures/linux-release.keptino").as_slice(),
			include_bytes!("../tests/fixtures/linux-release-v2.keptino").as_slice(),
			include_bytes!("../tests/fixtures/linux-release-unmarked.keptino").as_slice(),
		] {
			let mut damaged = original.to_vec();
			let chunk = damaged.len() / TOTAL_SHARDS;
			for shard in [0, 2, 4, 6] {
				damaged[shard * chunk + HEADER_SIZE] ^= 1;
			}
			assert!(encode(&decode(&damaged).unwrap()) == original);
		}
	}

	#[test]
	fn repairs_four_damaged_shards_and_refuses_five() {
		for len in [0usize, 1, 4096 * 8, 4096 * 8 + 1, 100_000] {
			let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
			let encoded = encode(&data);
			assert_eq!(encoded.len() % TOTAL_SHARDS, 0);
			assert_eq!(decode(&encoded).unwrap(), data);
			let chunk = encoded.len() / TOTAL_SHARDS;
			let mut damaged = encoded.clone();
			for shard in [0, 3, 7, 11] {
				damaged[shard * chunk + HEADER_SIZE + 5] ^= 0x80;
			}
			assert_eq!(decode(&damaged).unwrap(), data);
			// A damaged length is outvoted by the other copies.
			damaged[chunk + 2] ^= 1;
			assert_eq!(decode(&damaged).unwrap(), data);
			damaged[5 * chunk + HEADER_SIZE] ^= 1;
			assert!(decode(&damaged).is_err());
		}
	}

	#[test]
	fn garbage_is_rejected() {
		assert!(decode(&[]).is_err());
		assert!(decode(&[0; 11]).is_err());
		assert!(decode(&[0; 12 * 40]).is_err());
		assert!(decode(&[7; 12 * 4136]).is_err());
	}
}
