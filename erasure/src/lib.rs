//! Reed-Solomon erasure coding over GF(2^8), the code every Keptino vault
//! file is written with: `data` systematic shards followed by `parity`
//! shards, any `data` of which rebuild the rest. The field uses the
//! polynomial x^8 + x^4 + x^3 + x^2 + 1 and the encoding matrix is a
//! Vandermonde matrix normalised so its top block is the identity, the
//! construction Backblaze published and `reed-solomon-erasure` reproduced,
//! so the parity bytes here are identical to those in existing files. No
//! dependencies, no unsafe code, no SIMD: a vault is kilobytes.

#![forbid(unsafe_code)]

use std::fmt;

/// x^8 + x^4 + x^3 + x^2 + 1, the reducing polynomial of the field.
const POLYNOMIAL: u16 = 0x11D;
/// Field order: shard count is bounded by it.
pub const ORDER: usize = 256;

/// `EXP[i]` is 2^i; doubled so `EXP[log a + log b]` needs no reduction.
/// `LOG[2^i]` is i.
const TABLES: ([u8; 512], [u8; 256]) = {
	let mut exp = [0u8; 512];
	let mut log = [0u8; 256];
	let mut x: u16 = 1;
	let mut i = 0;
	while i < 255 {
		exp[i] = x as u8;
		log[x as usize] = i as u8;
		x <<= 1;
		if x & 0x100 != 0 {
			x ^= POLYNOMIAL;
		}
		i += 1;
	}
	let mut j = 255;
	while j < 512 {
		exp[j] = exp[j - 255];
		j += 1;
	}
	(exp, log)
};
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

#[inline]
fn mul(a: u8, b: u8) -> u8 {
	if a == 0 || b == 0 {
		0
	} else {
		EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
	}
}

fn div(a: u8, b: u8) -> u8 {
	assert!(b != 0, "division by zero in GF(2^8)");
	if a == 0 {
		0
	} else {
		EXP[LOG[a as usize] as usize + 255 - LOG[b as usize] as usize]
	}
}

/// a^n, with a^0 = 1 and 0^n = 0 for n > 0.
fn exp(a: u8, n: usize) -> u8 {
	if n == 0 {
		1
	} else if a == 0 {
		0
	} else {
		EXP[(LOG[a as usize] as usize * n) % 255]
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
	/// No data shards, or no parity shards.
	TooFewShards,
	/// More shards than field elements.
	TooManyShards,
	/// The slice does not hold `data + parity` shards.
	WrongShardCount,
	/// Shards differ in length, or a shard is empty.
	IncorrectShardSize,
	/// Fewer than `data` shards are present, so nothing can be rebuilt.
	TooFewShardsPresent,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::TooFewShards => "at least one data and one parity shard are required",
			Self::TooManyShards => "shard count exceeds the field order",
			Self::WrongShardCount => "the slice must hold data plus parity shards",
			Self::IncorrectShardSize => "shards must be non-empty and equal in length",
			Self::TooFewShardsPresent => "too few shards present to reconstruct",
		})
	}
}

impl std::error::Error for Error {}

/// A dense matrix over the field, rows of equal length.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Matrix {
	rows: usize,
	cols: usize,
	cells: Vec<u8>,
}

impl Matrix {
	fn zero(rows: usize, cols: usize) -> Self {
		Self {
			rows,
			cols,
			cells: vec![0; rows * cols],
		}
	}

	fn identity(n: usize) -> Self {
		let mut m = Self::zero(n, n);
		for i in 0..n {
			m.set(i, i, 1);
		}
		m
	}

	/// Row r holds r^0, r^1, ... r^(cols-1): rows are distinct, so any
	/// square selection of them is invertible.
	fn vandermonde(rows: usize, cols: usize) -> Self {
		let mut m = Self::zero(rows, cols);
		for r in 0..rows {
			for c in 0..cols {
				m.set(r, c, exp(r as u8, c));
			}
		}
		m
	}

	fn get(&self, r: usize, c: usize) -> u8 {
		self.cells[r * self.cols + c]
	}

	fn set(&mut self, r: usize, c: usize, v: u8) {
		self.cells[r * self.cols + c] = v;
	}

	fn row(&self, r: usize) -> &[u8] {
		&self.cells[r * self.cols..(r + 1) * self.cols]
	}

	fn multiply(&self, rhs: &Self) -> Self {
		assert_eq!(self.cols, rhs.rows);
		let mut out = Self::zero(self.rows, rhs.cols);
		for r in 0..self.rows {
			for c in 0..rhs.cols {
				let mut acc = 0;
				for k in 0..self.cols {
					acc ^= mul(self.get(r, k), rhs.get(k, c));
				}
				out.set(r, c, acc);
			}
		}
		out
	}

	fn sub_matrix(&self, rmin: usize, cmin: usize, rmax: usize, cmax: usize) -> Self {
		let mut out = Self::zero(rmax - rmin, cmax - cmin);
		for r in rmin..rmax {
			for c in cmin..cmax {
				out.set(r - rmin, c - cmin, self.get(r, c));
			}
		}
		out
	}

	fn swap_rows(&mut self, a: usize, b: usize) {
		if a == b {
			return;
		}
		for c in 0..self.cols {
			let (x, y) = (self.get(a, c), self.get(b, c));
			self.set(a, c, y);
			self.set(b, c, x);
		}
	}

	/// Gauss-Jordan elimination on [self | I]. `None` when singular.
	fn invert(&self) -> Option<Self> {
		assert_eq!(self.rows, self.cols);
		let n = self.rows;
		let mut work = Self::zero(n, 2 * n);
		for r in 0..n {
			for c in 0..n {
				work.set(r, c, self.get(r, c));
			}
			work.set(r, n + r, 1);
		}
		for col in 0..n {
			if work.get(col, col) == 0 {
				let pivot = (col + 1..n).find(|&r| work.get(r, col) != 0)?;
				work.swap_rows(col, pivot);
			}
			let scale = work.get(col, col);
			if scale != 1 {
				for c in 0..2 * n {
					work.set(col, c, div(work.get(col, c), scale));
				}
			}
			for r in 0..n {
				if r == col {
					continue;
				}
				let factor = work.get(r, col);
				if factor != 0 {
					for c in 0..2 * n {
						let v = work.get(r, c) ^ mul(factor, work.get(col, c));
						work.set(r, c, v);
					}
				}
			}
		}
		Some(work.sub_matrix(0, n, n, 2 * n))
	}
}

/// An encoder and repairer for a fixed shard layout.
#[derive(Clone, Debug)]
pub struct ReedSolomon {
	data: usize,
	parity: usize,
	/// `data + parity` rows by `data` columns; the top block is the identity.
	matrix: Matrix,
}

impl ReedSolomon {
	pub fn new(data: usize, parity: usize) -> Result<Self, Error> {
		if data == 0 || parity == 0 {
			return Err(Error::TooFewShards);
		}
		let total = data + parity;
		if total > ORDER {
			return Err(Error::TooManyShards);
		}
		let vandermonde = Matrix::vandermonde(total, data);
		let top = vandermonde.sub_matrix(0, 0, data, data);
		let matrix = vandermonde.multiply(&top.invert().expect("Vandermonde rows are distinct"));
		debug_assert_eq!(matrix.sub_matrix(0, 0, data, data), Matrix::identity(data));
		Ok(Self {
			data,
			parity,
			matrix,
		})
	}

	pub fn data_shard_count(&self) -> usize {
		self.data
	}

	pub fn parity_shard_count(&self) -> usize {
		self.parity
	}

	pub fn total_shard_count(&self) -> usize {
		self.data + self.parity
	}

	fn shard_len<'a>(&self, present: impl Iterator<Item = &'a [u8]>) -> Result<usize, Error> {
		let mut len = None;
		for shard in present {
			if shard.is_empty() || len.is_some_and(|l| l != shard.len()) {
				return Err(Error::IncorrectShardSize);
			}
			len = Some(shard.len());
		}
		len.ok_or(Error::TooFewShardsPresent)
	}

	/// Computes the parity shards from the data shards in place: `shards`
	/// holds `data + parity` equal-length vectors and the last `parity` of
	/// them are overwritten.
	pub fn encode(&self, shards: &mut [Vec<u8>]) -> Result<(), Error> {
		if shards.len() != self.total_shard_count() {
			return Err(Error::WrongShardCount);
		}
		let len = self.shard_len(shards.iter().map(Vec::as_slice))?;
		let (data, parity) = shards.split_at_mut(self.data);
		for (i, out) in parity.iter_mut().enumerate() {
			let row = self.matrix.row(self.data + i);
			code_row(row, data, out, len);
		}
		Ok(())
	}

	/// Rebuilds every missing data shard from any `data` present shards.
	/// Missing parity shards are left as they are; present shards are not
	/// checked against each other, so verify integrity separately.
	pub fn reconstruct_data(&self, shards: &mut [Option<Vec<u8>>]) -> Result<(), Error> {
		if shards.len() != self.total_shard_count() {
			return Err(Error::WrongShardCount);
		}
		let len = self.shard_len(shards.iter().flatten().map(Vec::as_slice))?;
		if shards[..self.data].iter().all(Option::is_some) {
			return Ok(());
		}
		let valid: Vec<usize> = shards
			.iter()
			.enumerate()
			.filter_map(|(i, s)| s.as_ref().map(|_| i))
			.take(self.data)
			.collect();
		if valid.len() < self.data {
			return Err(Error::TooFewShardsPresent);
		}
		let mut sub = Matrix::zero(self.data, self.data);
		for (r, &index) in valid.iter().enumerate() {
			for c in 0..self.data {
				sub.set(r, c, self.matrix.get(index, c));
			}
		}
		let decode = sub.invert().ok_or(Error::TooFewShardsPresent)?;
		let sources: Vec<Vec<u8>> = valid
			.iter()
			.map(|&i| shards[i].clone().expect("valid index"))
			.collect();
		for (d, shard) in shards.iter_mut().enumerate().take(self.data) {
			if shard.is_none() {
				let mut out = vec![0; len];
				code_row(decode.row(d), &sources, &mut out, len);
				*shard = Some(out);
			}
		}
		Ok(())
	}
}

/// `out[j] = XOR over k of row[k] * inputs[k][j]`.
fn code_row(row: &[u8], inputs: &[Vec<u8>], out: &mut Vec<u8>, len: usize) {
	out.clear();
	out.resize(len, 0);
	for (coefficient, input) in row.iter().zip(inputs) {
		if *coefficient == 0 {
			continue;
		}
		for (o, i) in out.iter_mut().zip(input) {
			*o ^= mul(*coefficient, *i);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A small deterministic generator for the differential tests.
	struct Xorshift(u64);
	impl Xorshift {
		fn next(&mut self) -> u64 {
			let mut x = self.0;
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			self.0 = x;
			x
		}
		fn bytes(&mut self, n: usize) -> Vec<u8> {
			(0..n).map(|_| self.next() as u8).collect()
		}
	}

	#[test]
	fn the_field_is_gf256_with_the_published_polynomial() {
		assert_eq!(EXP[0], 1);
		assert_eq!(EXP[1], 2);
		assert_eq!(EXP[8], 0x1D, "2^8 reduces to the low byte of the polynomial");
		assert_eq!(EXP[255], 1);
		for a in 1..=255u8 {
			assert_eq!(EXP[LOG[a as usize] as usize], a);
			assert_eq!(div(mul(a, 7), 7), a);
			assert_eq!(mul(a, 1), a);
			assert_eq!(mul(a, 0), 0);
		}
		assert_eq!(exp(0, 0), 1);
		assert_eq!(exp(0, 5), 0);
		assert_eq!(exp(2, 8), 0x1D);
		// Cross-check against the implementation being replaced.
		for a in 0..=255u8 {
			for b in [0u8, 1, 2, 3, 29, 100, 200, 255] {
				assert_eq!(mul(a, b), reed_solomon_erasure::galois_8::mul(a, b));
			}
			for n in 0..12 {
				assert_eq!(exp(a, n), reed_solomon_erasure::galois_8::exp(a, n));
			}
		}
	}

	#[test]
	fn matrices_invert_and_the_code_is_systematic() {
		let rs = ReedSolomon::new(8, 4).unwrap();
		assert_eq!(rs.matrix.sub_matrix(0, 0, 8, 8), Matrix::identity(8));
		let m = Matrix::vandermonde(5, 5);
		let inv = m.invert().unwrap();
		assert_eq!(m.multiply(&inv), Matrix::identity(5));
		let mut singular = Matrix::zero(2, 2);
		singular.set(0, 0, 1);
		singular.set(1, 0, 1);
		assert!(singular.invert().is_none());
		assert_eq!(ReedSolomon::new(0, 4).err(), Some(Error::TooFewShards));
		assert_eq!(ReedSolomon::new(4, 0).err(), Some(Error::TooFewShards));
		assert_eq!(ReedSolomon::new(200, 57).err(), Some(Error::TooManyShards));
		assert!(ReedSolomon::new(200, 56).is_ok());
	}

	#[test]
	fn parity_matches_the_replaced_implementation_and_repairs_any_loss() {
		let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
		for (data, parity) in [(8usize, 4usize), (1, 1), (3, 2), (10, 6), (17, 3)] {
			let ours = ReedSolomon::new(data, parity).unwrap();
			let theirs = reed_solomon_erasure::galois_8::ReedSolomon::new(data, parity).unwrap();
			for len in [1usize, 2, 63, 64, 1000, 4096] {
				let mut shards: Vec<Vec<u8>> =
					(0..data + parity).map(|_| rng.bytes(len)).collect();
				let mut reference = shards.clone();
				ours.encode(&mut shards).unwrap();
				theirs.encode(&mut reference).unwrap();
				assert_eq!(shards, reference, "data {data} parity {parity} len {len}");
				// Lose up to `parity` shards anywhere, rebuild the data.
				let mut damaged: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
				let mut lost = 0;
				while lost < parity {
					let i = rng.next() as usize % (data + parity);
					if damaged[i].is_some() {
						damaged[i] = None;
						lost += 1;
					}
				}
				let mut reference_damaged = damaged.clone();
				ours.reconstruct_data(&mut damaged).unwrap();
				theirs.reconstruct_data(&mut reference_damaged).unwrap();
				for d in 0..data {
					assert_eq!(damaged[d].as_deref(), Some(shards[d].as_slice()));
					assert_eq!(damaged[d], reference_damaged[d]);
				}
			}
		}
	}

	#[test]
	fn too_much_loss_and_bad_shapes_are_refused() {
		let rs = ReedSolomon::new(4, 2).unwrap();
		let mut shards: Vec<Vec<u8>> = (0..6).map(|i| vec![i as u8; 16]).collect();
		rs.encode(&mut shards).unwrap();
		let mut lost: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
		lost[0] = None;
		lost[1] = None;
		lost[2] = None;
		assert_eq!(rs.reconstruct_data(&mut lost), Err(Error::TooFewShardsPresent));
		let mut uneven = shards.clone();
		uneven[3].push(0);
		assert_eq!(rs.encode(&mut uneven), Err(Error::IncorrectShardSize));
		assert_eq!(rs.encode(&mut shards[..5]), Err(Error::WrongShardCount));
		let mut empty: Vec<Vec<u8>> = vec![Vec::new(); 6];
		assert_eq!(rs.encode(&mut empty), Err(Error::IncorrectShardSize));
		let mut intact: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
		intact[5] = None;
		assert_eq!(rs.reconstruct_data(&mut intact), Ok(()));
		assert!(intact[5].is_none(), "parity is not rebuilt");
	}

	/// The vault file layout: twelve equal chunks of an 8-byte length, a
	/// 32-byte BLAKE3 and the shard, as `linux/src/storage/persistence.rs`
	/// writes them.
	fn fixture_shards(file: &[u8]) -> Vec<Vec<u8>> {
		let chunk = file.len() / 12;
		assert_eq!(file.len() % 12, 0);
		file.chunks_exact(chunk).map(|c| c[40..].to_vec()).collect()
	}

	#[test]
	fn every_committed_vault_fixture_has_exactly_our_parity() {
		let rs = ReedSolomon::new(8, 4).unwrap();
		for (name, file) in [
			("linux-debug", &include_bytes!("../../android/droid/tests/fixtures/linux-debug.keptino")[..]),
			("linux-release", &include_bytes!("../../android/droid/tests/fixtures/linux-release.keptino")[..]),
			("linux-debug-v2", &include_bytes!("../../android/droid/tests/fixtures/linux-debug-v2.keptino")[..]),
			("linux-release-v2", &include_bytes!("../../android/droid/tests/fixtures/linux-release-v2.keptino")[..]),
			("linux-debug-unmarked", &include_bytes!("../../android/droid/tests/fixtures/linux-debug-unmarked.keptino")[..]),
		] {
			let stored = fixture_shards(file);
			let mut recomputed = stored.clone();
			for parity in &mut recomputed[8..] {
				parity.fill(0);
			}
			rs.encode(&mut recomputed).unwrap();
			assert_eq!(recomputed, stored, "{name}: parity written by reed-solomon-erasure");
			// Repair the worst case the layout allows: four shards gone,
			// three of them data.
			let mut damaged: Vec<Option<Vec<u8>>> = stored.iter().cloned().map(Some).collect();
			for i in [0, 3, 7, 9] {
				damaged[i] = None;
			}
			rs.reconstruct_data(&mut damaged).unwrap();
			for d in 0..8 {
				assert_eq!(damaged[d].as_deref(), Some(stored[d].as_slice()), "{name} shard {d}");
			}
		}
	}
}
