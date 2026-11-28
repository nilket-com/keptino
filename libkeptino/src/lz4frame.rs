//! LZ4 frames in safe Rust (ADR 0038), in place of the C library. The reader
//! decodes every frame the old library wrote: linked or independent blocks,
//! compressed or stored, with or without block checksums, content size and
//! content checksum. The writer stores data in uncompressed blocks, which
//! every LZ4 reader accepts. Output grows only by copying into a new wiping
//! allocation, so plaintext is never left behind in a freed buffer.
//!
//! Format: <https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md> and
//! <https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md>.

use zeroize::Zeroizing;

const MAGIC: u32 = 0x184D_2204;
/// Version 01 in bits 7-6 of FLG.
const VERSION: u8 = 0b0100_0000;
const FLG_INDEPENDENT: u8 = 0b0010_0000;
const FLG_BLOCK_CHECKSUM: u8 = 0b0001_0000;
const FLG_CONTENT_SIZE: u8 = 0b0000_1000;
const FLG_CONTENT_CHECKSUM: u8 = 0b0000_0100;
const FLG_RESERVED: u8 = 0b0000_0010;
const FLG_DICTIONARY: u8 = 0b0000_0001;
/// Block maximum code 4, 64 KiB, the old writer's default.
const BD_64K: u8 = 4 << 4;
const STORED: u32 = 0x8000_0000;
const MIN_MATCH: usize = 4;

/// A frame the reader refuses: damaged, truncated, over budget or using a
/// feature no Keptino writer ever used.
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid;

/// One frame of stored 64 KiB blocks, independent, no checksums: the
/// cipher already authenticates every byte.
pub fn write(data: &[u8]) -> Zeroizing<Vec<u8>> {
	const BLOCK: usize = 64 << 10;
	let blocks = data.len().div_ceil(BLOCK);
	let mut out = Zeroizing::new(Vec::with_capacity(7 + 4 * blocks + data.len() + 4));
	let descriptor = [VERSION | FLG_INDEPENDENT, BD_64K];
	out.extend_from_slice(&MAGIC.to_le_bytes());
	out.extend_from_slice(&descriptor);
	out.push(header_checksum(&descriptor));
	for block in data.chunks(BLOCK) {
		out.extend_from_slice(&(block.len() as u32 | STORED).to_le_bytes());
		out.extend_from_slice(block);
	}
	out.extend_from_slice(&0u32.to_le_bytes());
	out
}

/// Decodes exactly one frame into at most `budget` bytes.
pub fn read(frame: &[u8], budget: usize) -> Result<Zeroizing<Vec<u8>>, Invalid> {
	let mut input = Input(frame);
	if input.u32()? != MAGIC {
		return Err(Invalid);
	}
	let descriptor_start = input.0;
	let flg = input.u8()?;
	let bd = input.u8()?;
	if flg & 0b1100_0000 != VERSION || flg & (FLG_RESERVED | FLG_DICTIONARY) != 0 {
		return Err(Invalid);
	}
	if bd & 0b1000_1111 != 0 || !(4..=7).contains(&(bd >> 4)) {
		return Err(Invalid);
	}
	let block_max = 1usize << (8 + 2 * (bd >> 4));
	let content_size = if flg & FLG_CONTENT_SIZE != 0 {
		let size = input.u64()?;
		Some(usize::try_from(size).map_err(|_| Invalid)?)
	} else {
		None
	};
	let descriptor = &descriptor_start[..descriptor_start.len() - input.0.len()];
	if input.u8()? != header_checksum(descriptor) {
		return Err(Invalid);
	}
	if content_size.is_some_and(|size| size > budget) {
		return Err(Invalid);
	}

	let mut out = Output {
		bytes: Zeroizing::new(Vec::new()),
		budget,
	};
	loop {
		let word = input.u32()?;
		if word == 0 {
			break;
		}
		let size = (word & !STORED) as usize;
		if size > block_max {
			return Err(Invalid);
		}
		let block = input.take(size)?;
		if flg & FLG_BLOCK_CHECKSUM != 0 && input.u32()? != xxh32(block) {
			return Err(Invalid);
		}
		let start = out.bytes.len();
		if word & STORED != 0 {
			out.extend(block)?;
		} else {
			// Linked blocks may refer back into earlier blocks' output.
			let window = if flg & FLG_INDEPENDENT != 0 { start } else { 0 };
			decode_block(block, &mut out, window)?;
		}
		if out.bytes.len() - start > block_max {
			return Err(Invalid);
		}
	}
	if flg & FLG_CONTENT_CHECKSUM != 0 && input.u32()? != xxh32(&out.bytes) {
		return Err(Invalid);
	}
	if content_size.is_some_and(|size| size != out.bytes.len()) || !input.0.is_empty() {
		return Err(Invalid);
	}
	Ok(out.bytes)
}

/// One compressed block: sequences of literals, then a match copied from
/// at most `offset` bytes back, but never before `window`.
fn decode_block(block: &[u8], out: &mut Output, window: usize) -> Result<(), Invalid> {
	let mut input = Input(block);
	loop {
		let token = input.u8()?;
		let literals = input.length(usize::from(token >> 4))?;
		out.extend(input.take(literals)?)?;
		if input.0.is_empty() {
			return Ok(());
		}
		let offset = usize::from(u16::from_le_bytes([input.u8()?, input.u8()?]));
		let length = input.length(usize::from(token & 0x0f))? + MIN_MATCH;
		let position = out.bytes.len();
		if offset == 0 || offset > position - window {
			return Err(Invalid);
		}
		out.copy_back(offset, length)?;
	}
}

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
	fn take(&mut self, size: usize) -> Result<&'a [u8], Invalid> {
		if size > self.0.len() {
			return Err(Invalid);
		}
		let (head, rest) = self.0.split_at(size);
		self.0 = rest;
		Ok(head)
	}

	fn u8(&mut self) -> Result<u8, Invalid> {
		Ok(self.take(1)?[0])
	}

	fn u32(&mut self) -> Result<u32, Invalid> {
		Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
	}

	fn u64(&mut self) -> Result<u64, Invalid> {
		Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
	}

	/// A 4-bit length; 15 continues in bytes, each 255 continuing again.
	fn length(&mut self, nibble: usize) -> Result<usize, Invalid> {
		let mut length = nibble;
		if nibble == 15 {
			loop {
				let byte = self.u8()?;
				length = length.checked_add(usize::from(byte)).ok_or(Invalid)?;
				if byte != 255 {
					break;
				}
			}
		}
		Ok(length)
	}
}

struct Output {
	bytes: Zeroizing<Vec<u8>>,
	budget: usize,
}

impl Output {
	/// Makes room for `extra` more bytes within the budget, moving to a new
	/// wiping allocation rather than letting the old one be reallocated.
	fn reserve(&mut self, extra: usize) -> Result<(), Invalid> {
		let required = self.bytes.len().checked_add(extra).ok_or(Invalid)?;
		if required > self.budget {
			return Err(Invalid);
		}
		if required > self.bytes.capacity() {
			let capacity = required
				.max(self.bytes.capacity().saturating_mul(2))
				.min(self.budget);
			let mut next = Zeroizing::new(Vec::with_capacity(capacity));
			next.extend_from_slice(&self.bytes);
			self.bytes = next;
		}
		Ok(())
	}

	fn extend(&mut self, bytes: &[u8]) -> Result<(), Invalid> {
		self.reserve(bytes.len())?;
		self.bytes.extend_from_slice(bytes);
		Ok(())
	}

	/// Copies `length` bytes starting `offset` back; the source may overlap
	/// what is being written, which repeats the last `offset` bytes.
	fn copy_back(&mut self, offset: usize, length: usize) -> Result<(), Invalid> {
		self.reserve(length)?;
		let start = self.bytes.len() - offset;
		if offset >= length {
			self.bytes.extend_from_within(start..start + length);
		} else {
			for index in start..start + length {
				let byte = self.bytes[index];
				self.bytes.push(byte);
			}
		}
		Ok(())
	}
}

/// The descriptor's check byte: the second byte of its xxHash32.
fn header_checksum(descriptor: &[u8]) -> u8 {
	(xxh32(descriptor) >> 8) as u8
}

/// xxHash32 with seed 0, as the frame format uses it.
pub fn xxh32(data: &[u8]) -> u32 {
	const P1: u32 = 2_654_435_761;
	const P2: u32 = 2_246_822_519;
	const P3: u32 = 3_266_489_917;
	const P4: u32 = 668_265_263;
	const P5: u32 = 374_761_393;
	let round = |acc: u32, lane: &[u8; 4]| {
		acc.wrapping_add(u32::from_le_bytes(*lane).wrapping_mul(P2))
			.rotate_left(13)
			.wrapping_mul(P1)
	};
	let (stripes, rest) = data.as_chunks::<16>();
	let mut hash = if stripes.is_empty() {
		P5
	} else {
		let mut v = [P1.wrapping_add(P2), P2, 0, 0u32.wrapping_sub(P1)];
		for stripe in stripes {
			for (acc, lane) in v.iter_mut().zip(stripe.as_chunks::<4>().0) {
				*acc = round(*acc, lane);
			}
		}
		v[0].rotate_left(1)
			.wrapping_add(v[1].rotate_left(7))
			.wrapping_add(v[2].rotate_left(12))
			.wrapping_add(v[3].rotate_left(18))
	};
	hash = hash.wrapping_add(data.len() as u32);
	let (words, bytes) = rest.as_chunks::<4>();
	for word in words {
		hash = hash
			.wrapping_add(u32::from_le_bytes(*word).wrapping_mul(P3))
			.rotate_left(17)
			.wrapping_mul(P4);
	}
	for &byte in bytes {
		hash = hash
			.wrapping_add(u32::from(byte).wrapping_mul(P5))
			.rotate_left(11)
			.wrapping_mul(P1);
	}
	hash ^= hash >> 15;
	hash = hash.wrapping_mul(P2);
	hash ^= hash >> 13;
	hash = hash.wrapping_mul(P3);
	hash ^ (hash >> 16)
}

#[cfg(test)]
mod tests {
	use super::*;
	use lz4::liblz4::BlockChecksum;
	use lz4::{BlockMode, BlockSize, ContentChecksum};
	use std::io::{Read, Write};

	/// Text-like bytes that compress, with a varying tail that does not.
	fn sample(size: usize) -> Vec<u8> {
		let mut state = 0x9e37_79b9u32;
		(0..size)
			.map(|index| {
				if index % 3000 < 2000 {
					b"keptino entry bank user password note "[index % 38]
				} else {
					state ^= state << 13;
					state ^= state >> 17;
					state ^= state << 5;
					state as u8
				}
			})
			.collect()
	}

	fn real_frame(
		data: &[u8],
		level: u32,
		size: BlockSize,
		mode: BlockMode,
		checks: bool,
	) -> Vec<u8> {
		let mut builder = lz4::EncoderBuilder::new();
		builder
			.level(level)
			.block_size(size)
			.block_mode(mode)
			.checksum(if checks {
				ContentChecksum::ChecksumEnabled
			} else {
				ContentChecksum::NoChecksum
			})
			.block_checksum(if checks {
				BlockChecksum::BlockChecksumEnabled
			} else {
				BlockChecksum::NoBlockChecksum
			});
		if checks {
			builder.content_size(data.len() as u64);
		}
		let mut encoder = builder.build(Vec::new()).unwrap();
		encoder.write_all(data).unwrap();
		let (frame, result) = encoder.finish();
		result.unwrap();
		frame
	}

	#[test]
	fn reads_every_frame_the_c_library_writes() {
		for size in [0, 1, 15, 16, 70_000, 300_000] {
			let data = sample(size);
			for level in [0, 1, 4, 9, 12] {
				for block in [BlockSize::Max64KB, BlockSize::Max256KB, BlockSize::Max4MB] {
					for mode in [BlockMode::Linked, BlockMode::Independent] {
						for checks in [false, true] {
							let frame =
								real_frame(&data, level, block.clone(), mode.clone(), checks);
							let decoded = read(&frame, data.len()).unwrap_or_else(|_| {
								panic!(
									"size {size} level {level} {block:?} {mode:?} checks {checks}"
								)
							});
							assert_eq!(&*decoded, &data[..]);
						}
					}
				}
			}
		}
	}

	#[test]
	fn the_c_library_reads_what_this_writes() {
		for size in [0, 1, 65_536, 65_537, 300_000] {
			let data = sample(size);
			let frame = write(&data);
			let mut decoded = Vec::new();
			lz4::Decoder::new(&frame[..])
				.unwrap()
				.read_to_end(&mut decoded)
				.unwrap();
			assert_eq!(decoded, data);
			assert_eq!(&*read(&frame, size).unwrap(), &data[..]);
		}
	}

	#[test]
	fn xxh32_matches_the_reference_vectors() {
		assert_eq!(xxh32(b""), 0x02CC_5D05);
		assert_eq!(xxh32(b"a"), 0x550D_7456);
		assert_eq!(xxh32(b"abc"), 0x32D1_53FF);
		assert_eq!(
			xxh32(b"Nobody inspects the spammish repetition"),
			0xE229_3B2F
		);
	}

	#[test]
	fn refuses_damage_truncation_trailing_bytes_and_overruns() {
		let data = sample(100_000);
		for frame in [
			real_frame(&data, 9, BlockSize::Max64KB, BlockMode::Linked, true),
			real_frame(&data, 0, BlockSize::Max64KB, BlockMode::Independent, false),
			write(&data).to_vec(),
		] {
			assert!(read(&frame, data.len()).is_ok());
			assert_eq!(read(&frame, data.len() - 1), Err(Invalid), "over budget");
			for cut in [0, 4, 6, 7, frame.len() / 2, frame.len() - 1] {
				assert_eq!(
					read(&frame[..cut], data.len()),
					Err(Invalid),
					"cut at {cut}"
				);
			}
			let mut trailing = frame.clone();
			trailing.push(0);
			assert_eq!(read(&trailing, data.len()), Err(Invalid));
			let mut header = frame.clone();
			header[5] ^= 0x40;
			assert_eq!(read(&header, data.len()), Err(Invalid), "block maximum");
		}
		let checked = real_frame(&data, 9, BlockSize::Max64KB, BlockMode::Linked, true);
		let mut damaged = checked.clone();
		let middle = damaged.len() / 2;
		damaged[middle] ^= 1;
		assert_eq!(read(&damaged, data.len()), Err(Invalid));
		// A match reaching before the start of the output.
		let mut frame = Vec::from(&write(b"")[..7]);
		frame.extend_from_slice(&3u32.to_le_bytes());
		frame.extend_from_slice(&[0x00, 0x01, 0x00]);
		frame.extend_from_slice(&0u32.to_le_bytes());
		assert_eq!(read(&frame, 1 << 20), Err(Invalid));
	}

	#[test]
	fn an_independent_block_cannot_reach_into_the_previous_one() {
		let mut frame = Vec::from(&write(b"")[..7]);
		frame.extend_from_slice(&(4 | STORED).to_le_bytes());
		frame.extend_from_slice(b"abcd");
		// One literal, a 4-byte match at offset 4, then the empty literal run
		// that ends a block. Inside the block only one byte exists, so offset 4
		// reaches into the stored block.
		frame.extend_from_slice(&5u32.to_le_bytes());
		frame.extend_from_slice(&[0x10, b'x', 0x04, 0x00, 0x00]);
		frame.extend_from_slice(&0u32.to_le_bytes());
		assert_eq!(read(&frame, 1 << 20), Err(Invalid));
		// The same block, linked, may.
		frame[4] &= !FLG_INDEPENDENT;
		frame[6] = header_checksum(&frame[4..6]);
		assert_eq!(&*read(&frame, 1 << 20).unwrap(), b"abcdxbcdx");
	}
}
