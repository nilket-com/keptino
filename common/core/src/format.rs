//! The vault file. Records are TLV, `tag u8 | len u32 LE | value`. A
//! database is a sequence of entry records, each holding a field record set;
//! a file is the database's meta entries copied into a plaintext envelope
//! beside the ciphertext, the whole thing erasure coded into twelve shards.
//!
//! The envelope copies are the integrity check: after decryption the
//! plaintext meta set must equal the authenticated copy inside, so a changed,
//! added or dropped plaintext field fails like a wrong key. That needs no
//! marker and holds for every vault ever written. Files marked `format` 2
//! were written, for a few hours, with the same metadata bound as associated
//! data instead; they still open and are converted on their next save.

use crate::crypto::{NONCE_SIZE, SALT_SIZE};
use base64ct::{Base64, Encoding};
use keptino_erasure::ReedSolomon;
use std::{collections::BTreeMap, collections::HashMap, fmt};
use zeroize::Zeroizing;

/// Entry record tags.
pub const TAG_META: u8 = 0;
pub const TAG_PASSWORD: u8 = 1;

/// Field ids of a meta entry.
pub mod meta_field {
	pub const NAME: u8 = 1;
	pub const VALUE: u8 = 2;
}

/// Field ids of a password entry.
pub mod field {
	pub const NAME: u8 = 1;
	pub const USERNAME: u8 = 2;
	pub const PASSWORD: u8 = 3;
	pub const PIN: u8 = 4;
	pub const NOTE: u8 = 5;
	pub const URL: u8 = 6;
	pub const TAGS: u8 = 7;
	pub const CREATED_TS: u8 = 8;
	pub const MODIFIED_TS: u8 = 9;
}

/// The marker of the short-lived AAD form; nothing newer exists.
pub const AAD_FORMAT: u32 = 2;
const AAD_PREFIX: &[u8] = b"keptino-envelope-v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
	/// Not a vault file, or damaged beyond what the shards can repair.
	Damaged,
	/// Intact, but written by a newer Keptino.
	NewerFormat(u32),
	/// Over a budget of ADR 0006: the file, the database or a record.
	TooLarge,
}

impl fmt::Display for FormatError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Damaged => f.write_str("the file is damaged beyond repair."),
			Self::NewerFormat(format) => write!(
				f,
				"the file was written by a newer Keptino (format {format}). Update Keptino to open it."
			),
			Self::TooLarge => write!(
				f,
				"the vault exceeds the {} MiB budget.",
				MAX_FILE_BYTES >> 20
			),
		}
	}
}

impl std::error::Error for FormatError {}

/// The budgets reader and writer share (ADR 0006). A file, a database or a
/// record list beyond them is refused before it is allocated, and a save
/// that would exceed them is refused, so a vault one head writes always
/// opens on the other.
pub const MAX_FILE_BYTES: usize = 64 << 20;
/// Sized so that a database within budget always yields a file within
/// `MAX_FILE_BYTES`: LZ4 adds under one percent to incompressible data,
/// base64 one third, and the 8+4 parity one half (30 x 1.01 x 4/3 x 1.5 is
/// under 61 MiB).
pub const MAX_DATABASE_BYTES: usize = 30 << 20;
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_FIELD_BYTES: usize = 16 << 20;

/// Splits one record off the front of `data`.
pub fn next_record<'a>(data: &mut &'a [u8]) -> Result<(u8, &'a [u8]), FormatError> {
	let (header, rest) = data.split_at_checked(5).ok_or(FormatError::Damaged)?;
	let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
	if len > MAX_FIELD_BYTES {
		return Err(FormatError::TooLarge);
	}
	let (value, rest) = rest.split_at_checked(len).ok_or(FormatError::Damaged)?;
	*data = rest;
	Ok((header[0], value))
}

fn push_record(buffer: &mut Vec<u8>, tag: u8, value: &[u8]) {
	buffer.push(tag);
	buffer.extend_from_slice(&(value.len() as u32).to_le_bytes());
	buffer.extend_from_slice(value);
}

/// The fields of one entry, keyed by id. Unknown ids are preserved, so a
/// newer version's fields survive a round trip through an older one.
#[derive(Clone, Default)]
pub struct FieldAtlas {
	fields: BTreeMap<u8, Zeroizing<Vec<u8>>>,
}

impl FieldAtlas {
	pub fn deserialize(mut data: &[u8]) -> Result<Self, FormatError> {
		let mut fields = BTreeMap::new();
		while !data.is_empty() {
			let (id, value) = next_record(&mut data)?;
			fields.insert(id, Zeroizing::new(value.to_vec()));
		}
		Ok(Self { fields })
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		let size = self.fields.values().map(|v| 5 + v.len()).sum();
		let mut buffer = Zeroizing::new(Vec::with_capacity(size));
		for (&id, value) in &self.fields {
			push_record(&mut buffer, id, value);
		}
		buffer
	}

	pub fn get(&self, id: u8) -> Option<&[u8]> {
		self.fields.get(&id).map(|v| v.as_slice())
	}

	pub fn get_str(&self, id: u8) -> Option<&str> {
		self.get(id)
			.and_then(|bytes| std::str::from_utf8(bytes).ok())
	}

	pub fn set(&mut self, id: u8, value: &[u8]) {
		self.fields.insert(id, Zeroizing::new(value.to_vec()));
	}

	pub fn take(&mut self, id: u8) -> Option<Zeroizing<Vec<u8>>> {
		self.fields.remove(&id)
	}
}

/// The entry records of a database as `(tag, raw field bytes)`, in file
/// order. The raw bytes let a head keep records sealed without reparsing.
pub fn deserialize_records(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>, FormatError> {
	let mut records = Vec::new();
	while !data.is_empty() {
		if records.len() == MAX_RECORDS {
			return Err(FormatError::TooLarge);
		}
		records.push(next_record(&mut data)?);
	}
	Ok(records)
}

/// The entry records of a database, parsed.
pub fn deserialize_entries(data: &[u8]) -> Result<Vec<(u8, FieldAtlas)>, FormatError> {
	deserialize_records(data)?
		.into_iter()
		.map(|(tag, value)| Ok((tag, FieldAtlas::deserialize(value)?)))
		.collect()
}

pub fn serialize_entries<'a>(
	entries: impl Iterator<Item = (u8, &'a [u8])> + Clone,
) -> Zeroizing<Vec<u8>> {
	let size = entries.clone().map(|(_, value)| 5 + value.len()).sum();
	let mut buffer = Zeroizing::new(Vec::with_capacity(size));
	for (tag, value) in entries {
		push_record(&mut buffer, tag, value);
	}
	buffer
}

/// One meta entry's field bytes.
pub fn meta_entry(name: &str, value: &str) -> Zeroizing<Vec<u8>> {
	let mut atlas = FieldAtlas::default();
	atlas.set(meta_field::NAME, name.as_bytes());
	atlas.set(meta_field::VALUE, value.as_bytes());
	atlas.serialize()
}

/// The `(name, value)` of every meta entry in a serialized database, in
/// file order. Any record that is not a well-formed meta entry is skipped
/// when `strict` is off (a database also holds password entries) and an
/// error when it is on (an envelope holds nothing else).
fn meta_pairs_in(data: &[u8], strict: bool) -> Result<Vec<(String, String)>, FormatError> {
	let mut pairs = Vec::new();
	for (tag, value) in deserialize_records(data)? {
		if tag != TAG_META {
			if strict {
				return Err(FormatError::Damaged);
			}
			continue;
		}
		let record = FieldAtlas::deserialize(value)?;
		let (Some(name), Some(value)) = (
			record.get_str(meta_field::NAME),
			record.get_str(meta_field::VALUE),
		) else {
			return Err(FormatError::Damaged);
		};
		pairs.push((name.to_owned(), value.to_owned()));
	}
	Ok(pairs)
}

/// The meta entries of a serialized database.
pub fn meta_pairs(database: &[u8]) -> Result<Vec<(String, String)>, FormatError> {
	meta_pairs_in(database, false)
}

/// Whether two meta sets hold the same names with the same values.
pub fn mirrors(outer: &[(String, String)], inner: &[(String, String)]) -> bool {
	let mut outer: Vec<&(String, String)> = outer.iter().collect();
	let mut inner: Vec<&(String, String)> = inner.iter().collect();
	outer.sort();
	inner.sort();
	outer == inner
}

/// Associated data of the marked AAD form: every plaintext meta entry except
/// the ciphertext itself, length-prefixed and sorted by name.
pub fn envelope_aad(meta: &[(String, String)]) -> Vec<u8> {
	let mut pairs: Vec<&(String, String)> = meta.iter().filter(|(name, _)| name != "db").collect();
	pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
	let mut aad = AAD_PREFIX.to_vec();
	for (name, value) in pairs {
		for part in [name, value] {
			aad.extend_from_slice(&(part.len() as u32).to_le_bytes());
			aad.extend_from_slice(part.as_bytes());
		}
	}
	aad
}

/// Argon2id cost: memory in KiB, passes, lanes. Vaults record theirs as the
/// meta entries `kdf_m`, `kdf_t`, `kdf_p`; older files carry none and open
/// with the cost the reader is built with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
	pub m_cost: u32,
	pub t_cost: u32,
	pub p_cost: u32,
}

impl KdfParams {
	/// The Linux release cost: 4 GiB, one pass, one lane.
	pub const RELEASE: Self = Self {
		m_cost: 1 << 22,
		t_cost: 1,
		p_cost: 1,
	};
	/// The debug cost, also what the test fixtures use: 4 MiB.
	pub const DEBUG: Self = Self {
		m_cost: 1 << 12,
		t_cost: 1,
		p_cost: 1,
	};
	/// The cost matching this build's profile.
	pub const BUILD_DEFAULT: Self = if cfg!(debug_assertions) {
		Self::DEBUG
	} else {
		Self::RELEASE
	};
	/// 4 MiB to 16 GiB; outside this the file is not one Keptino wrote.
	pub const M_COST: std::ops::RangeInclusive<u32> = (1 << 12)..=(1 << 24);
	pub const T_COST: std::ops::RangeInclusive<u32> = 1..=64;
	pub const P_COST: std::ops::RangeInclusive<u32> = 1..=16;

	pub const fn memory_only(m_cost: u32) -> Self {
		Self {
			m_cost,
			t_cost: 1,
			p_cost: 1,
		}
	}

	/// The recorded cost, `default` when all three entries are absent,
	/// `None` when they are partial or out of range.
	pub fn from_meta(metadata: &HashMap<String, String>, default: Self) -> Option<Self> {
		let fields = ["kdf_m", "kdf_t", "kdf_p"].map(|name| metadata.get(name));
		if fields.iter().all(Option::is_none) {
			return Some(default);
		}
		let [m_cost, t_cost, p_cost] = fields.map(|field| field?.parse::<u32>().ok());
		let params = Self {
			m_cost: m_cost?,
			t_cost: t_cost?,
			p_cost: p_cost?,
		};
		(Self::M_COST.contains(&params.m_cost)
			&& Self::T_COST.contains(&params.t_cost)
			&& Self::P_COST.contains(&params.p_cost))
		.then_some(params)
	}

	/// The meta entries that record this cost.
	pub fn meta_pairs(self) -> [(String, String); 3] {
		[
			("kdf_m".into(), self.m_cost.to_string()),
			("kdf_t".into(), self.t_cost.to_string()),
			("kdf_p".into(), self.p_cost.to_string()),
		]
	}
}

/// The plaintext layer of a vault file. Every field is unverified until the
/// caller has compared `mirror` against the meta pairs inside the decrypted
/// database; `aad` is empty except for the marked AAD form.
#[derive(Clone, Debug)]
pub struct Envelope {
	pub modified: u64,
	pub revision: Option<u64>,
	pub kdf: KdfParams,
	pub nonce: [u8; NONCE_SIZE],
	pub salt: [u8; SALT_SIZE],
	pub ciphertext: Vec<u8>,
	/// Every plaintext meta entry except the ciphertext itself, as stored.
	pub mirror: Vec<(String, String)>,
	pub aad: Vec<u8>,
}

impl Envelope {
	/// Repairs the shards and reads the envelope. `default_kdf` applies to a
	/// file that records no cost.
	pub fn parse(file: &[u8], default_kdf: KdfParams) -> Result<Self, FormatError> {
		if file.len() > MAX_FILE_BYTES {
			return Err(FormatError::TooLarge);
		}
		let recovered = decode_shards(file)?;
		let pairs = meta_pairs_in(&recovered, true)?;
		let mut metadata = HashMap::new();
		for (name, value) in &pairs {
			// A duplicate name could let one copy pass the mirror check
			// while a reader honors the other.
			if metadata.insert(name.clone(), value.clone()).is_some() {
				return Err(FormatError::Damaged);
			}
		}
		let damaged = || FormatError::Damaged;
		let format: u32 = match metadata.get("format") {
			Some(format) => format.parse().map_err(|_| damaged())?,
			None => 1,
		};
		if format > AAD_FORMAT {
			return Err(FormatError::NewerFormat(format));
		}
		if format == 0 {
			return Err(damaged());
		}
		// The revision and the cost are read from the plaintext and vouched
		// for afterwards: a forged cost derives a key that opens nothing, and
		// a forged revision fails the mirror check.
		let revision = match metadata.get("revision") {
			Some(revision) => Some(revision.parse().map_err(|_| damaged())?),
			None if format >= AAD_FORMAT => return Err(damaged()),
			None => None,
		};
		// Marked files were written from revision 1; a zero there is a forgery.
		if format >= AAD_FORMAT && revision == Some(0) {
			return Err(damaged());
		}
		let kdf = KdfParams::from_meta(&metadata, default_kdf).ok_or_else(damaged)?;
		let aad = if format >= AAD_FORMAT {
			envelope_aad(&pairs)
		} else {
			Vec::new()
		};
		let mirror = pairs
			.iter()
			.filter(|(name, _)| name != "db")
			.cloned()
			.collect();
		let counter: u128 = metadata
			.get("nonce")
			.ok_or_else(damaged)?
			.parse()
			.map_err(|_| damaged())?;
		let mut nonce = [0; NONCE_SIZE];
		nonce[..16].copy_from_slice(&counter.to_le_bytes());
		let salt = Base64::decode_vec(metadata.get("salt").ok_or_else(damaged)?)
			.map_err(|_| damaged())?
			.try_into()
			.map_err(|_| damaged())?;
		let ciphertext =
			Base64::decode_vec(metadata.get("db").ok_or_else(damaged)?).map_err(|_| damaged())?;
		Ok(Self {
			modified: metadata
				.get("modified_ts")
				.ok_or_else(damaged)?
				.parse()
				.map_err(|_| damaged())?,
			revision,
			kdf,
			nonce,
			salt,
			ciphertext,
			mirror,
			aad,
		})
	}

	/// Decrypts and decompresses the database, then insists that the
	/// plaintext metadata is exactly the authenticated copy inside. `None`
	/// for a wrong key, a tampered envelope or a damaged payload alike.
	pub fn open(&self, key: &[u8; crate::crypto::KEY_SIZE]) -> Option<Zeroizing<Vec<u8>>> {
		let compressed =
			crate::crypto::decrypt(self.ciphertext.clone(), key, &self.nonce, &self.aad)?;
		let database = crate::crypto::decompress(&compressed, MAX_DATABASE_BYTES).ok()?;
		let inner = meta_pairs(&database).ok()?;
		mirrors(&self.mirror, &inner).then_some(database)
	}
}

/// Builds a vault file from the database's meta entries (in storage order)
/// and the ciphertext: the TLV envelope, then the shards.
pub fn encode_envelope(meta: &[(String, String)], ciphertext: &[u8]) -> Vec<u8> {
	let mut records = Vec::new();
	for (name, value) in meta {
		push_record(&mut records, TAG_META, &meta_entry(name, value));
	}
	push_record(
		&mut records,
		TAG_META,
		&meta_entry("db", &Base64::encode_string(ciphertext)),
	);
	encode_shards(&records)
}

const DATA_SHARDS: usize = 8;
const PARITY_SHARDS: usize = 4;
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;
const MIN_SHARD_SIZE: usize = 4096;
const SHARD_HEADER: usize = 8 + 32;

/// Reed-Solomon 8:4 with a `len u64 LE | blake3 | shard` header per shard.
pub fn encode_shards(data: &[u8]) -> Vec<u8> {
	let shard_size = data.len().div_ceil(DATA_SHARDS).max(MIN_SHARD_SIZE);
	let mut padded = data.to_vec();
	padded.resize(shard_size * DATA_SHARDS, 0);
	let mut shards: Vec<Vec<u8>> = padded
		.chunks_exact(shard_size)
		.map(<[u8]>::to_vec)
		.collect();
	shards.resize(TOTAL_SHARDS, vec![0; shard_size]);
	ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
		.and_then(|rs| rs.encode(&mut shards))
		.expect("fixed erasure geometry");
	let mut output = Vec::with_capacity(TOTAL_SHARDS * (SHARD_HEADER + shard_size));
	for shard in shards {
		output.extend_from_slice(&(data.len() as u64).to_le_bytes());
		output.extend_from_slice(blake3::hash(&shard).as_bytes());
		output.extend_from_slice(&shard);
	}
	output
}

/// Verifies every shard, rebuilds up to four damaged ones and returns the
/// original bytes. The length lives outside the checksum, so the copy most
/// shards agree on is trusted.
pub fn decode_shards(encoded: &[u8]) -> Result<Vec<u8>, FormatError> {
	let chunk_size = encoded.len() / TOTAL_SHARDS;
	if chunk_size < SHARD_HEADER + MIN_SHARD_SIZE || !encoded.len().is_multiple_of(TOTAL_SHARDS) {
		return Err(FormatError::Damaged);
	}
	let shard_size = chunk_size - SHARD_HEADER;
	let mut lengths = Vec::with_capacity(TOTAL_SHARDS);
	let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(TOTAL_SHARDS);
	for chunk in encoded.chunks_exact(chunk_size) {
		let (header, shard) = chunk.split_at(SHARD_HEADER);
		if blake3::hash(shard).as_bytes() == &header[8..] {
			lengths.push(u64::from_le_bytes(header[..8].try_into().unwrap()));
			shards.push(Some(shard.to_vec()));
		} else {
			shards.push(None);
		}
	}
	let original_len = lengths
		.iter()
		.max_by_key(|len| lengths.iter().filter(|other| other == len).count())
		.copied()
		.ok_or(FormatError::Damaged)?;
	if original_len > (shard_size * DATA_SHARDS) as u64 {
		return Err(FormatError::Damaged);
	}
	ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
		.and_then(|rs| rs.reconstruct_data(&mut shards))
		.map_err(|_| FormatError::Damaged)?;
	let mut recovered: Vec<u8> = shards
		.into_iter()
		.take(DATA_SHARDS)
		.flatten()
		.flatten()
		.collect();
	recovered.truncate(original_len as usize);
	Ok(recovered)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::{self, KEY_SIZE};

	const KEY: [u8; KEY_SIZE] = [42; KEY_SIZE];

	/// A small database: meta entries and one password entry.
	fn database(meta: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
		let mut entry = FieldAtlas::default();
		entry.set(field::NAME, b"bank");
		entry.set(field::PASSWORD, "hunter2 ünïcödé 🔑".as_bytes());
		let entry = entry.serialize();
		let metas: Vec<Zeroizing<Vec<u8>>> = meta.iter().map(|(n, v)| meta_entry(n, v)).collect();
		let records: Vec<(u8, &[u8])> = metas
			.iter()
			.map(|m| (TAG_META, m.as_slice()))
			.chain(std::iter::once((TAG_PASSWORD, entry.as_slice())))
			.collect();
		serialize_entries(records.iter().copied())
	}

	fn base_meta() -> Vec<(&'static str, &'static str)> {
		vec![
			("db_name", "example"),
			("nonce", "7"),
			("salt", "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="),
			("created_ts", "1600000000"),
			("modified_ts", "1700000000"),
		]
	}

	fn encode(meta: &[(&str, &str)], aad_form: bool) -> Vec<u8> {
		let db = database(meta);
		let pairs: Vec<(String, String)> = meta
			.iter()
			.map(|(n, v)| (n.to_string(), v.to_string()))
			.collect();
		let aad = if aad_form {
			envelope_aad(&pairs)
		} else {
			Vec::new()
		};
		let mut nonce = [0u8; NONCE_SIZE];
		nonce[..16].copy_from_slice(&7u128.to_le_bytes());
		let ciphertext = crypto::encrypt(&crypto::compress(&db), &KEY, &nonce, &aad);
		encode_envelope(&pairs, &ciphertext)
	}

	/// Re-encodes a file with one plaintext meta value altered.
	fn tamper(file: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
		let mut recovered = decode_shards(file).unwrap();
		let at = recovered
			.windows(from.len())
			.position(|window| window == from)
			.expect("plaintext field present");
		recovered[at..at + from.len()].copy_from_slice(to);
		encode_shards(&recovered)
	}

	#[test]
	fn records_roundtrip_sorted_and_keep_unknown_ids() {
		let mut raw = Vec::new();
		push_record(&mut raw, 200, b"future");
		push_record(&mut raw, 1, b"name");
		push_record(&mut raw, 1, b"last wins");
		let atlas = FieldAtlas::deserialize(&raw).unwrap();
		assert_eq!(atlas.get_str(1), Some("last wins"));
		let mut expected = Vec::new();
		push_record(&mut expected, 1, b"last wins");
		push_record(&mut expected, 200, b"future");
		assert_eq!(&*atlas.serialize(), &expected);
		let mut single = Vec::new();
		push_record(&mut single, 1, b"name");
		for cut in 1..single.len() {
			assert!(
				FieldAtlas::deserialize(&single[..cut]).is_err(),
				"cut {cut}"
			);
		}
		assert!(deserialize_entries(&[1, 255, 255, 255, 255]).is_err());
		let db = database(&base_meta());
		assert_eq!(deserialize_entries(&db).unwrap().len(), 6);
		assert_eq!(meta_pairs(&db).unwrap().len(), 5);
	}

	#[test]
	fn legacy_files_open_through_the_mirror_check() {
		let file = encode(&base_meta(), false);
		let envelope = Envelope::parse(&file, KdfParams::DEBUG).unwrap();
		assert_eq!(envelope.revision, None);
		assert_eq!(envelope.kdf, KdfParams::DEBUG);
		assert_eq!(envelope.modified, 1700000000);
		assert_eq!(envelope.salt, [42; SALT_SIZE]);
		assert!(envelope.aad.is_empty());
		let inner = envelope.open(&KEY).unwrap();
		assert_eq!(meta_pairs(&inner).unwrap().len(), 5);
		assert!(envelope.open(&[1; KEY_SIZE]).is_none(), "wrong key");
		let replayed = Envelope::parse(
			&tamper(&file, b"1700000000", b"1800000000"),
			KdfParams::DEBUG,
		)
		.unwrap();
		assert_eq!(replayed.modified, 1800000000);
		assert!(
			replayed.open(&KEY).is_none(),
			"a bumped timestamp is caught"
		);
	}

	#[test]
	fn unmarked_files_carry_revision_and_cost_and_reject_a_changed_copy() {
		let mut meta = base_meta();
		meta.push(("revision", "1"));
		meta.extend([("kdf_m", "4096"), ("kdf_t", "1"), ("kdf_p", "1")]);
		let file = encode(&meta, false);
		let envelope = Envelope::parse(&file, KdfParams::RELEASE).unwrap();
		assert_eq!(envelope.revision, Some(1));
		assert_eq!(
			envelope.kdf,
			KdfParams::DEBUG,
			"the recorded cost wins over the default"
		);
		assert!(envelope.open(&KEY).is_some());
		for (from, to) in [
			(&b"example"[..], &b"exampel"[..]),
			(
				b"revision\x02\x01\x00\x00\x001",
				b"revision\x02\x01\x00\x00\x002",
			),
			(b"kdf_t\x02\x01\x00\x00\x001", b"kdf_t\x02\x01\x00\x00\x002"),
		] {
			let altered = Envelope::parse(&tamper(&file, from, to), KdfParams::RELEASE).unwrap();
			assert!(altered.open(&KEY).is_none(), "{from:?}");
		}
		// A dropped or added plaintext field fails the same way; a duplicate
		// name is refused before any key is derived.
		let mut recovered = decode_shards(&file).unwrap();
		push_record(&mut recovered, TAG_META, &meta_entry("extra", "1"));
		assert!(
			Envelope::parse(&encode_shards(&recovered), KdfParams::DEBUG)
				.unwrap()
				.open(&KEY)
				.is_none()
		);
		let mut recovered = decode_shards(&file).unwrap();
		push_record(&mut recovered, TAG_META, &meta_entry("salt", "AAAA"));
		assert_eq!(
			Envelope::parse(&encode_shards(&recovered), KdfParams::DEBUG).err(),
			Some(FormatError::Damaged)
		);
		// Out-of-range or partial costs are not a vault at all.
		assert!(
			Envelope::parse(
				&tamper(
					&file,
					b"kdf_m\x02\x04\x00\x00\x004096",
					b"kdf_m\x02\x04\x00\x00\x000001"
				),
				KdfParams::DEBUG
			)
			.is_err()
		);
		assert!(Envelope::parse(&tamper(&file, b"kdf_p", b"kdf_q"), KdfParams::DEBUG).is_err());
	}

	#[test]
	fn marked_aad_files_still_open() {
		let mut meta = base_meta();
		meta.extend([("format", "2"), ("revision", "3")]);
		let file = encode(&meta, true);
		let envelope = Envelope::parse(&file, KdfParams::DEBUG).unwrap();
		assert_eq!(envelope.revision, Some(3));
		assert!(envelope.aad.starts_with(AAD_PREFIX));
		assert!(envelope.open(&KEY).is_some());
		assert!(
			Envelope::parse(&tamper(&file, b"example", b"exampel"), KdfParams::DEBUG)
				.unwrap()
				.open(&KEY)
				.is_none()
		);
		assert_eq!(
			Envelope::parse(&tamper(&file, b"revision", b"revisioN"), KdfParams::DEBUG).err(),
			Some(FormatError::Damaged),
			"a marked file must carry a revision"
		);
		assert_eq!(
			Envelope::parse(
				&tamper(
					&file,
					b"revision\x02\x01\x00\x00\x003",
					b"revision\x02\x01\x00\x00\x000"
				),
				KdfParams::DEBUG
			)
			.err(),
			Some(FormatError::Damaged),
			"a marked file never has revision 0"
		);
		assert_eq!(
			Envelope::parse(
				&tamper(
					&file,
					b"format\x02\x01\x00\x00\x002",
					b"format\x02\x01\x00\x00\x000"
				),
				KdfParams::DEBUG
			)
			.err(),
			Some(FormatError::Damaged),
			"format 0 is not a vault"
		);
		assert_eq!(
			Envelope::parse(
				&tamper(
					&file,
					b"format\x02\x01\x00\x00\x002",
					b"format\x02\x01\x00\x00\x009"
				),
				KdfParams::DEBUG
			)
			.err(),
			Some(FormatError::NewerFormat(9))
		);
	}

	#[test]
	fn associated_data_is_canonical_and_excludes_the_ciphertext() {
		let a = vec![
			("salt".to_string(), "s".to_string()),
			("db".to_string(), "ciphertext".to_string()),
			("format".to_string(), "2".to_string()),
		];
		let b = vec![
			("format".to_string(), "2".to_string()),
			("salt".to_string(), "s".to_string()),
		];
		assert_eq!(envelope_aad(&a), envelope_aad(&b));
		let mut expected = AAD_PREFIX.to_vec();
		for part in ["format", "2", "salt", "s"] {
			expected.extend_from_slice(&(part.len() as u32).to_le_bytes());
			expected.extend_from_slice(part.as_bytes());
		}
		assert_eq!(envelope_aad(&a), expected);
	}

	#[test]
	fn kdf_parameters_default_when_absent_and_are_bounded() {
		let meta = |fields: &[(&str, &str)]| {
			fields
				.iter()
				.map(|(k, v)| (k.to_string(), v.to_string()))
				.collect::<HashMap<_, _>>()
		};
		assert_eq!(
			KdfParams::from_meta(&meta(&[]), KdfParams::RELEASE),
			Some(KdfParams::RELEASE)
		);
		assert_eq!(
			KdfParams::from_meta(
				&meta(&[("kdf_m", "4194304"), ("kdf_t", "3"), ("kdf_p", "2")]),
				KdfParams::DEBUG
			),
			Some(KdfParams {
				m_cost: 1 << 22,
				t_cost: 3,
				p_cost: 2
			})
		);
		assert_eq!(
			KdfParams::from_meta(&meta(&[("kdf_m", "4194304")]), KdfParams::DEBUG),
			None,
			"partial"
		);
		assert_eq!(
			KdfParams::from_meta(
				&meta(&[("kdf_m", "1024"), ("kdf_t", "1"), ("kdf_p", "1")]),
				KdfParams::DEBUG
			),
			None,
			"below the floor"
		);
		assert_eq!(
			KdfParams::from_meta(
				&meta(&[("kdf_m", "4096"), ("kdf_t", "0"), ("kdf_p", "1")]),
				KdfParams::DEBUG
			),
			None,
			"zero passes"
		);
		assert_eq!(
			KdfParams::from_meta(
				&meta(&[("kdf_m", "4096"), ("kdf_t", "1"), ("kdf_p", "x")]),
				KdfParams::DEBUG
			),
			None,
			"not a number"
		);
		assert_eq!(KdfParams::memory_only(4096), KdfParams::DEBUG);
		let recorded = KdfParams::DEBUG.meta_pairs();
		assert_eq!(recorded[0], ("kdf_m".to_string(), "4096".to_string()));
	}

	#[test]
	fn shards_repair_four_losses_and_refuse_garbage() {
		for len in [0usize, 1, 4096 * 8, 4096 * 8 + 1, 100_000] {
			let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
			let encoded = encode_shards(&data);
			assert_eq!(encoded.len() % TOTAL_SHARDS, 0);
			assert_eq!(decode_shards(&encoded).unwrap(), data);
			let chunk = encoded.len() / TOTAL_SHARDS;
			let mut damaged = encoded.clone();
			for shard in [0, 3, 7, 11] {
				damaged[shard * chunk + SHARD_HEADER + 5] ^= 0x80;
			}
			assert_eq!(decode_shards(&damaged).unwrap(), data);
			damaged[chunk + 2] ^= 1;
			assert_eq!(
				decode_shards(&damaged).unwrap(),
				data,
				"a damaged length is outvoted"
			);
			damaged[5 * chunk + SHARD_HEADER] ^= 1;
			assert!(decode_shards(&damaged).is_err());
		}
		assert!(decode_shards(&[]).is_err());
		assert!(decode_shards(&[0; 12 * 40]).is_err());
		assert!(decode_shards(&[7; 12 * 4136]).is_err());
	}

	const FIXTURES: [(&str, &[u8]); 6] = [
		(
			"linux-debug",
			include_bytes!("../../../android/droid/tests/fixtures/linux-debug.keptino"),
		),
		(
			"linux-release",
			include_bytes!("../../../android/droid/tests/fixtures/linux-release.keptino"),
		),
		(
			"linux-debug-v2",
			include_bytes!("../../../android/droid/tests/fixtures/linux-debug-v2.keptino"),
		),
		(
			"linux-release-v2",
			include_bytes!("../../../android/droid/tests/fixtures/linux-release-v2.keptino"),
		),
		(
			"linux-debug-unmarked",
			include_bytes!("../../../android/droid/tests/fixtures/linux-debug-unmarked.keptino"),
		),
		(
			"linux-release-unmarked",
			include_bytes!("../../../android/droid/tests/fixtures/linux-release-unmarked.keptino"),
		),
	];
	const FIXTURE_PASSWORD: &[u8] = b"correct horse battery staple";
	const FIXTURE_PEPPER_HEX: &str =
		"3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1";

	#[test]
	fn every_committed_fixture_parses_and_restores_byte_for_byte() {
		for (name, file) in FIXTURES {
			let envelope = Envelope::parse(file, KdfParams::DEBUG).unwrap();
			let marked = name.ends_with("-v2");
			let legacy = !marked && !name.ends_with("-unmarked");
			assert_eq!(envelope.revision.is_some(), !legacy, "{name}");
			assert_eq!(!envelope.aad.is_empty(), marked, "{name}");
			let expected_cost = if legacy || name.starts_with("linux-debug") {
				4096
			} else {
				1 << 22
			};
			assert_eq!(
				envelope.kdf.m_cost, expected_cost,
				"{name}: a legacy fixture takes the default, the others record theirs"
			);
			// Four damaged data shards, repaired to the identical file.
			let mut damaged = file.to_vec();
			let chunk = damaged.len() / TOTAL_SHARDS;
			for shard in [0, 2, 4, 6] {
				damaged[shard * chunk + SHARD_HEADER] ^= 1;
			}
			assert_eq!(
				encode_shards(&decode_shards(&damaged).unwrap()),
				file,
				"{name}"
			);
		}
	}

	/// Opens the debug fixtures with the fixture password and pepper: the
	/// whole read path, from shards to entries, against files the previous
	/// implementations wrote. The release fixtures need 4 GiB; see the
	/// ignored test.
	fn open_fixture(name: &str, file: &[u8]) {
		// A legacy fixture records no cost, so the default must be the cost it
		// was written with: 4 MiB for the debug set, 4 GiB for the release set.
		let default = if name.starts_with("linux-release") {
			KdfParams::RELEASE
		} else {
			KdfParams::DEBUG
		};
		let envelope = Envelope::parse(file, default).unwrap();
		let mut pepper = [0u8; crypto::PEPPER_SIZE];
		hex::decode_to_slice(FIXTURE_PEPPER_HEX, &mut pepper).unwrap();
		let mut key = Zeroizing::new([0u8; KEY_SIZE]);
		crypto::derive_master_key(
			FIXTURE_PASSWORD,
			&pepper,
			&envelope.salt,
			envelope.kdf,
			&mut key,
		)
		.unwrap();
		let database = envelope
			.open(&key)
			.unwrap_or_else(|| panic!("{name} opens"));
		let names: Vec<String> = deserialize_entries(&database)
			.unwrap()
			.into_iter()
			.filter(|(tag, _)| *tag == TAG_PASSWORD)
			.map(|(_, entry)| entry.get_str(field::NAME).unwrap().to_owned())
			.collect();
		assert_eq!(names, ["bank", "mail", "wifi"], "{name}");
		let mut wrong = *key;
		wrong[0] ^= 1;
		assert!(envelope.open(&wrong).is_none(), "{name}: wrong key");
	}

	#[test]
	fn debug_fixtures_decrypt_with_the_fixture_pepper() {
		for (name, file) in FIXTURES {
			if name.starts_with("linux-debug") {
				open_fixture(name, file);
			}
		}
	}

	/// Needs 4 GiB of memory per fixture: `cargo test -p keptino-core --release -- --ignored`.
	#[test]
	#[ignore]
	fn release_fixtures_decrypt_with_the_fixture_pepper() {
		for (name, file) in FIXTURES {
			if name.starts_with("linux-release") {
				open_fixture(name, file);
			}
		}
	}

	#[test]
	fn inputs_over_budget_are_refused_before_allocation() {
		let huge = vec![0u8; MAX_FILE_BYTES + TOTAL_SHARDS];
		assert_eq!(
			Envelope::parse(&huge, KdfParams::DEBUG).err(),
			Some(FormatError::TooLarge)
		);
		let mut records = Vec::with_capacity((MAX_RECORDS + 1) * 5);
		for _ in 0..=MAX_RECORDS {
			push_record(&mut records, TAG_META, &[]);
		}
		assert_eq!(
			deserialize_records(&records).err(),
			Some(FormatError::TooLarge)
		);
		assert_eq!(
			deserialize_records(&records[..MAX_RECORDS * 5])
				.unwrap()
				.len(),
			MAX_RECORDS
		);
		let mut field = vec![field::NOTE];
		field.extend_from_slice(&((MAX_FIELD_BYTES + 1) as u32).to_le_bytes());
		field.resize(5 + MAX_FIELD_BYTES + 1, b'x');
		assert_eq!(
			FieldAtlas::deserialize(&field).err(),
			Some(FormatError::TooLarge)
		);
		assert_eq!(
			crate::crypto::decompress(&crate::crypto::compress(&[7u8; 4096]), 4095).err(),
			Some(crate::crypto::CorruptPayload),
			"decompression stops at the budget"
		);
		assert_eq!(
			crate::crypto::decompress(&crate::crypto::compress(&[7u8; 4096]), 4096)
				.unwrap()
				.len(),
			4096
		);
	}
}
