//! An unlocked database and the entry being viewed or edited, with the
//! semantics of the Linux application's password screen.

use crate::{
	atlas::{FieldAtlas, deserialize_entries, serialize_entries},
	crypto::{self, KdfCost, Key, NONCE_SIZE, PEPPER_SIZE, SALT_SIZE},
	erasure,
	error::{Error, Result},
};
use base64ct::{Base64, Encoding};
use std::{collections::BTreeMap, ops::Bound, time::SystemTime};
use zeroize::{Zeroize, Zeroizing};

/// Saves upgrade format-1 vaults now that Linux and Android both read
/// format 2; a format-2 vault is never written back as format 1.
const WRITE_FORMAT_2: bool = true;
const TAG_META: u8 = 0;
const TAG_PASSWORD: u8 = 1;
const META_NAME: u8 = 1;
const META_VALUE: u8 = 2;

/// Field ids of a password entry, as stored on disk.
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

/// Where an opened database came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Source {
	New = 0,
	Local = 1,
	Remote = 2,
}

/// The outcome of committing the working entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Commit {
	EmptyName = 0,
	Updated = 1,
	Created = 2,
}

fn now() -> u64 {
	SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or_default()
}

fn blank_entry() -> FieldAtlas {
	let ts = now().to_string();
	let mut entry = FieldAtlas::default();
	entry.set(field::CREATED_TS, ts.as_bytes());
	entry.set(field::MODIFIED_TS, ts.as_bytes());
	entry
}

fn entry_name(entry: &FieldAtlas) -> &str {
	entry.get_str(field::NAME).unwrap_or_default()
}

/// Entries in file order with name and tag indexes. Ids are positions, as
/// in the Linux application: an entry keeps its place when rewritten.
#[derive(Default)]
struct Store {
	next_id: u32,
	entries: BTreeMap<u32, (u8, Zeroizing<Vec<u8>>)>,
	metas: BTreeMap<String, u32>,
	passwords: BTreeMap<String, u32>,
	tags: BTreeMap<String, Vec<u32>>,
}

impl Store {
	fn deserialize(data: &[u8]) -> Result<Self> {
		let mut store = Self::default();
		for (tag, entry) in deserialize_entries(data)? {
			match tag {
				TAG_META => {
					let name = entry
						.get_str(META_NAME)
						.ok_or(Error::Corrupt("unnamed meta entry"))?
						.to_owned();
					store.set_raw(TAG_META, &name, &entry);
				}
				TAG_PASSWORD => store.set_password(&entry),
				// Refuse rather than drop what a newer version wrote.
				_ => return Err(Error::Corrupt("unknown entry type")),
			}
		}
		Ok(store)
	}

	fn serialize(&self) -> Zeroizing<Vec<u8>> {
		serialize_entries(self.entries.values().map(|(tag, value)| (*tag, value.as_slice())))
	}

	fn set_raw(&mut self, tag: u8, name: &str, entry: &FieldAtlas) -> (u32, bool) {
		let index = if tag == TAG_META {
			&mut self.metas
		} else {
			&mut self.passwords
		};
		let (id, is_new) = match index.get(name) {
			Some(id) => (*id, false),
			None => {
				let id = self.next_id;
				self.next_id += 1;
				index.insert(name.to_owned(), id);
				(id, true)
			}
		};
		self.entries.insert(id, (tag, entry.serialize()));
		(id, is_new)
	}

	fn set_meta(&mut self, name: &str, value: &str) {
		let mut entry = FieldAtlas::default();
		entry.set(META_NAME, name.as_bytes());
		entry.set(META_VALUE, value.as_bytes());
		self.set_raw(TAG_META, name, &entry);
	}

	fn meta(&self, name: &str) -> Option<String> {
		let (_, data) = self.entries.get(self.metas.get(name)?)?;
		let entry = FieldAtlas::deserialize(data).ok()?;
		entry.get_str(META_VALUE).map(str::to_owned)
	}

	fn metadata_aad(&self) -> Result<Vec<u8>> {
		let mut aad = b"keptino-envelope-v2".to_vec();
		// metas is a BTreeMap with UTF-8 byte ordering.
		for name in self.metas.keys().filter(|name| name.as_str() != "db") {
			let value = self.required_meta(name, "metadata value")?;
			for part in [name.as_bytes(), value.as_bytes()] {
				let len = u32::try_from(part.len()).map_err(|_| Error::Corrupt("metadata length"))?;
				aad.extend_from_slice(&len.to_le_bytes());
				aad.extend_from_slice(part);
			}
		}
		Ok(aad)
	}

	fn required_meta(&self, name: &str, what: &'static str) -> Result<String> {
		self.meta(name).ok_or(Error::Corrupt(what))
	}

	fn set_password(&mut self, entry: &FieldAtlas) {
		let (id, is_new) = self.set_raw(TAG_PASSWORD, entry_name(entry), entry);
		if !is_new {
			// Linux indexes tags only when an entry first appears, so edited
			// tags are found there after a reload. Reindex at once instead.
			self.tags.retain(|_, ids| {
				ids.retain(|other| *other != id);
				!ids.is_empty()
			});
		}
		let tags = entry.get_str(field::TAGS).unwrap_or_default();
		for tag in tags.split(',').map(str::trim).filter(|tag| !tag.is_empty()) {
			let ids = self.tags.entry(tag.to_owned()).or_default();
			ids.push(id);
			ids.sort_unstable();
		}
	}

	fn password(&self, id: u32) -> Option<FieldAtlas> {
		let (tag, data) = self.entries.get(&id)?;
		if *tag != TAG_PASSWORD {
			return None;
		}
		FieldAtlas::deserialize(data).ok()
	}

	fn password_by_name(&self, name: &str) -> Option<FieldAtlas> {
		self.password(*self.passwords.get(name)?)
	}

	fn query(&self, query: &str) -> Option<FieldAtlas> {
		if let Some(entry) = self.password_by_name(query) {
			return Some(entry);
		}
		// "tag" is the first entry with that tag, "tag.N" the Nth.
		let (tag, index) = match query.split_once('.') {
			Some((tag, index)) => match index.parse::<usize>() {
				Ok(index) => (tag, index.saturating_sub(1)),
				Err(_) => (query, 0),
			},
			None => (query, 0),
		};
		self.password(*self.tags.get(tag)?.get(index)?)
	}

	fn previous(&self, name: &str) -> Option<FieldAtlas> {
		let (_, id) = self
			.passwords
			.range::<str, _>((Bound::Unbounded, Bound::Excluded(name)))
			.next_back()?;
		self.password(*id)
	}

	fn next(&self, name: &str) -> Option<FieldAtlas> {
		let offset = usize::from(self.passwords.contains_key(name));
		let (_, id) = self
			.passwords
			.range::<str, _>((Bound::Included(name), Bound::Unbounded))
			.nth(offset)?;
		self.password(*id)
	}
}

impl Drop for Store {
	fn drop(&mut self) {
		for index in [&mut self.metas, &mut self.passwords] {
			for (mut name, _) in std::mem::take(index) {
				name.zeroize();
			}
		}
		for (mut tag, _) in std::mem::take(&mut self.tags) {
			tag.zeroize();
		}
	}
}

/// The unencrypted outer layer of a vault file.
struct Envelope {
	nonce: [u8; NONCE_SIZE],
	salt: [u8; SALT_SIZE],
	modified_ts: u64,
	ciphertext: Vec<u8>,
	revision: Option<u64>,
	aad: Vec<u8>,
	cost: Option<KdfCost>,
}

fn nonce_bytes(counter: u128) -> [u8; NONCE_SIZE] {
	let mut nonce = [0u8; NONCE_SIZE];
	nonce[..16].copy_from_slice(&counter.to_le_bytes());
	nonce
}

impl Envelope {
	fn parse(file: &[u8]) -> Result<Self> {
		let mut store = Store::default();
		for (tag, entry) in deserialize_entries(&erasure::decode(file)?)? {
			let name = entry
				.get_str(META_NAME)
				.ok_or(Error::Corrupt("envelope metadata name"))?;
			if tag != TAG_META || store.metas.contains_key(name) || entry.get_str(META_VALUE).is_none() {
				return Err(Error::Corrupt("invalid or duplicate envelope metadata"));
			}
			store.set_raw(TAG_META, name, &entry);
		}
		let (revision, aad) = match store.meta("format").as_deref() {
			None | Some("1") => (None, Vec::new()),
			Some("2") => {
				let rev = store
					.required_meta("revision", "missing revision")?
					.parse::<u64>()
					.map_err(|_| Error::Corrupt("revision"))?;
				if rev == 0 {
					return Err(Error::Corrupt("zero revision"));
				}
				(Some(rev), store.metadata_aad()?)
			}
			Some(_) => return Err(Error::Invalid("unsupported vault format; update Keptino")),
		};
		let cost = if revision.is_some() {
			match (store.meta("kdf_m"), store.meta("kdf_t"), store.meta("kdf_p")) {
				(None, None, None) => None,
				(Some(m), Some(t), Some(p)) => {
					let read = |field: &str, bounds: std::ops::RangeInclusive<u32>| {
						field
							.parse()
							.ok()
							.filter(|v| bounds.contains(v))
							.ok_or(Error::Corrupt("unsupported Argon2 costs"))
					};
					Some(KdfCost {
						memory_kib: read(&m, 4096..=16777216)?,
						passes: read(&t, 1..=64)?,
						lanes: read(&p, 1..=16)?,
					})
				}
				_ => return Err(Error::Corrupt("incomplete Argon2 costs")),
			}
		} else {
			None
		};
		let counter = store
			.required_meta("nonce", "missing nonce")?
			.parse::<u128>()
			.map_err(|_| Error::Corrupt("nonce"))?;
		let salt = Base64::decode_vec(&store.required_meta("salt", "missing salt")?)
			.ok()
			.and_then(|salt| <[u8; SALT_SIZE]>::try_from(salt).ok())
			.ok_or(Error::Corrupt("salt"))?;
		let modified_ts = store
			.required_meta("modified_ts", "missing modification time")?
			.parse::<u64>()
			.map_err(|_| Error::Corrupt("modification time"))?;
		let ciphertext = Base64::decode_vec(&store.required_meta("db", "missing database")?)
			.map_err(|_| Error::Corrupt("database encoding"))?;
		Ok(Self {
			nonce: nonce_bytes(counter),
			salt,
			modified_ts,
			ciphertext,
			revision,
			cost,
			aad,
		})
	}
	fn unlock(self, key: &Key) -> Result<Store> {
		let compressed = crypto::decrypt_with_aad(self.ciphertext, key, &self.nonce, &self.aad)?;
		let store = Store::deserialize(&crypto::decompress(&compressed)?)?;
		for name in ["db_name", "nonce", "salt", "modified_ts"] {
			store.required_meta(name, "incomplete database")?;
		}
		if self.revision.is_some() && store.metadata_aad()? != self.aad {
			return Err(Error::Corrupt("inner and outer metadata differ"));
		}
		if self.revision.is_none()
			&& (store.meta("modified_ts").and_then(|v| v.parse().ok()) != Some(self.modified_ts)
				|| !matches!(store.meta("format").as_deref(), None | Some("1"))
				|| store.meta("revision").is_some())
		{
			return Err(Error::Corrupt("inconsistent legacy metadata"));
		}
		Ok(store)
	}
}

pub struct Vault {
	key: Key,
	store: Store,
	working: FieldAtlas,
	source: Source,
	pub uploads_paused: bool,
	cost: KdfCost,
}

impl Vault {
	/// Opens the newer of the local and remote copies, preferring the local
	/// one on a tie, or creates an empty database when there is neither.
	pub fn open(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		local: Option<&[u8]>,
		remote: Option<&[u8]>,
		mem_kib: u32,
	) -> Result<Self> {
		let local = local.map(Envelope::parse);
		let remote = remote.map(Envelope::parse);
		let mut uploads_paused = false;
		let (first, second) = match (local, remote) {
			(None, None) => return Self::create(db_name, password, pepper, mem_kib),
			(Some(Ok(local)), Some(Ok(remote))) => {
				if local.salt != remote.salt {
					return Err(Error::Invalid("a different vault uses this name in the bucket"));
				}
				let remote_first = match (local.revision, remote.revision) {
					(Some(l), Some(r)) if l != r => r > l,
					_ => remote.modified_ts > local.modified_ts,
				};
				// A newer legacy timestamp can win selection during rollout.
				// Keep its local edits, but never overwrite a versioned remote.
				uploads_paused = !remote_first && remote.revision > local.revision;
				let l = (local, Source::Local);
				let r = (remote, Source::Remote);
				if remote_first { (r, Some(l)) } else { (l, Some(r)) }
			}
			(Some(Ok(local)), Some(Err(Error::Corrupt(_)))) => {
				uploads_paused = true;
				((local, Source::Local), None)
			}
			(Some(Err(Error::Corrupt(_))), Some(Ok(remote))) => {
				uploads_paused = true;
				((remote, Source::Remote), None)
			}
			(Some(Err(err)), _) | (_, Some(Err(err))) => return Err(err),
			(Some(Ok(local)), None) => ((local, Source::Local), None),
			(None, Some(Ok(remote))) => ((remote, Source::Remote), None),
		};
		let (candidate, source) = first;
		let mut cached = None;
		let mut unlock = |envelope: Envelope| {
			let cost = envelope.cost.unwrap_or(KdfCost::legacy(mem_kib));
			if cached.as_ref().is_none_or(|(previous, _)| *previous != cost) {
				let key = crypto::derive_master_key_with_cost(password, pepper, &envelope.salt, cost)?;
				cached = Some((cost, key));
			}
			envelope.unlock(&cached.as_ref().expect("key derived above").1)
		};
		let (store, source) = match unlock(candidate) {
			Ok(store) => (store, source),
			Err(err) => {
				let (alternate, source) = second.ok_or(err)?;
				uploads_paused = true;
				(unlock(alternate)?, source)
			}
		};
		let (cost, key) = cached.expect("successfully opened vault has a key");
		Ok(Self {
			key,
			store,
			source,
			working: blank_entry(),
			uploads_paused,
			cost,
		})
	}

	fn create(db_name: &str, password: &[u8], pepper: &[u8; PEPPER_SIZE], mem_kib: u32) -> Result<Self> {
		let mut salt = [0u8; SALT_SIZE];
		getrandom::fill(&mut salt).map_err(|_| Error::Kdf("no system randomness".into()))?;
		let key = crypto::derive_master_key(password, pepper, &salt, mem_kib)?;
		let created_ts = now().to_string();
		let mut store = Store::default();
		store.set_meta("db_name", db_name);
		store.set_meta("nonce", "0");
		store.set_meta("salt", &Base64::encode_string(&salt));
		store.set_meta("created_ts", &created_ts);
		store.set_meta("modified_ts", &created_ts);
		Ok(Self {
			key,
			store,
			working: blank_entry(),
			source: Source::New,
			uploads_paused: false,
			cost: KdfCost::legacy(mem_kib),
		})
	}

	pub fn source(&self) -> Source {
		self.source
	}

	pub fn meta(&self, name: &str) -> Option<String> {
		self.store.meta(name)
	}

	pub fn modified_ts(&self) -> u64 {
		self.meta("modified_ts")
			.and_then(|ts| ts.parse().ok())
			.unwrap_or_default()
	}

	/// The names of all password entries, in navigation order.
	pub fn names(&self) -> Vec<String> {
		self.store.passwords.keys().cloned().collect()
	}

	fn show(&mut self, found: Option<FieldAtlas>) -> bool {
		let is_found = found.is_some();
		self.working = found.unwrap_or_else(blank_entry);
		is_found
	}

	/// Shows the entry with this name, else the entry `tag` or `tag.N`
	/// selects. The working entry becomes blank when nothing matches.
	pub fn query(&mut self, query: &str) -> bool {
		let found = self.store.query(query);
		self.show(found)
	}

	#[allow(clippy::should_implement_trait)]
	pub fn next(&mut self) -> bool {
		let found = self.store.next(entry_name(&self.working));
		self.show(found)
	}

	pub fn previous(&mut self) -> bool {
		let found = self.store.previous(entry_name(&self.working));
		self.show(found)
	}

	pub fn clear(&mut self) {
		self.working = blank_entry();
	}

	pub fn get_field(&self, id: u8) -> Result<Zeroizing<Vec<u8>>> {
		if !(field::NAME..=field::MODIFIED_TS).contains(&id) {
			return Err(Error::Invalid("unknown field"));
		}
		Ok(Zeroizing::new(self.working.get(id).unwrap_or_default().to_vec()))
	}

	/// Edits the working entry. Nothing reaches the database before `commit`.
	pub fn set_field(&mut self, id: u8, value: &[u8]) -> Result<()> {
		if !(field::NAME..=field::TAGS).contains(&id) {
			return Err(Error::Invalid("field is not editable"));
		}
		if std::str::from_utf8(value).is_err() {
			return Err(Error::Invalid("text is not UTF-8"));
		}
		self.working.set(field::MODIFIED_TS, now().to_string().as_bytes());
		self.working.set(id, value);
		Ok(())
	}

	/// Stores the working entry under its name: an existing entry of that
	/// name keeps its creation time and takes every other field.
	pub fn commit(&mut self) -> Commit {
		let name = entry_name(&self.working).to_owned();
		if name.is_empty() {
			return Commit::EmptyName;
		}
		let (mut entry, outcome) = match self.store.password_by_name(&name) {
			Some(entry) => (entry, Commit::Updated),
			None => {
				let mut entry = blank_entry();
				entry.set(field::NAME, name.as_bytes());
				(entry, Commit::Created)
			}
		};
		for id in [
			field::USERNAME,
			field::PASSWORD,
			field::PIN,
			field::NOTE,
			field::URL,
			field::TAGS,
		] {
			entry.set(id, self.working.get(id).unwrap_or_default());
		}
		entry.set(field::MODIFIED_TS, now().to_string().as_bytes());
		self.store.set_password(&entry);
		if outcome == Commit::Created {
			self.working = entry;
		}
		outcome
	}

	/// Encrypts the database into the bytes of a vault file. The Backblaze
	/// object is the base64 text of the same bytes.
	pub fn revision(&self) -> u64 {
		self.store.meta("revision").and_then(|s| s.parse().ok()).unwrap_or(0)
	}

	pub fn save(&mut self) -> Result<Vec<u8>> {
		self.save_format(WRITE_FORMAT_2)
	}

	fn save_format(&mut self, upgrade: bool) -> Result<Vec<u8>> {
		let format_two = upgrade || self.store.meta("format").as_deref() == Some("2");
		if format_two {
			let next = self
				.revision()
				.checked_add(1)
				.ok_or(Error::Invalid("revision exhausted"))?;
			self.store.set_meta("format", "2");
			self.store.set_meta("kdf_m", &self.cost.memory_kib.to_string());
			self.store.set_meta("kdf_t", &self.cost.passes.to_string());
			self.store.set_meta("kdf_p", &self.cost.lanes.to_string());
			self.store.set_meta("revision", &next.to_string());
		}
		// Never go backwards: Linux keeps its local copy unless the remote
		// one is strictly newer, so a slow clock here must not hide a save.
		let modified_ts = now().max(self.modified_ts().saturating_add(1));
		self.store.set_meta("modified_ts", &modified_ts.to_string());
		// Older Linux versions increment this field after loading the vault.
		// Leave room for that increment when choosing a fresh nonce.
		let mut random = [0u8; 16];
		getrandom::fill(&mut random[..15]).map_err(|_| Error::Kdf("no system randomness".into()))?;
		let counter = u128::from_le_bytes(random).max(1);
		self.store.set_meta("nonce", &counter.to_string());
		let compressed = crypto::compress(&self.store.serialize());
		let aad = if format_two {
			self.store.metadata_aad()?
		} else {
			Vec::new()
		};
		let ciphertext = crypto::encrypt_with_aad(&compressed, &self.key, &nonce_bytes(counter), &aad);
		let mut envelope = Store::default();
		for (tag, data) in self.store.entries.values() {
			if *tag == TAG_META {
				let entry = FieldAtlas::deserialize(data)?;
				let name = entry.get_str(META_NAME).unwrap_or_default().to_owned();
				envelope.set_raw(TAG_META, &name, &entry);
			}
		}
		envelope.set_meta("db", &Base64::encode_string(&ciphertext));
		Ok(erasure::encode(&envelope.serialize()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::DEBUG_MEM_KIB;

	const PEPPER: [u8; PEPPER_SIZE] = [9; PEPPER_SIZE];

	fn open(local: Option<&[u8]>, remote: Option<&[u8]>) -> Result<Vault> {
		Vault::open("test", b"master", &PEPPER, local, remote, DEBUG_MEM_KIB)
	}

	fn add(vault: &mut Vault, name: &str, password: &str, tags: &str) -> Commit {
		vault.clear();
		vault.set_field(field::NAME, name.as_bytes()).unwrap();
		vault.set_field(field::PASSWORD, password.as_bytes()).unwrap();
		vault.set_field(field::TAGS, tags.as_bytes()).unwrap();
		vault.commit()
	}

	fn text(vault: &Vault, id: u8) -> String {
		String::from_utf8(vault.get_field(id).unwrap().to_vec()).unwrap()
	}

	#[test]
	fn reads_both_formats_preserves_cost_and_refuses_unknown_versions() {
		let mut vault = open(None, None).unwrap();
		let legacy = vault.save_format(false).unwrap();
		assert_eq!(open(Some(&legacy), None).unwrap().revision(), 0);
		let first = vault.save_format(true).unwrap();
		let mut opened = Vault::open("alias", b"master", &PEPPER, Some(&first), None, DEBUG_MEM_KIB * 2).unwrap();
		assert_eq!(opened.revision(), 1);
		let next = opened.save().unwrap();
		let preferred = open(Some(&next), Some(&first)).unwrap();
		assert_eq!((preferred.source(), preferred.revision()), (Source::Local, 2));
		assert!(!preferred.uploads_paused);

		let mut envelope = Store::deserialize(&erasure::decode(&next).unwrap()).unwrap();
		envelope.set_meta("revision", "3");
		let damaged = erasure::encode(&envelope.serialize());
		let recovered = open(Some(&first), Some(&damaged)).unwrap();
		assert_eq!(recovered.source(), Source::Local);
		assert!(recovered.uploads_paused);
		assert!(open(Some(&damaged), None).is_err());
		envelope.set_meta("format", "3");
		assert!(matches!(
			open(Some(&first), Some(&erasure::encode(&envelope.serialize()))),
			Err(Error::Invalid(_))
		));
	}

	#[test]
	fn honors_nondefault_argon2_costs_and_rejects_partial_or_out_of_range_costs() {
		let mut vault = open(None, None).unwrap();
		let salt = Base64::decode_vec(&vault.meta("salt").unwrap())
			.unwrap()
			.try_into()
			.unwrap();
		vault.cost = KdfCost {
			memory_kib: DEBUG_MEM_KIB,
			passes: 2,
			lanes: 2,
		};
		vault.key = crypto::derive_master_key_with_cost(b"master", &PEPPER, &salt, vault.cost).unwrap();
		let file = vault.save_format(true).unwrap();
		let mut reopened = open(Some(&file), None).unwrap();
		let saved = reopened.save().unwrap();
		let params = Envelope::parse(&saved).unwrap().cost.unwrap();
		assert_eq!((params.memory_kib, params.passes, params.lanes), (DEBUG_MEM_KIB, 2, 2));

		let mut header = Store::deserialize(&erasure::decode(&file).unwrap()).unwrap();
		header.set_meta("kdf_t", "65");
		assert!(matches!(
			Envelope::parse(&erasure::encode(&header.serialize())),
			Err(Error::Corrupt(_))
		));
		let id = header.metas.remove("kdf_p").unwrap();
		header.entries.remove(&id);
		header.set_meta("kdf_t", "2");
		assert!(matches!(
			Envelope::parse(&erasure::encode(&header.serialize())),
			Err(Error::Corrupt(_))
		));
	}

	#[test]
	fn canonical_metadata_uses_utf8_byte_lengths_and_excludes_db() {
		let mut store = Store::default();
		store.set_meta("é", "ab");
		store.set_meta("db", "ciphertext");
		store.set_meta("a", "é");
		assert_eq!(
			store.metadata_aad().unwrap(),
			b"keptino-envelope-v2\x01\0\0\0a\x02\0\0\0\xc3\xa9\x02\0\0\0\xc3\xa9\x02\0\0\0ab"
		);
	}

	#[test]
	fn create_edit_save_reopen() {
		let mut vault = open(None, None).unwrap();
		assert_eq!(vault.source(), Source::New);
		assert_eq!(vault.commit(), Commit::EmptyName);
		assert_eq!(add(&mut vault, "bank", "hunter2", "money, work"), Commit::Created);
		assert_eq!(add(&mut vault, "mail", "pässword 🔑", "work"), Commit::Created);
		assert_eq!(add(&mut vault, "bank", "changed", "money"), Commit::Updated);
		let file = vault.save().unwrap();
		assert_eq!(file.len() % 12, 0);
		assert!(!file.windows(7).any(|w| w == b"hunter2" || w == b"changed"));

		let mut vault = open(Some(&file), None).unwrap();
		assert_eq!(vault.source(), Source::Local);
		assert_eq!(vault.meta("db_name").as_deref(), Some("test"));
		assert_eq!(vault.names(), ["bank", "mail"]);
		assert!(vault.query("bank"));
		assert_eq!(text(&vault, field::PASSWORD), "changed");
		assert!(vault.next());
		assert_eq!(text(&vault, field::PASSWORD), "pässword 🔑");
		assert!(!vault.next());
		assert_eq!(text(&vault, field::NAME), "");
		assert!(vault.next());
		assert_eq!(text(&vault, field::NAME), "bank");
		assert!(!vault.previous());
		assert!(vault.query("work"));
		assert_eq!(text(&vault, field::NAME), "mail");
		assert!(vault.query("money.1"));
		assert_eq!(text(&vault, field::NAME), "bank");
		assert!(!vault.query("work.2"));
		assert!(!vault.query("absent"));

		assert_eq!(
			Vault::open("test", b"wrong", &PEPPER, Some(&file), None, DEBUG_MEM_KIB).err(),
			Some(Error::Decryption)
		);
		assert_eq!(
			Vault::open("test", b"master", &[8; 32], Some(&file), None, DEBUG_MEM_KIB).err(),
			Some(Error::Decryption)
		);
	}

	#[test]
	fn working_entry_is_not_stored_before_commit_and_fields_are_checked() {
		let mut vault = open(None, None).unwrap();
		add(&mut vault, "site", "one", "");
		assert!(vault.query("site"));
		vault.set_field(field::PASSWORD, b"two").unwrap();
		assert!(vault.query("site"));
		assert_eq!(text(&vault, field::PASSWORD), "one");
		assert!(vault.set_field(field::CREATED_TS, b"1").is_err());
		assert!(vault.set_field(field::NAME, &[0xff]).is_err());
		assert!(vault.get_field(0).is_err());
		assert!(vault.get_field(10).is_err());
		// Renaming the working entry stores a copy under the new name.
		vault.set_field(field::NAME, b"site2").unwrap();
		assert_eq!(vault.commit(), Commit::Created);
		assert_eq!(vault.names(), ["site", "site2"]);
	}

	#[test]
	fn the_newer_copy_wins_and_local_wins_a_tie() {
		let mut vault = open(None, None).unwrap();
		add(&mut vault, "first", "1", "");
		let older = vault.save().unwrap();
		add(&mut vault, "second", "2", "");
		let newer = vault.save().unwrap();
		let opened = open(Some(&older), Some(&newer)).unwrap();
		assert_eq!(opened.source(), Source::Remote);
		assert_eq!(opened.names().len(), 2);
		let opened = open(Some(&newer), Some(&older)).unwrap();
		assert_eq!(opened.source(), Source::Local);
		assert_eq!(opened.names().len(), 2);
		assert_eq!(open(Some(&older), Some(&older)).unwrap().source(), Source::Local);
		assert_eq!(open(None, Some(&older)).unwrap().source(), Source::Remote);
	}

	#[test]
	fn saves_advance_time_and_never_repeat_a_nonce() {
		let mut vault = open(None, None).unwrap();
		let mut seen = std::collections::BTreeSet::new();
		let mut last_ts = vault.modified_ts();
		for _ in 0..20 {
			vault.save().unwrap();
			assert!(vault.modified_ts() > last_ts);
			last_ts = vault.modified_ts();
			let nonce: u128 = vault.meta("nonce").unwrap().parse().unwrap();
			assert!(nonce < 1 << 120);
			assert!(seen.insert(nonce));
		}
	}

	#[test]
	fn edited_tags_are_reindexed() {
		let mut vault = open(None, None).unwrap();
		add(&mut vault, "a", "1", "x");
		add(&mut vault, "b", "2", "x");
		add(&mut vault, "a", "1", "y");
		assert!(vault.query("x"));
		assert_eq!(text(&vault, field::NAME), "b");
		assert!(vault.query("y"));
		assert_eq!(text(&vault, field::NAME), "a");
		assert!(!vault.query("x.2"));
	}

	#[test]
	fn damaged_files_fail_cleanly() {
		let mut vault = open(None, None).unwrap();
		add(&mut vault, "a", "1", "");
		let file = vault.save().unwrap();
		let mut repairable = file.clone();
		let chunk = file.len() / 12;
		for shard in 0..4 {
			repairable[shard * chunk + 100] ^= 1;
		}
		assert_eq!(open(Some(&repairable), None).unwrap().names(), ["a"]);
		assert!(open(Some(&file[..file.len() - 12]), None).is_err());
		assert!(open(Some(b"junk"), None).is_err());
		assert!(open(Some(&[]), None).is_err());
	}
}
