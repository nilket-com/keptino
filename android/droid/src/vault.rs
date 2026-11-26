//! An unlocked database and the entry being viewed or edited, with the
//! semantics of the Linux application's password screen.

use crate::{
	atlas::{FieldAtlas, deserialize_entries, serialize_entries},
	crypto::{self, Key, NONCE_SIZE, PEPPER_SIZE, SALT_SIZE},
	erasure,
	error::{Error, Result},
};
use base64ct::{Base64, Encoding};
use std::{collections::BTreeMap, ops::Bound, time::SystemTime};
use zeroize::{Zeroize, Zeroizing};

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
}

fn nonce_bytes(counter: u128) -> [u8; NONCE_SIZE] {
	let mut nonce = [0u8; NONCE_SIZE];
	nonce[..16].copy_from_slice(&counter.to_le_bytes());
	nonce
}

impl Envelope {
	fn parse(file: &[u8]) -> Result<Self> {
		let store = Store::deserialize(&erasure::decode(file)?)?;
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
		})
	}
}

pub struct Vault {
	key: Key,
	store: Store,
	working: FieldAtlas,
	source: Source,
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
		let local = local.map(Envelope::parse).transpose()?;
		let remote = remote.map(Envelope::parse).transpose()?;
		let (envelope, source) = match (local, remote) {
			(None, None) => return Self::create(db_name, password, pepper, mem_kib),
			(Some(local), None) => (local, Source::Local),
			(None, Some(remote)) => (remote, Source::Remote),
			(Some(local), Some(remote)) => {
				if local.modified_ts >= remote.modified_ts {
					(local, Source::Local)
				} else {
					(remote, Source::Remote)
				}
			}
		};
		let key = crypto::derive_master_key(password, pepper, &envelope.salt, mem_kib)?;
		let compressed = crypto::decrypt(envelope.ciphertext, &key, &envelope.nonce)?;
		let store = Store::deserialize(&crypto::decompress(&compressed)?)?;
		for name in ["db_name", "nonce", "salt", "modified_ts"] {
			store.required_meta(name, "incomplete database")?;
		}
		Ok(Self {
			key,
			store,
			working: blank_entry(),
			source,
		})
	}

	fn create(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		mem_kib: u32,
	) -> Result<Self> {
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
	pub fn save(&mut self) -> Result<Vec<u8>> {
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
		let ciphertext = crypto::encrypt(&compressed, &self.key, &nonce_bytes(counter));
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
