//! An unlocked database and the entry being viewed or edited, with the
//! semantics of the Linux application's password screen.

use crate::{
	error::{Error, Result},
	security::{LockedKey, derive_master_key},
};
use base64ct::{Base64, Encoding};
use keptino_core::{
	crypto::{self, NONCE_SIZE, PEPPER_SIZE, SALT_SIZE},
	format::{
		self, Envelope, FieldAtlas, KdfParams, TAG_META, TAG_PASSWORD, deserialize_entries, field,
		meta_field, serialize_entries,
	},
	policy,
};
use std::{collections::BTreeMap, ops::Bound, time::SystemTime};
use zeroize::{Zeroize, Zeroizing};

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
						.get_str(meta_field::NAME)
						.ok_or(Error::Corrupt("unnamed meta entry"))?
						.to_owned();
					if store.metas.contains_key(&name) || entry.get_str(meta_field::VALUE).is_none()
					{
						return Err(Error::Corrupt("invalid or duplicate inner metadata"));
					}
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
		serialize_entries(
			self.entries
				.values()
				.map(|(tag, value)| (*tag, value.as_slice())),
		)
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
		entry.set(meta_field::NAME, name.as_bytes());
		entry.set(meta_field::VALUE, value.as_bytes());
		self.set_raw(TAG_META, name, &entry);
	}

	fn remove_meta(&mut self, name: &str) {
		if let Some(id) = self.metas.remove(name) {
			self.entries.remove(&id);
		}
	}

	fn meta(&self, name: &str) -> Option<String> {
		let (_, data) = self.entries.get(self.metas.get(name)?)?;
		let entry = FieldAtlas::deserialize(data).ok()?;
		entry.get_str(meta_field::VALUE).map(str::to_owned)
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

fn nonce_bytes(counter: u128) -> [u8; NONCE_SIZE] {
	let mut nonce = [0u8; NONCE_SIZE];
	nonce[..16].copy_from_slice(&counter.to_le_bytes());
	nonce
}

pub struct Vault {
	key: LockedKey,
	store: Store,
	working: FieldAtlas,
	source: Source,
	pub uploads_paused: bool,
	cost: KdfParams,
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
		let parse = |file: &[u8]| {
			Envelope::parse(file, KdfParams::memory_only(mem_kib)).map_err(Error::from)
		};
		let local = local.map(parse);
		let remote = remote.map(parse);
		let mut uploads_paused = false;
		let (first, second) = match (local, remote) {
			(None, None) => return Self::create(db_name, password, pepper, mem_kib),
			(Some(Ok(local)), Some(Ok(remote))) => {
				if local.salt != remote.salt {
					return Err(Error::Invalid(
						"a different vault uses this name in the bucket",
					));
				}
				let remote_first = !policy::prefer_local(&local, &remote);
				// A newer legacy timestamp can win selection during rollout.
				// Keep its local edits, but never overwrite a versioned remote.
				uploads_paused = !remote_first && remote.revision > local.revision;
				let l = (local, Source::Local);
				let r = (remote, Source::Remote);
				if remote_first {
					(r, Some(l))
				} else {
					(l, Some(r))
				}
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
			let cost = envelope.kdf;
			if cached
				.as_ref()
				.is_none_or(|(previous, _)| *previous != cost)
			{
				let key = derive_master_key(password, pepper, &envelope.salt, cost)?;
				cached = Some((cost, key));
			}
			let database = envelope
				.open(&cached.as_ref().expect("key derived above").1)
				.ok_or(Error::Decryption)?;
			let store = Store::deserialize(&database)?;
			if !store.metas.contains_key("db_name") {
				return Err(Error::Corrupt("incomplete database"));
			}
			Ok(store)
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

	fn create(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		mem_kib: u32,
	) -> Result<Self> {
		let mut salt = [0u8; SALT_SIZE];
		getrandom::fill(&mut salt).map_err(|_| Error::Kdf("no system randomness".into()))?;
		let key = derive_master_key(password, pepper, &salt, KdfParams::memory_only(mem_kib))?;
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
			cost: KdfParams::memory_only(mem_kib),
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
		Ok(Zeroizing::new(
			self.working.get(id).unwrap_or_default().to_vec(),
		))
	}

	/// Edits the working entry. Nothing reaches the database before `commit`.
	pub fn set_field(&mut self, id: u8, value: &[u8]) -> Result<()> {
		if !(field::NAME..=field::TAGS).contains(&id) {
			return Err(Error::Invalid("field is not editable"));
		}
		if std::str::from_utf8(value).is_err() {
			return Err(Error::Invalid("text is not UTF-8"));
		}
		self.working
			.set(field::MODIFIED_TS, now().to_string().as_bytes());
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
		self.store
			.meta("revision")
			.and_then(|s| s.parse().ok())
			.unwrap_or(0)
	}

	pub fn save(&mut self) -> Result<Vec<u8>> {
		let next = self
			.revision()
			.checked_add(1)
			.ok_or(Error::Invalid("revision exhausted"))?;
		self.store.set_meta("revision", &next.to_string());
		if self.store.meta("kdf_m").is_none() {
			for (name, value) in self.cost.meta_pairs() {
				self.store.set_meta(&name, &value);
			}
		}
		self.store.remove_meta("format");
		// Never go backwards: Linux keeps its local copy unless the remote
		// one is strictly newer, so a slow clock here must not hide a save.
		let modified_ts = now().max(self.modified_ts().saturating_add(1));
		self.store.set_meta("modified_ts", &modified_ts.to_string());
		// Older Linux versions increment this field after loading the vault.
		// Leave room for that increment when choosing a fresh nonce.
		let mut random = [0u8; 16];
		getrandom::fill(&mut random[..15])
			.map_err(|_| Error::Kdf("no system randomness".into()))?;
		let counter = u128::from_le_bytes(random).max(1);
		self.store.set_meta("nonce", &counter.to_string());
		let database = self.store.serialize();
		let meta = format::meta_pairs(&database)?;
		let ciphertext = crypto::encrypt(
			&crypto::compress(&database),
			&self.key,
			&nonce_bytes(counter),
			&[],
		);
		Ok(format::encode_envelope(&meta, &ciphertext))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keptino_core::format::{FormatError, decode_shards, encode_shards};
	const DEBUG_MEM_KIB: u32 = KdfParams::DEBUG.m_cost;

	const PEPPER: [u8; PEPPER_SIZE] = [9; PEPPER_SIZE];

	fn open(local: Option<&[u8]>, remote: Option<&[u8]>) -> Result<Vault> {
		Vault::open("test", b"master", &PEPPER, local, remote, DEBUG_MEM_KIB)
	}

	fn add(vault: &mut Vault, name: &str, password: &str, tags: &str) -> Commit {
		vault.clear();
		vault.set_field(field::NAME, name.as_bytes()).unwrap();
		vault
			.set_field(field::PASSWORD, password.as_bytes())
			.unwrap();
		vault.set_field(field::TAGS, tags.as_bytes()).unwrap();
		vault.commit()
	}

	fn text(vault: &Vault, id: u8) -> String {
		String::from_utf8(vault.get_field(id).unwrap().to_vec()).unwrap()
	}

	fn fixture_pepper() -> [u8; PEPPER_SIZE] {
		let mut pepper = [0u8; PEPPER_SIZE];
		hex::decode_to_slice(
			"3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1",
			&mut pepper,
		)
		.unwrap();
		pepper
	}

	#[test]
	fn reads_both_formats_preserves_cost_and_refuses_unknown_versions() {
		let first = include_bytes!("../tests/fixtures/linux-debug-v2.keptino").as_slice();
		let pepper = fixture_pepper();
		let load = |local, remote| {
			Vault::open(
				"alias",
				b"correct horse battery staple",
				&pepper,
				local,
				remote,
				DEBUG_MEM_KIB * 2,
			)
		};
		let mut opened = load(Some(first), None).unwrap();
		assert_eq!(opened.revision(), 1);
		let next = opened.save().unwrap();
		assert!(
			Envelope::parse(&next, KdfParams::DEBUG)
				.unwrap()
				.aad
				.is_empty()
		);
		let preferred = load(Some(&next), Some(first)).unwrap();
		assert_eq!(
			(preferred.source(), preferred.revision()),
			(Source::Local, 2)
		);
		assert!(!preferred.uploads_paused);

		let mut envelope = Store::deserialize(&decode_shards(&next).unwrap()).unwrap();
		envelope.set_meta("revision", "3");
		let damaged = encode_shards(&envelope.serialize());
		let recovered = load(Some(first), Some(&damaged)).unwrap();
		assert_eq!(recovered.source(), Source::Local);
		assert!(recovered.uploads_paused);
		assert!(load(Some(&damaged), None).is_err());
		envelope.set_meta("format", "3");
		assert!(matches!(
			load(Some(first), Some(&encode_shards(&envelope.serialize()))),
			Err(Error::Invalid(_))
		));
	}

	#[test]
	fn legacy_files_require_an_exact_mirror_before_accepting_an_import() {
		let legacy = include_bytes!("../tests/fixtures/linux-debug.keptino");
		let pepper = fixture_pepper();
		let load = |file: &[u8]| {
			Vault::open(
				"imported-name",
				b"correct horse battery staple",
				&pepper,
				Some(file),
				None,
				DEBUG_MEM_KIB,
			)
		};
		assert_eq!(load(legacy).unwrap().revision(), 0);
		let original = decode_shards(legacy).unwrap();
		for (name, value) in [
			("db_name", Some("imported-name")),
			("note", Some("extra")),
			("created_ts", None),
		] {
			let mut outer = Store::deserialize(&original).unwrap();
			match value {
				Some(value) => outer.set_meta(name, value),
				None => outer.remove_meta(name),
			}
			assert!(matches!(
				load(&encode_shards(&outer.serialize())),
				Err(Error::Decryption)
			));
		}
		let mut duplicate = Store::default();
		duplicate.set_meta("db_name", "vaultdebug");
		let mut repeated = original;
		repeated.extend_from_slice(&duplicate.serialize());
		assert!(matches!(
			Envelope::parse(&encode_shards(&repeated), KdfParams::DEBUG),
			Err(FormatError::Damaged)
		));
	}

	#[test]
	fn honors_nondefault_argon2_costs_and_rejects_partial_or_out_of_range_costs() {
		let mut vault = open(None, None).unwrap();
		let salt = Base64::decode_vec(&vault.meta("salt").unwrap())
			.unwrap()
			.try_into()
			.unwrap();
		vault.cost = KdfParams {
			m_cost: DEBUG_MEM_KIB,
			t_cost: 2,
			p_cost: 2,
		};
		vault.key = derive_master_key(b"master", &PEPPER, &salt, vault.cost).unwrap();
		let file = vault.save().unwrap();
		let mut reopened = open(Some(&file), None).unwrap();
		let saved = reopened.save().unwrap();
		let params = Envelope::parse(&saved, KdfParams::DEBUG).unwrap().kdf;
		assert_eq!(
			(params.m_cost, params.t_cost, params.p_cost),
			(DEBUG_MEM_KIB, 2, 2)
		);

		let mut header = Store::deserialize(&decode_shards(&file).unwrap()).unwrap();
		header.set_meta("kdf_t", "65");
		assert!(matches!(
			Envelope::parse(&encode_shards(&header.serialize()), KdfParams::DEBUG),
			Err(FormatError::Damaged)
		));
		let id = header.metas.remove("kdf_p").unwrap();
		header.entries.remove(&id);
		header.set_meta("kdf_t", "2");
		assert!(matches!(
			Envelope::parse(&encode_shards(&header.serialize()), KdfParams::DEBUG),
			Err(FormatError::Damaged)
		));
	}

	#[test]
	fn create_edit_save_reopen() {
		let mut vault = open(None, None).unwrap();
		assert_eq!(vault.source(), Source::New);
		assert_eq!(vault.commit(), Commit::EmptyName);
		assert_eq!(
			add(&mut vault, "bank", "hunter2", "money, work"),
			Commit::Created
		);
		assert_eq!(
			add(&mut vault, "mail", "pässword 🔑", "work"),
			Commit::Created
		);
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
			Vault::open(
				"test",
				b"master",
				&[8; 32],
				Some(&file),
				None,
				DEBUG_MEM_KIB
			)
			.err(),
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
		assert_eq!(
			open(Some(&older), Some(&older)).unwrap().source(),
			Source::Local
		);
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
