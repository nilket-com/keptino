//! An unlocked database and the entry being viewed or edited, with the
//! semantics of the Linux application's password screen.

use crate::{
	error::{Error, Result},
	security::{LockedKey, derive_master_key},
};
use keptino_core::{
	crypto::PEPPER_SIZE,
	format::{Envelope, KdfParams, field},
	vault::{self, Database, OpenError, PasswordEntry, UnlockError, unlock},
};
use zeroize::Zeroizing;
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

pub struct Vault {
	database: Database<LockedKey>,
	working: PasswordEntry<LockedKey>,
	source: Source,
	pub uploads_paused: bool,
	cost: KdfParams,
}

impl Vault {
	/// Opens the newer of the local and remote copies, preferring the local
	/// one on a tie, or creates an empty database when there is neither. The
	/// selection, the fallback and the cautions are the core's; this head
	/// decides what to do about a copy that does not parse.
	pub fn open(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		local: Option<&[u8]>,
		remote: Option<&[u8]>,
		mem_kib: u32,
	) -> Result<Self> {
		Self::open_at(
			db_name,
			password,
			pepper,
			local,
			remote,
			KdfParams::memory_only(mem_kib),
		)
	}

	/// A new vault derived at `cost`, for tests of costs other than the
	/// default.
	#[cfg(test)]
	fn create(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		cost: KdfParams,
	) -> Result<Self> {
		Self::open_at(db_name, password, pepper, None, None, cost)
	}

	fn open_at(
		db_name: &str,
		password: &[u8],
		pepper: &[u8; PEPPER_SIZE],
		local: Option<&[u8]>,
		remote: Option<&[u8]>,
		default_cost: KdfParams,
	) -> Result<Self> {
		let parse = |file: &[u8]| Envelope::parse(file, default_cost).map_err(Error::from);
		let local = local.map(parse);
		let remote = remote.map(parse);
		// A copy that fails to parse is set aside and the other one opened,
		// with uploads paused so it is not written over blindly.
		let mut uploads_paused = false;
		let (local, remote) = match (local, remote) {
			(Some(Ok(local)), Some(Err(Error::Corrupt(_)))) => {
				uploads_paused = true;
				(Some(local), None)
			}
			(Some(Err(Error::Corrupt(_))), Some(Ok(remote))) => {
				uploads_paused = true;
				(None, Some(remote))
			}
			(Some(Err(err)), _) | (_, Some(Err(err))) => return Err(err),
			(local, remote) => (local.map(Result::unwrap), remote.map(Result::unwrap)),
		};
		let derive =
			|salt: &[u8; 32], cost: KdfParams| derive_master_key(password, pepper, salt, cost);
		let unlocked =
			unlock(db_name, local, remote, default_cost, derive).map_err(|err| match err {
				UnlockError::DifferentVault => {
					Error::Invalid("a different vault uses this name in the bucket")
				}
				UnlockError::Derive(err) => err,
				UnlockError::Open(OpenError::Decryption) => Error::Decryption,
				UnlockError::Open(OpenError::Format(err)) => err.into(),
				UnlockError::Open(OpenError::Memory(_)) => {
					Error::Memory("cannot allocate vault key memory")
				}
			})?;
		let source = match unlocked.source {
			vault::Source::New => Source::New,
			vault::Source::Local => Source::Local,
			vault::Source::Remote => Source::Remote,
		};
		Ok(Self {
			database: unlocked.database,
			working: PasswordEntry::try_new()?,
			source,
			uploads_paused: uploads_paused || unlocked.caution.is_some(),
			cost: unlocked.cost,
		})
	}

	pub fn source(&self) -> Source {
		self.source
	}

	pub fn meta(&self, name: &str) -> Option<String> {
		self.database.meta(name)
	}

	pub fn modified_ts(&self) -> u64 {
		self.database.modified_ts()
	}

	/// The names of all password entries, in navigation order.
	pub fn names(&self) -> Vec<String> {
		self.database.names()
	}

	fn show(&mut self, found: Option<PasswordEntry<LockedKey>>) -> bool {
		let is_found = found.is_some();
		self.working = found.unwrap_or_default();
		is_found
	}

	/// Shows the entry with this name, else the entry `tag` or `tag.N`
	/// selects. The working entry becomes blank when nothing matches.
	pub fn query(&mut self, query: &str) -> bool {
		let found = self.database.query(query);
		self.show(found)
	}

	#[allow(clippy::should_implement_trait)]
	pub fn next(&mut self) -> bool {
		let found = self.database.next(self.working.get_name());
		self.show(found)
	}

	pub fn previous(&mut self) -> bool {
		let found = self.database.previous(self.working.get_name());
		self.show(found)
	}

	pub fn clear(&mut self) {
		self.working = PasswordEntry::new();
	}

	pub fn get_field(&self, id: u8) -> Result<Zeroizing<Vec<u8>>> {
		if !(field::NAME..=field::MODIFIED_TS).contains(&id) {
			return Err(Error::Invalid("unknown field"));
		}
		let mut text = self.working.get_field(id);
		Ok(Zeroizing::new(std::mem::take(&mut *text).into_bytes()))
	}

	/// Edits the working entry. Nothing reaches the database before `commit`.
	pub fn set_field(&mut self, id: u8, value: &[u8]) -> Result<()> {
		if !(field::NAME..=field::TAGS).contains(&id) {
			return Err(Error::Invalid("field is not editable"));
		}
		let text = std::str::from_utf8(value).map_err(|_| Error::Invalid("text is not UTF-8"))?;
		self.working.set_field(id, text);
		Ok(())
	}

	/// Stores the working entry under its name: an existing entry of that
	/// name keeps its creation time and takes every other field.
	pub fn commit(&mut self) -> Commit {
		let name = self.working.get_name();
		if name.is_empty() {
			return Commit::EmptyName;
		}
		let (mut entry, outcome) = match self.database.get_password_entry_by_name(name) {
			Some(entry) => (entry, Commit::Updated),
			None => {
				let mut entry = PasswordEntry::new();
				entry.set_name(name);
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
			entry.set_field(id, &self.working.get_field(id));
		}
		if outcome == Commit::Created {
			self.working = entry.clone();
		}
		self.database.set_password_entry(entry);
		outcome
	}

	pub fn revision(&self) -> u64 {
		self.database.revision().unwrap_or(0)
	}

	pub fn save(&mut self) -> Result<Vec<u8>> {
		if self.revision() == u64::MAX {
			return Err(Error::Invalid("revision exhausted"));
		}
		Ok(self.database.encode(false, self.cost))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keptino_core::format::{FormatError, decode_shards, encode_shards};
	use keptino_core::vault::{MetaEntry, Store};
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

		let mut envelope = Store::<LockedKey>::deserialize(&decode_shards(&next).unwrap()).unwrap();
		envelope.set_meta_entry(MetaEntry::new("revision", "3"));
		let damaged = encode_shards(&envelope.serialize());
		let recovered = load(Some(first), Some(&damaged)).unwrap();
		assert_eq!(recovered.source(), Source::Local);
		assert!(recovered.uploads_paused);
		assert!(load(Some(&damaged), None).is_err());
		envelope.set_meta_entry(MetaEntry::new("format", "3"));
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
			let mut outer = Store::<LockedKey>::deserialize(&original).unwrap();
			match value {
				Some(value) => outer.set_meta_entry(MetaEntry::new(name, value)),
				None => {
					outer.remove_meta_entry(name);
				}
			}
			assert!(matches!(
				load(&encode_shards(&outer.serialize())),
				Err(Error::Decryption)
			));
		}
		let mut duplicate = Store::<LockedKey>::default();
		duplicate.set_meta_entry(MetaEntry::new("db_name", "vaultdebug"));
		let mut repeated = original;
		repeated.extend_from_slice(&duplicate.serialize());
		assert!(matches!(
			Envelope::parse(&encode_shards(&repeated), KdfParams::DEBUG),
			Err(FormatError::Damaged)
		));
	}

	#[test]
	fn honors_nondefault_argon2_costs_and_rejects_partial_or_out_of_range_costs() {
		let cost = KdfParams {
			m_cost: DEBUG_MEM_KIB,
			t_cost: 2,
			p_cost: 2,
		};
		let mut vault = Vault::create("test", b"master", &PEPPER, cost).unwrap();
		let file = vault.save().unwrap();
		let mut reopened = open(Some(&file), None).unwrap();
		let saved = reopened.save().unwrap();
		let params = Envelope::parse(&saved, KdfParams::DEBUG).unwrap().kdf;
		assert_eq!(
			(params.m_cost, params.t_cost, params.p_cost),
			(DEBUG_MEM_KIB, 2, 2)
		);

		let mut header = Store::<LockedKey>::deserialize(&decode_shards(&file).unwrap()).unwrap();
		header.set_meta_entry(MetaEntry::new("kdf_t", "65"));
		assert!(matches!(
			Envelope::parse(&encode_shards(&header.serialize()), KdfParams::DEBUG),
			Err(FormatError::Damaged)
		));
		header.remove_meta_entry("kdf_p");
		header.set_meta_entry(MetaEntry::new("kdf_t", "2"));
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
