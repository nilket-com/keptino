//! The database in memory, with every record sealed. Entries are kept as
//! ciphertext under keys that live in the head's secret storage, and each
//! password entry's secret fields are sealed again under a key of their own,
//! so an idle vault holds no entry plaintext and a record is decrypted only
//! for the moment it is used. The head supplies the storage through
//! [`KeyStore`]: `memfd_secret` pages on Linux, locked pages on Android.

use crate::{
	crypto::{self, KEY_SIZE, NONCE_SIZE},
	format::{
		self, AAD_FORMAT, Envelope, FieldAtlas, FormatError, KdfParams, TAG_META, TAG_PASSWORD,
		encode_envelope, envelope_aad, field, meta_field,
	},
	policy,
};
use chacha20poly1305::{
	XChaCha20Poly1305,
	aead::{AeadInPlace, KeyInit},
};
use std::{
	collections::BTreeMap,
	mem,
	sync::{Arc, RwLock},
	time::SystemTime,
};
use zeroize::{Zeroize, Zeroizing};

/// A 32-byte key that lives where the head can protect it. The bytes are
/// exposed only inside `with_key`, for the duration of one cipher operation.
pub trait KeyStore: Send + Sync + Sized + 'static {
	type Error: std::error::Error + Send + Sync + 'static;
	/// Heads with a vault list can index its non-secret row fields at open.
	const INDEX_LIST_ROWS: bool = false;

	/// Stores a key the caller already holds, such as the derived master key.
	fn from_bytes(key: &[u8; KEY_SIZE]) -> Result<Self, Self::Error>;

	/// Maps the key, runs `f` over it, and unmaps it.
	fn with_key<T>(&self, f: impl FnOnce(&[u8; KEY_SIZE]) -> T) -> T;

	/// Wipes the key; the store is unusable afterwards.
	fn zeroize(&self);

	/// A store holding fresh random bytes, for a per-record or per-entry key.
	fn fresh() -> Result<Self, Self::Error> {
		let mut bytes = Zeroizing::new([0u8; KEY_SIZE]);
		getrandom::fill(&mut *bytes).expect("Memory key generation failed");
		Self::from_bytes(&bytes)
	}
}

fn try_fresh_key<K: KeyStore>() -> Result<Arc<K>, K::Error> {
	K::fresh().map(Arc::new)
}

/// Why a vault file did not open under a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
	/// Wrong key, tampered envelope or damaged payload: the AEAD or the
	/// mirror check refused it.
	Decryption,
	/// Authenticated, but the database inside is not well formed.
	Format(FormatError),
	/// The head could not provide secret storage for the records.
	Memory(String),
}

impl std::fmt::Display for OpenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Decryption => {
				f.write_str("Cannot decrypt vault. Check the master password and pepper.")
			}
			Self::Format(err) => write!(f, "Vault contents: {err}"),
			Self::Memory(what) => write!(f, "Secret memory unavailable: {what}"),
		}
	}
}

impl std::error::Error for OpenError {}

/// Bytes sealed under a shared key with a caller-supplied context as
/// associated data. Cloning copies the ciphertext only.
pub struct ProtectedBytes<K: KeyStore> {
	ciphertext: Vec<u8>,
	nonce: [u8; NONCE_SIZE],
	key: Arc<K>,
}

impl<K: KeyStore> Clone for ProtectedBytes<K> {
	fn clone(&self) -> Self {
		Self {
			ciphertext: self.ciphertext.clone(),
			nonce: self.nonce,
			key: Arc::clone(&self.key),
		}
	}
}

impl<K: KeyStore> ProtectedBytes<K> {
	pub fn plaintext_len(&self) -> usize {
		self.ciphertext.len() - 16
	}

	pub fn seal(key: &Arc<K>, plaintext: &[u8], context: &[u8]) -> Self {
		let mut nonce = [0u8; NONCE_SIZE];
		getrandom::fill(&mut nonce).expect("Memory nonce generation failed");
		// Reserve the authentication tag up front, so encryption cannot leave
		// a reallocated plaintext buffer behind.
		let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
		buffer.extend_from_slice(plaintext);
		key.with_key(|key| {
			XChaCha20Poly1305::new(key.into())
				.encrypt_in_place((&nonce).into(), context, &mut *buffer)
				.expect("Memory encryption failed");
		});
		Self {
			ciphertext: mem::take(&mut *buffer),
			nonce,
			key: Arc::clone(key),
		}
	}

	/// The plaintext. A record that fails to authenticate is a corrupted
	/// process, and the process stops rather than return something else.
	pub fn open(&self, context: &[u8]) -> Zeroizing<Vec<u8>> {
		let mut buffer = Zeroizing::new(self.ciphertext.clone());
		self.key.with_key(|key| {
			XChaCha20Poly1305::new(key.into())
				.decrypt_in_place((&self.nonce).into(), context, &mut *buffer)
				.expect("Memory authentication failed");
		});
		buffer
	}
}

/// Entry records sealed under one key, with the record's position and tag
/// as context, so a record cannot be swapped for another.
pub struct EntryAtlas<K: KeyStore> {
	entries: BTreeMap<u32, (u8, ProtectedBytes<K>)>,
	key: Arc<K>,
}

impl<K: KeyStore> Default for EntryAtlas<K> {
	fn default() -> Self {
		Self::try_new().expect("Secret memory unavailable")
	}
}

impl<K: KeyStore> EntryAtlas<K> {
	pub fn try_new() -> Result<Self, K::Error> {
		Ok(Self {
			entries: BTreeMap::new(),
			key: try_fresh_key()?,
		})
	}

	fn context(id: u32, tag: u8) -> [u8; 5] {
		let mut context = [0; 5];
		context[..4].copy_from_slice(&id.to_le_bytes());
		context[4] = tag;
		context
	}

	pub fn ids(&self) -> impl Iterator<Item = u32> + '_ {
		self.entries.keys().copied()
	}

	pub fn len(&self) -> usize {
		self.entries.len()
	}

	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	/// The size of the serialized records, from the ciphertext lengths, so
	/// no record is opened to measure it.
	pub fn serialized_len(&self) -> usize {
		self.entries
			.values()
			.map(|(_, value)| 5 + value.plaintext_len())
			.sum()
	}

	/// Each record's plaintext length, from its ciphertext.
	pub fn record_lens(&self) -> impl Iterator<Item = usize> + '_ {
		self.entries
			.values()
			.map(|(_, value)| value.plaintext_len())
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		let size = self.serialized_len();
		let mut buffer = Zeroizing::new(Vec::with_capacity(size));
		for id in self.entries.keys() {
			let (tag, value) = self.get(*id).unwrap();
			buffer.push(tag);
			buffer.extend_from_slice(&(value.len() as u32).to_le_bytes());
			buffer.extend_from_slice(&value);
		}
		buffer
	}

	pub fn set(&mut self, id: u32, tag: u8, value: &[u8]) {
		let sealed = ProtectedBytes::seal(&self.key, value, &Self::context(id, tag));
		self.entries.insert(id, (tag, sealed));
	}

	pub fn get(&self, id: u32) -> Option<(u8, Zeroizing<Vec<u8>>)> {
		let (tag, sealed) = self.entries.get(&id)?;
		Some((*tag, sealed.open(&Self::context(id, *tag))))
	}

	/// Drops a record; its ciphertext goes with it and its key is per-atlas,
	/// so nothing of the plaintext remains recoverable from this object.
	pub fn remove(&mut self, id: u32) -> bool {
		self.entries.remove(&id).is_some()
	}

	pub fn clear(&mut self) {
		self.entries.clear();
		self.key.zeroize();
	}
}

/// A name and a value: the database's own bookkeeping.
#[derive(Clone, Default)]
pub struct MetaEntry {
	fields: FieldAtlas,
}

impl From<FieldAtlas> for MetaEntry {
	fn from(fields: FieldAtlas) -> Self {
		Self { fields }
	}
}

impl MetaEntry {
	pub fn new(name: &str, value: &str) -> Self {
		let mut entry = Self::default();
		entry.fields.set(meta_field::NAME, name.as_bytes());
		entry.fields.set(meta_field::VALUE, value.as_bytes());
		entry
	}

	pub fn get_name(&self) -> &str {
		self.fields.get_str(meta_field::NAME).unwrap_or_default()
	}

	pub fn get_value(&self) -> &str {
		self.fields.get_str(meta_field::VALUE).unwrap_or_default()
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		self.fields.serialize()
	}
}

fn now_seconds() -> u64 {
	SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or_default()
}

/// Which fields of a password entry are secrets, sealed separately.
const SECRET_FIELDS: [u8; 3] = [field::PASSWORD, field::PIN, field::NOTE];

/// One password entry. Name, username, URL, tags and timestamps are held in
/// the clear for display and indexing; password, PIN and note are sealed
/// under a key of this entry's own and opened only on request.
pub struct PasswordEntry<K: KeyStore> {
	fields: FieldAtlas,
	secrets: BTreeMap<u8, ProtectedBytes<K>>,
	key: Arc<K>,
}

impl<K: KeyStore> Clone for PasswordEntry<K> {
	fn clone(&self) -> Self {
		Self {
			fields: self.fields.clone(),
			secrets: self.secrets.clone(),
			key: Arc::clone(&self.key),
		}
	}
}

impl<K: KeyStore> From<FieldAtlas> for PasswordEntry<K> {
	fn from(fields: FieldAtlas) -> Self {
		Self::try_from_fields(fields).expect("Secret memory unavailable")
	}
}

impl<K: KeyStore> Default for PasswordEntry<K> {
	fn default() -> Self {
		Self::new()
	}
}

impl<K: KeyStore> PasswordEntry<K> {
	/// Seals the secret fields of a parsed record under a key of its own.
	pub fn try_from_fields(mut fields: FieldAtlas) -> Result<Self, K::Error> {
		let key = try_fresh_key()?;
		let mut secrets = BTreeMap::new();
		for id in SECRET_FIELDS {
			if let Some(value) = fields.take(id) {
				secrets.insert(id, ProtectedBytes::seal(&key, &value, &[id]));
			}
		}
		Ok(Self {
			fields,
			secrets,
			key,
		})
	}

	pub fn new() -> Self {
		Self::try_new().expect("Secret memory unavailable")
	}

	/// A blank entry stamped now, or the head's error when no key page can
	/// be had for it.
	pub fn try_new() -> Result<Self, K::Error> {
		let now = now_seconds().to_string();
		let mut fields = FieldAtlas::default();
		fields.set(field::CREATED_TS, now.as_bytes());
		fields.set(field::MODIFIED_TS, now.as_bytes());
		Self::try_from_fields(fields)
	}

	fn touch(&mut self) {
		self.fields
			.set(field::MODIFIED_TS, now_seconds().to_string().as_bytes());
	}

	fn set_plain(&mut self, id: u8, value: &str) {
		self.touch();
		self.fields.set(id, value.as_bytes());
	}

	fn set_secret(&mut self, id: u8, value: &str) {
		self.touch();
		self.secrets
			.insert(id, ProtectedBytes::seal(&self.key, value.as_bytes(), &[id]));
	}

	pub fn set_name(&mut self, name: &str) {
		self.set_plain(field::NAME, name);
	}
	pub fn set_username(&mut self, username: &str) {
		self.set_plain(field::USERNAME, username);
	}
	pub fn set_url(&mut self, url: &str) {
		self.set_plain(field::URL, url);
	}
	pub fn set_tags(&mut self, tags: &str) {
		self.set_plain(field::TAGS, tags);
	}
	pub fn set_password(&mut self, password: &str) {
		self.set_secret(field::PASSWORD, password);
	}
	pub fn set_pin(&mut self, pin: &str) {
		self.set_secret(field::PIN, pin);
	}
	pub fn set_note(&mut self, note: &str) {
		self.set_secret(field::NOTE, note);
	}

	fn plain(&self, id: u8) -> &str {
		self.fields.get_str(id).unwrap_or_default()
	}

	pub fn get_name(&self) -> &str {
		self.plain(field::NAME)
	}
	pub fn get_username(&self) -> &str {
		self.plain(field::USERNAME)
	}
	pub fn get_url(&self) -> &str {
		self.plain(field::URL)
	}
	pub fn get_tags(&self) -> &str {
		self.plain(field::TAGS)
	}
	pub fn get_password(&self) -> Zeroizing<String> {
		self.open_secret(field::PASSWORD)
	}
	pub fn get_pin(&self) -> Zeroizing<String> {
		self.open_secret(field::PIN)
	}
	pub fn get_note(&self) -> Zeroizing<String> {
		self.open_secret(field::NOTE)
	}

	/// Seconds since the epoch, as stored; `None` when absent or malformed.
	pub fn created(&self) -> Option<i64> {
		self.fields.get_str(field::CREATED_TS)?.parse().ok()
	}
	pub fn modified(&self) -> Option<i64> {
		self.fields.get_str(field::MODIFIED_TS)?.parse().ok()
	}

	/// Any field by id, secret or not, as text; for callers that address
	/// fields by number, such as the Android bridge.
	pub fn get_field(&self, id: u8) -> Zeroizing<String> {
		if SECRET_FIELDS.contains(&id) {
			self.open_secret(id)
		} else {
			Zeroizing::new(self.plain(id).to_owned())
		}
	}

	/// Sets any editable field by id; timestamps are not editable.
	pub fn set_field(&mut self, id: u8, value: &str) -> bool {
		if !(field::NAME..=field::TAGS).contains(&id) {
			return false;
		}
		if SECRET_FIELDS.contains(&id) {
			self.set_secret(id, value);
		} else {
			self.set_plain(id, value);
		}
		true
	}

	fn open_secret(&self, id: u8) -> Zeroizing<String> {
		let Some(value) = self.secrets.get(&id) else {
			return Zeroizing::new(String::new());
		};
		let mut bytes = value.open(&[id]);
		// Validate before transferring ownership to the wiping String.
		std::str::from_utf8(&bytes).expect("Invalid secret text");
		Zeroizing::new(String::from_utf8(mem::take(&mut *bytes)).unwrap())
	}

	/// The entry's field record with every secret in the clear, as stored.
	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		let mut fields = self.fields.clone();
		for (id, value) in &self.secrets {
			let plaintext = value.open(&[*id]);
			fields.set(*id, &plaintext);
		}
		fields.serialize()
	}
}

/// The entries of one vault with their indexes. Record ids are positions in
/// the file, so an edited entry keeps its place and a deleted one simply
/// leaves the next save one record shorter.
pub struct Store<K: KeyStore> {
	next_id: u32,
	entries: EntryAtlas<K>,
	index_by_name: BTreeMap<String, u32>,
	index_by_tag: BTreeMap<String, Vec<u32>>,
	list_rows: BTreeMap<u32, ListRow>,
}

/// Display metadata retained by heads that render a list.
pub struct ListRow {
	pub username: Zeroizing<String>,
	pub tags: Zeroizing<String>,
	pub weak: bool,
}

impl ListRow {
	fn new(username: &str, tags: &str, password: &str) -> Self {
		Self {
			username: Zeroizing::new(username.to_owned()),
			tags: Zeroizing::new(tags.to_owned()),
			weak: !password.is_empty()
				&& crate::health::estimate_bits(password) < crate::health::WEAK_BITS,
		}
	}
}

impl<K: KeyStore> Default for Store<K> {
	fn default() -> Self {
		Self::try_new().expect("Secret memory unavailable")
	}
}

fn password_key(name: &str) -> String {
	format!("password\x00{name}")
}

fn meta_key(name: &str) -> String {
	format!("meta\x00{name}")
}

fn tag_key(tag: &str) -> String {
	format!("tag\x00{tag}")
}

impl<K: KeyStore> Store<K> {
	pub fn try_new() -> Result<Self, K::Error> {
		Ok(Self {
			next_id: 0,
			entries: EntryAtlas::try_new()?,
			index_by_name: BTreeMap::new(),
			index_by_tag: BTreeMap::new(),
			list_rows: BTreeMap::new(),
		})
	}

	/// Parses an authenticated database, sealing every record. An unknown
	/// record tag is refused rather than dropped: it is something a newer
	/// version wrote. A head that cannot provide a key page for every entry
	/// reports that instead of stopping the process.
	pub fn deserialize(data: &[u8]) -> Result<Self, OpenError> {
		let memory = |err: K::Error| OpenError::Memory(err.to_string());
		let mut store = Self::try_new().map_err(memory)?;
		for (tag, fields) in format::deserialize_entries(data).map_err(OpenError::Format)? {
			match tag {
				TAG_META => store.set_meta_entry(MetaEntry::from(fields)),
				TAG_PASSWORD => {
					// Every known field is text; a record that is not would
					// panic later in open_secret, so it is refused here.
					for id in field::NAME..=field::MODIFIED_TS {
						if fields.get(id).is_some() && fields.get_str(id).is_none() {
							return Err(OpenError::Format(FormatError::Damaged));
						}
					}
					let name = fields.get_str(field::NAME).unwrap_or_default().to_owned();
					let tags = fields.get_str(field::TAGS).unwrap_or_default().to_owned();
					// Sealed as parsed: no per-entry key page is touched until
					// an entry is actually opened.
					let row = K::INDEX_LIST_ROWS.then(|| {
						ListRow::new(
							fields.get_str(field::USERNAME).unwrap_or_default(),
							&tags,
							fields.get_str(field::PASSWORD).unwrap_or_default(),
						)
					});
					store.store_password_record(&name, &tags, &fields.serialize(), row);
				}
				_ => return Err(OpenError::Format(FormatError::Damaged)),
			}
		}
		Ok(store)
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		self.entries.serialize()
	}

	fn allocate(&mut self, key: String) -> (u32, bool) {
		match self.index_by_name.get(&key) {
			Some(id) => (*id, false),
			None => {
				let id = self.next_id;
				self.next_id += 1;
				self.index_by_name.insert(key, id);
				(id, true)
			}
		}
	}

	fn unindex_tags(&mut self, id: u32) {
		self.index_by_tag.retain(|_, ids| {
			ids.retain(|other| *other != id);
			!ids.is_empty()
		});
	}

	/// Stores an entry under its name, replacing one of the same name. Tags
	/// are reindexed on every store, so an edited tag list is found at once.
	pub fn set_password_entry(&mut self, entry: PasswordEntry<K>) {
		let name = entry.get_name().to_owned();
		let tags = entry.get_tags().to_owned();
		let row = K::INDEX_LIST_ROWS
			.then(|| ListRow::new(entry.get_username(), &tags, &entry.get_password()));
		self.store_password_record(&name, &tags, &entry.serialize(), row);
	}

	/// Indexes a password record by name and tags and seals its bytes.
	fn store_password_record(
		&mut self,
		name: &str,
		tags: &str,
		record: &[u8],
		row: Option<ListRow>,
	) {
		let (id, is_new) = self.allocate(password_key(name));
		if !is_new {
			self.unindex_tags(id);
		}
		for tag in tags.split(',').map(str::trim) {
			if tag.is_empty() {
				continue;
			}
			let ids = self.index_by_tag.entry(tag_key(tag)).or_default();
			ids.push(id);
			ids.sort_unstable();
		}
		if let Some(row) = row {
			self.list_rows.insert(id, row);
		}
		self.entries.set(id, TAG_PASSWORD, record);
	}

	fn password(&self, id: u32) -> Option<PasswordEntry<K>> {
		let (tag, data) = self.entries.get(id)?;
		if tag != TAG_PASSWORD {
			return None;
		}
		Some(PasswordEntry::from(
			FieldAtlas::deserialize(&data).expect("Invalid field record"),
		))
	}

	pub fn get_password_entry_by_name(&self, name: &str) -> Option<PasswordEntry<K>> {
		self.password(*self.index_by_name.get(&password_key(name))?)
	}

	/// Removes an entry and every index reference to it.
	pub fn delete_password_entry(&mut self, name: &str) -> bool {
		let Some(id) = self.index_by_name.remove(&password_key(name)) else {
			return false;
		};
		self.entries.remove(id);
		self.unindex_tags(id);
		self.list_rows.remove(&id);
		true
	}

	pub fn get_password_entries_by_tag(&self, tag: &str) -> Option<Vec<PasswordEntry<K>>> {
		let ids = self.index_by_tag.get(&tag_key(tag))?;
		Some(ids.iter().filter_map(|id| self.password(*id)).collect())
	}

	/// The entry by name, else the first entry carrying `query` as a tag,
	/// else the N-th such entry for `tag.N`.
	pub fn query(&self, query: &str) -> Option<PasswordEntry<K>> {
		if let Some(entry) = self.get_password_entry_by_name(query) {
			return Some(entry);
		}
		let (tag, index) = match query.split_once('.') {
			Some((tag, index)) => match index.parse::<usize>() {
				Ok(index) => (tag, index.saturating_sub(1)),
				Err(_) => (query, 0),
			},
			None => (query, 0),
		};
		self.password(*self.index_by_tag.get(&tag_key(tag))?.get(index)?)
	}

	/// The names of every password entry, in navigation order.
	pub fn names(&self) -> Vec<String> {
		let prefix = password_key("");
		self.index_by_name
			.range(prefix.clone()..format!("password\x01"))
			.map(|(key, _)| key[prefix.len()..].to_owned())
			.collect()
	}

	/// The names a find for `query` lands on, in navigation order: every
	/// name containing it, ignoring case, and every entry tagged exactly
	/// with it. Only the indexes are read, so no record is opened.
	pub fn find(&self, query: &str) -> Vec<String> {
		let query = query.trim();
		if query.is_empty() {
			return Vec::new();
		}
		let lower = query.to_lowercase();
		let tagged = self
			.index_by_tag
			.get(&tag_key(query))
			.map_or(&[][..], Vec::as_slice);
		let prefix = password_key("");
		self.index_by_name
			.range(prefix.clone()..format!("password\x01"))
			.filter(|(key, id)| {
				key[prefix.len()..].to_lowercase().contains(&lower)
					|| tagged.binary_search(id).is_ok()
			})
			.map(|(key, _)| key[prefix.len()..].to_owned())
			.collect()
	}

	pub fn previous(&self, name: &str) -> Option<PasswordEntry<K>> {
		let id = *self
			.index_by_name
			.range(password_key("")..password_key(name))
			.next_back()?
			.1;
		self.password(id)
	}

	pub fn next(&self, name: &str) -> Option<PasswordEntry<K>> {
		let key = password_key(name);
		let offset = usize::from(self.index_by_name.contains_key(&key));
		let id = *self
			.index_by_name
			.range(key..format!("password\x01"))
			.nth(offset)?
			.1;
		self.password(id)
	}

	pub fn set_meta_entry(&mut self, entry: MetaEntry) {
		let (id, _) = self.allocate(meta_key(entry.get_name()));
		self.entries.set(id, TAG_META, &entry.serialize());
	}

	pub fn get_meta_entry(&self, name: &str) -> Option<MetaEntry> {
		let (tag, data) = self
			.entries
			.get(*self.index_by_name.get(&meta_key(name))?)?;
		(tag == TAG_META)
			.then(|| MetaEntry::from(FieldAtlas::deserialize(&data).expect("Invalid field record")))
	}

	pub fn remove_meta_entry(&mut self, name: &str) -> bool {
		let Some(id) = self.index_by_name.remove(&meta_key(name)) else {
			return false;
		};
		self.entries.remove(id)
	}

	/// Every meta entry as (name, value), in storage order.
	pub fn meta_pairs(&self) -> Vec<(String, String)> {
		self.entries
			.ids()
			.filter_map(|id| {
				let (tag, data) = self.entries.get(id)?;
				if tag != TAG_META {
					return None;
				}
				let meta = MetaEntry::from(FieldAtlas::deserialize(&data).ok()?);
				Some((meta.get_name().to_owned(), meta.get_value().to_owned()))
			})
			.collect()
	}

	pub fn zeroize(&mut self) {
		self.entries.clear();
		self.list_rows.clear();
		for (mut key, _) in mem::take(&mut self.index_by_name) {
			key.zeroize();
		}
		for (mut key, _) in mem::take(&mut self.index_by_tag) {
			key.zeroize();
		}
	}
}

impl<K: KeyStore> Drop for Store<K> {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// A vault open in memory: its store and its master key, shared between the
/// user interface and the save path.
pub struct Database<K: KeyStore> {
	store: Arc<RwLock<Store<K>>>,
	/// Replaced only by `rekey`; read for every save.
	master_key: Arc<RwLock<K>>,
}

impl<K: KeyStore> Clone for Database<K> {
	fn clone(&self) -> Self {
		Self {
			store: Arc::clone(&self.store),
			master_key: Arc::clone(&self.master_key),
		}
	}
}

impl<K: KeyStore> Database<K> {
	/// An empty database under `master_key`, with the meta entries every
	/// vault starts with.
	pub fn new(master_key: K, db_name: &str, salt: &[u8; crypto::SALT_SIZE]) -> Self {
		Self::try_new(master_key, db_name, salt).expect("Secret memory unavailable")
	}

	/// As `new`, reporting the head's error when no key page can be had for
	/// the records.
	pub fn try_new(
		master_key: K,
		db_name: &str,
		salt: &[u8; crypto::SALT_SIZE],
	) -> Result<Self, K::Error> {
		use base64ct::{Base64, Encoding};
		let db = Self::with_store(master_key, Store::try_new()?);
		let created = now_seconds().to_string();
		db.set_meta_entry(MetaEntry::new("db_name", db_name));
		db.set_meta_entry(MetaEntry::new("nonce", "0"));
		db.set_meta_entry(MetaEntry::new("salt", &Base64::encode_string(salt)));
		db.set_meta_entry(MetaEntry::new("created_ts", &created));
		db.set_meta_entry(MetaEntry::new("modified_ts", &created));
		Ok(db)
	}

	pub fn with_store(master_key: K, store: Store<K>) -> Self {
		Self {
			store: Arc::new(RwLock::new(store)),
			master_key: Arc::new(RwLock::new(master_key)),
		}
	}

	/// The salt the master key was derived with, from the meta entry.
	pub fn salt(&self) -> Option<[u8; crypto::SALT_SIZE]> {
		use base64ct::{Base64, Encoding};
		Base64::decode_vec(&self.meta("salt")?)
			.ok()?
			.try_into()
			.ok()
	}

	/// Whether `candidate` is the master key this database is open under,
	/// compared in constant time: how a head checks a typed password before
	/// it derives a new key from it (ADR 0041).
	pub fn is_master_key(&self, candidate: &[u8; KEY_SIZE]) -> bool {
		let slot = self.master_key.read().unwrap_or_else(|e| e.into_inner());
		slot.with_key(|key| {
			let difference = key
				.iter()
				.zip(candidate)
				.fold(0u8, |acc, (a, b)| acc | (a ^ b));
			std::hint::black_box(difference) == 0
		})
	}

	/// Puts the database under a new master key derived with `salt`: the old
	/// key is wiped, the salt meta entry is replaced, and the next save
	/// writes a file only the new key opens. The records are untouched;
	/// they are sealed under their own keys.
	pub fn rekey(&self, master_key: K, salt: &[u8; crypto::SALT_SIZE]) {
		use base64ct::{Base64, Encoding};
		let mut slot = self.master_key.write().unwrap_or_else(|e| e.into_inner());
		slot.zeroize();
		*slot = master_key;
		drop(slot);
		self.set_meta_entry(MetaEntry::new("salt", &Base64::encode_string(salt)));
	}

	/// Decrypts `envelope` under `key` and parses the database. On failure
	/// the key is handed back with the reason, so a second candidate can be
	/// tried under the same key.
	pub fn open(envelope: &Envelope, key: K) -> Result<Self, (K, OpenError)> {
		let Some(database) = key.with_key(|bytes| envelope.open(bytes)) else {
			return Err((key, OpenError::Decryption));
		};
		match Store::deserialize(&database) {
			Ok(store) => Ok(Self::with_store(key, store)),
			Err(err) => Err((key, err)),
		}
	}

	fn read(&self) -> std::sync::RwLockReadGuard<'_, Store<K>> {
		self.store.read().unwrap_or_else(|e| e.into_inner())
	}

	fn write(&self) -> std::sync::RwLockWriteGuard<'_, Store<K>> {
		self.store.write().unwrap_or_else(|e| e.into_inner())
	}

	pub fn set_password_entry(&self, entry: PasswordEntry<K>) {
		self.write().set_password_entry(entry);
	}
	pub fn get_password_entry_by_name(&self, name: &str) -> Option<PasswordEntry<K>> {
		self.read().get_password_entry_by_name(name)
	}
	pub fn delete_password_entry(&self, name: &str) -> bool {
		self.write().delete_password_entry(name)
	}
	pub fn get_password_entries_by_tag(&self, tag: &str) -> Option<Vec<PasswordEntry<K>>> {
		self.read().get_password_entries_by_tag(tag)
	}
	pub fn query(&self, query: &str) -> Option<PasswordEntry<K>> {
		self.read().query(query)
	}
	pub fn names(&self) -> Vec<String> {
		self.read().names()
	}
	/// Visits the list projection (ADR 0020, ADR 0022) without opening any
	/// sealed record.
	pub fn visit_list_rows(&self, mut visit: impl FnMut(&str, &ListRow)) {
		let store = self.read();
		let prefix = password_key("");
		for (key, id) in store
			.index_by_name
			.range(prefix.clone()..String::from("password\x01"))
		{
			if let Some(row) = store.list_rows.get(id) {
				visit(&key[prefix.len()..], row);
			}
		}
	}
	pub fn find(&self, query: &str) -> Vec<String> {
		self.read().find(query)
	}
	pub fn previous(&self, name: &str) -> Option<PasswordEntry<K>> {
		self.read().previous(name)
	}
	pub fn next(&self, name: &str) -> Option<PasswordEntry<K>> {
		self.read().next(name)
	}
	pub fn set_meta_entry(&self, entry: MetaEntry) {
		self.write().set_meta_entry(entry);
	}
	pub fn get_meta_entry(&self, name: &str) -> Option<MetaEntry> {
		self.read().get_meta_entry(name)
	}
	pub fn meta(&self, name: &str) -> Option<String> {
		Some(self.get_meta_entry(name)?.get_value().to_owned())
	}
	pub fn remove_meta_entry(&self, name: &str) -> bool {
		self.write().remove_meta_entry(name)
	}
	pub fn meta_pairs(&self) -> Vec<(String, String)> {
		self.read().meta_pairs()
	}
	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		self.read().serialize()
	}

	pub fn revision(&self) -> Option<u64> {
		self.meta("revision")?.parse().ok()
	}

	pub fn modified_ts(&self) -> u64 {
		self.meta("modified_ts")
			.and_then(|ts| ts.parse().ok())
			.unwrap_or_default()
	}

	/// Encrypts the database into the bytes of a vault file, advancing its
	/// bookkeeping: a modification time that never goes backwards, a fresh
	/// nonce, the next revision, the derivation cost recorded if it never
	/// was, and the AAD marker only in the marked form. `default_kdf` is the
	/// cost the database was opened with when none is recorded. A database
	/// or file over the budgets of ADR 0006 is refused unchanged.
	pub fn encode(&self, aad_form: bool, default_kdf: KdfParams) -> Result<Vec<u8>, FormatError> {
		// Refuse before touching the bookkeeping, and without opening a
		// record: a refused save leaves the revision and timestamps as they
		// were.
		{
			let store = self.read();
			if store.entries.serialized_len() > format::MAX_DATABASE_BYTES
				|| store.entries.len() > format::MAX_RECORDS
				|| store
					.entries
					.record_lens()
					.any(|len| len > format::MAX_FIELD_BYTES)
			{
				return Err(FormatError::TooLarge);
			}
		}
		// The bookkeeping is restored if the file still comes out over
		// budget, which the database budget is sized to prevent.
		let bookkeeping = [
			"modified_ts",
			"nonce",
			"revision",
			"kdf_m",
			"kdf_t",
			"kdf_p",
			"format",
		];
		let previous: Vec<(&str, Option<String>)> = bookkeeping
			.iter()
			.map(|name| (*name, self.meta(name)))
			.collect();
		// Never go backwards: a reader keeps its local copy unless the remote
		// one is strictly newer, so a slow clock must not hide a save.
		let modified = now_seconds().max(self.modified_ts().saturating_add(1));
		self.set_meta_entry(MetaEntry::new("modified_ts", &modified.to_string()));
		// Older readers increment this counter after loading; fifteen random
		// bytes leave room for that in the decimal u128 field.
		let mut random = [0u8; 16];
		getrandom::fill(&mut random[..15]).expect("Nonce generation failed");
		let counter = u128::from_le_bytes(random).max(1);
		self.set_meta_entry(MetaEntry::new("nonce", &counter.to_string()));
		let mut nonce = [0u8; NONCE_SIZE];
		nonce[..16].copy_from_slice(&counter.to_le_bytes());
		let revision = self
			.revision()
			.unwrap_or(0)
			.checked_add(1)
			.expect("Revision counter exhausted");
		self.set_meta_entry(MetaEntry::new("revision", &revision.to_string()));
		if self.get_meta_entry("kdf_m").is_none() {
			for (name, value) in default_kdf.meta_pairs() {
				self.set_meta_entry(MetaEntry::new(&name, &value));
			}
		}
		if aad_form {
			self.set_meta_entry(MetaEntry::new("format", &AAD_FORMAT.to_string()));
		} else {
			self.remove_meta_entry("format");
		}
		let restore = |db: &Self| {
			for (name, value) in &previous {
				match value {
					Some(value) => db.set_meta_entry(MetaEntry::new(name, value)),
					None => {
						db.remove_meta_entry(name);
					}
				}
			}
		};
		// The bookkeeping entries themselves count; a database at the exact
		// boundary is caught here and left as it was.
		{
			let store = self.read();
			if store.entries.serialized_len() > format::MAX_DATABASE_BYTES
				|| store.entries.len() > format::MAX_RECORDS
			{
				drop(store);
				restore(self);
				return Err(FormatError::TooLarge);
			}
		}
		let compressed = crypto::compress(&self.serialize());
		let meta = self.meta_pairs();
		let aad = if aad_form {
			envelope_aad(&meta)
		} else {
			Vec::new()
		};
		let ciphertext = self
			.master_key
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.with_key(|key| crypto::encrypt(&compressed, key, &nonce, &aad));
		let file = encode_envelope(&meta, &ciphertext);
		if file.len() > format::MAX_FILE_BYTES {
			restore(self);
			return Err(FormatError::TooLarge);
		}
		Ok(file)
	}

	/// Wipes the master key and every record; the database is empty after.
	pub fn zeroize(&self) {
		self.master_key
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.zeroize();
		self.write().zeroize();
	}
}

/// Which copy of a vault a session opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
	/// Neither copy existed; the database was created.
	New,
	Local,
	Remote,
}

/// A reason for the head to pause uploads after an unlock that succeeded:
/// writing over the other copy might lose something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caution {
	/// The preferred copy did not open and the other one did.
	OtherCopyFailed(Source),
	/// A legacy local copy won on its timestamp over a remote copy that
	/// carries a revision, as happens once during the rollout of revisions.
	LegacyLocalOverVersionedRemote,
}

/// An unlocked vault and how it came to be open.
pub struct Unlocked<K: KeyStore> {
	pub database: Database<K>,
	pub source: Source,
	/// The cost the opened copy was derived with, which a save records.
	pub cost: KdfParams,
	pub caution: Option<Caution>,
}

/// The copy `unlock` is about to open, for the head's key derivation: a
/// head with security keys reads the slots and asks a key for the roaming
/// secret before it derives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate<'a> {
	pub source: Source,
	pub salt: &'a [u8; crypto::SALT_SIZE],
	pub cost: KdfParams,
	pub slots: &'a [crate::roaming::KeySlot],
}

/// What a head's key derivation came back with.
pub enum Derived<K, E> {
	Key(K),
	/// No key could be made for this copy, say none of its slots opened; the
	/// other copy is tried and the head pauses uploads if it opens.
	Unavailable,
	/// The user gave up; the unlock ends here, whatever the other copy.
	Canceled,
	/// The derivation itself failed; the unlock ends here.
	Failed(E),
}

/// Why no copy opened. `E` is the head's key derivation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnlockError<E> {
	/// The two copies were made with different salts: another vault of the
	/// same name lives in the bucket.
	DifferentVault,
	Derive(E),
	/// The last copy tried did not open.
	Open(OpenError),
	/// No key could be made for the last copy tried.
	Unavailable,
	/// The user canceled the key derivation.
	Canceled,
}

impl<E> UnlockError<E> {
	/// Whether the other copy is still worth trying after this one.
	fn is_recoverable(&self) -> bool {
		matches!(self, Self::Open(_) | Self::Unavailable)
	}
}

impl<E: std::fmt::Display> std::fmt::Display for UnlockError<E> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::DifferentVault => {
				f.write_str("A different vault already uses this name in the selected bucket.")
			}
			Self::Derive(err) => write!(f, "{err}"),
			Self::Open(err) => write!(f, "{err}"),
			Self::Unavailable => f.write_str("No security key opened this vault."),
			Self::Canceled => f.write_str("Unlock canceled."),
		}
	}
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for UnlockError<E> {}

/// Opens the better of the local and remote copies, or creates the vault
/// when there is neither. `derive` turns a salt and a cost into the master
/// key; it runs once when both copies share a cost, which they do except
/// across a rekey. The preferred copy is tried first; when it fails and the
/// other opens, the result carries a caution so the head pauses uploads
/// instead of writing over a copy it could not read.
pub fn unlock<K: KeyStore, E>(
	db_name: &str,
	local: Option<Envelope>,
	remote: Option<Envelope>,
	default_cost: KdfParams,
	mut derive: impl FnMut(&Candidate<'_>) -> Derived<K, E>,
) -> Result<Unlocked<K>, UnlockError<E>> {
	let mut derive = |candidate: &Candidate<'_>| match derive(candidate) {
		Derived::Key(key) => Ok(key),
		Derived::Unavailable => Err(UnlockError::Unavailable),
		Derived::Canceled => Err(UnlockError::Canceled),
		Derived::Failed(err) => Err(UnlockError::Derive(err)),
	};
	let (first, second, caution) = match (local, remote) {
		(None, None) => {
			let mut salt = [0u8; crypto::SALT_SIZE];
			getrandom::fill(&mut salt).expect("Salt generation failed");
			let key = derive(&Candidate {
				source: Source::New,
				salt: &salt,
				cost: default_cost,
				slots: &[],
			})?;
			let database = Database::try_new(key, db_name, &salt)
				.map_err(|err| UnlockError::Open(OpenError::Memory(err.to_string())))?;
			return Ok(Unlocked {
				database,
				source: Source::New,
				cost: default_cost,
				caution: None,
			});
		}
		(Some(local), None) => ((local, Source::Local), None, None),
		(None, Some(remote)) => ((remote, Source::Remote), None, None),
		(Some(local), Some(remote)) => {
			if local.salt != remote.salt {
				return Err(UnlockError::DifferentVault);
			}
			let local_first = policy::prefer_local(&local, &remote);
			let caution = (local_first && remote.revision > local.revision)
				.then_some(Caution::LegacyLocalOverVersionedRemote);
			let local = (local, Source::Local);
			let remote = (remote, Source::Remote);
			if local_first {
				(local, Some(remote), caution)
			} else {
				(remote, Some(local), caution)
			}
		}
	};
	// A key that failed on one copy serves the other only when it was made
	// in the same context: same salt, same cost, same slots. Two copies of
	// one vault can differ in their slots after a backup key was added.
	let same_context = second.as_ref().is_some_and(|(alternate, _)| {
		alternate.salt == first.0.salt
			&& alternate.kdf == first.0.kdf
			&& alternate.slots == first.0.slots
	});
	let mut spare: Option<K> = None;
	let mut open =
		|envelope: &Envelope, source: Source| -> Result<(Database<K>, KdfParams), UnlockError<E>> {
			let cost = envelope.kdf;
			let key = match spare.take() {
				Some(key) if same_context => key,
				other => {
					if let Some(key) = other {
						key.zeroize();
					}
					derive(&Candidate {
						source,
						salt: &envelope.salt,
						cost,
						slots: &envelope.slots,
					})?
				}
			};
			match Database::open(envelope, key) {
				Ok(database) if database.meta("db_name").is_some() => Ok((database, cost)),
				Ok(database) => {
					database.zeroize();
					Err(UnlockError::Open(OpenError::Format(FormatError::Damaged)))
				}
				Err((key, err)) => {
					spare = Some(key);
					Err(UnlockError::Open(err))
				}
			}
		};
	let (candidate, source) = first;
	let outcome = match open(&candidate, source) {
		Ok((database, cost)) => Ok((database, cost, source, caution)),
		Err(err) => match second {
			Some((alternate, alternate_source)) if err.is_recoverable() => {
				open(&alternate, alternate_source).map(|(database, cost)| {
					(
						database,
						cost,
						alternate_source,
						Some(Caution::OtherCopyFailed(source)),
					)
				})
			}
			_ => Err(err),
		},
	};
	// A key left over from a failed attempt is wiped on every path out.
	if let Some(key) = spare.take() {
		key.zeroize();
	}
	let (database, source, cost, caution) = outcome.map(|(d, c, s, w)| (d, s, c, w))?;
	Ok(Unlocked {
		database,
		source,
		cost,
		caution,
	})
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use std::sync::Mutex;

	/// A heap key for tests: a wiping array behind a mutex.
	pub struct HeapKey(Mutex<Zeroizing<[u8; KEY_SIZE]>>);

	use std::convert::Infallible;

	impl KeyStore for HeapKey {
		type Error = Infallible;
		fn from_bytes(key: &[u8; KEY_SIZE]) -> Result<Self, Infallible> {
			Ok(Self(Mutex::new(Zeroizing::new(*key))))
		}
		fn with_key<T>(&self, f: impl FnOnce(&[u8; KEY_SIZE]) -> T) -> T {
			f(&self.0.lock().unwrap())
		}
		fn zeroize(&self) {
			self.0.lock().unwrap().zeroize();
		}
	}

	type Entry = PasswordEntry<HeapKey>;

	#[test]
	fn protected_bytes_clone_ciphertext_only_and_authenticate_context() {
		let key = try_fresh_key::<HeapKey>().unwrap();
		let plaintext = b"distinctive-password-123456789";
		let first = ProtectedBytes::seal(&key, plaintext, b"password");
		let second = ProtectedBytes::seal(&key, plaintext, b"password");
		assert_ne!(first.nonce, second.nonce);
		assert_ne!(first.ciphertext, second.ciphertext);
		assert!(
			!first
				.ciphertext
				.windows(plaintext.len())
				.any(|w| w == plaintext)
		);
		let cloned = first.clone();
		drop(first);
		assert_eq!(&*cloned.open(b"password"), plaintext);
		assert!(
			std::panic::catch_unwind(|| cloned.open(b"pin")).is_err(),
			"wrong context"
		);
		let mut altered = second.clone();
		altered.ciphertext[0] ^= 1;
		assert!(std::panic::catch_unwind(|| altered.open(b"password")).is_err());
	}

	#[test]
	fn secret_fields_are_absent_from_the_plaintext_atlas() {
		let mut entry = Entry::new();
		entry.set_password("secret");
		entry.set_pin("4567");
		entry.set_note("sensitive note");
		for id in SECRET_FIELDS {
			assert!(entry.fields.get(id).is_none());
		}
		let cloned = entry.clone();
		drop(entry);
		assert_eq!(cloned.get_password().as_str(), "secret");
		assert_eq!(cloned.get_field(field::PIN).as_str(), "4567");
		let restored = Entry::from(FieldAtlas::deserialize(&cloned.serialize()).unwrap());
		assert_eq!(restored.get_note().as_str(), "sensitive note");
		assert_eq!(restored.get_pin().as_str(), "4567");
		assert!(restored.created().is_some());
		let mut edited = restored;
		assert!(edited.set_field(field::URL, "https://x"));
		assert!(
			!edited.set_field(field::CREATED_TS, "1"),
			"timestamps are not editable"
		);
		assert_eq!(edited.get_url(), "https://x");
	}

	fn original_format_fixture() -> Vec<u8> {
		// The on-disk record of one entry, as every version has written it.
		let mut fields = Vec::new();
		for (id, text) in [
			(1u8, "example"),
			(2, "alice"),
			(3, "password 🔑"),
			(4, "1234"),
			(5, "private note"),
			(7, "test"),
		] {
			fields.push(id);
			fields.extend_from_slice(&(text.len() as u32).to_le_bytes());
			fields.extend_from_slice(text.as_bytes());
		}
		let mut bytes = vec![TAG_PASSWORD];
		bytes.extend_from_slice(&(fields.len() as u32).to_le_bytes());
		bytes.extend_from_slice(&fields);
		bytes
	}

	#[test]
	fn the_store_roundtrips_edits_deletes_and_reindexes_tags() {
		let fixture = original_format_fixture();
		let mut store = Store::<HeapKey>::deserialize(&fixture).unwrap();
		assert_eq!(&*store.serialize(), &fixture);
		let mut entry = store.get_password_entry_by_name("example").unwrap();
		assert_eq!(entry.get_password().as_str(), "password 🔑");
		assert_eq!(store.get_password_entries_by_tag("test").unwrap().len(), 1);
		entry.set_password("replacement");
		entry.set_tags("other");
		store.set_password_entry(entry);
		assert!(
			store.get_password_entries_by_tag("test").is_none(),
			"tags are reindexed on edit"
		);
		assert_eq!(store.query("other").unwrap().get_name(), "example");
		let reloaded = Store::<HeapKey>::deserialize(&store.serialize()).unwrap();
		assert_eq!(
			reloaded
				.get_password_entry_by_name("example")
				.unwrap()
				.get_password()
				.as_str(),
			"replacement"
		);
		assert_eq!(
			reloaded
				.get_password_entry_by_name("example")
				.unwrap()
				.get_note()
				.as_str(),
			"private note"
		);
		let mut second = Entry::new();
		second.set_name("other");
		second.set_tags("other, x");
		store.set_password_entry(second);
		assert_eq!(store.names(), ["example", "other"]);
		assert_eq!(store.next("example").unwrap().get_name(), "other");
		assert_eq!(store.previous("other").unwrap().get_name(), "example");
		assert!(store.next("other").is_none());
		assert_eq!(store.query("other.2").unwrap().get_name(), "other");
		// Find: names containing the text, any case, and exact tags, in
		// navigation order, without opening a record.
		assert_eq!(
			store.find("other"),
			["example", "other"],
			"a tag and a name"
		);
		assert_eq!(store.find("OTH"), ["other"], "names ignore case");
		assert_eq!(store.find("xam"), ["example"]);
		assert_eq!(store.find("x"), ["example", "other"]);
		assert!(store.find("  ").is_empty());
		assert!(store.find("missing").is_empty());
		assert!(store.delete_password_entry("example"));
		assert!(!store.delete_password_entry("example"));
		assert_eq!(store.get_password_entries_by_tag("other").unwrap().len(), 1);
		assert!(
			Store::<HeapKey>::deserialize(&[9, 0, 0, 0, 0]).is_err(),
			"unknown tags are refused"
		);
		let mut binary = FieldAtlas::default();
		binary.set(field::NAME, b"x");
		binary.set(field::PASSWORD, &[0xff, 0xfe]);
		let record = format::serialize_entries(std::iter::once((
			TAG_PASSWORD,
			binary.serialize().as_slice(),
		)));
		assert_eq!(
			Store::<HeapKey>::deserialize(&record).err(),
			Some(OpenError::Format(FormatError::Damaged)),
			"non-text secrets are refused at open"
		);
		store.zeroize();
		assert!(store.entries.is_empty());
		assert!(store.index_by_name.is_empty());
	}

	/// K7: an opened vault holds no entry plaintext. Every record sits in the
	/// atlas as ciphertext, and an entry's secret is in the clear only inside
	/// the Zeroizing buffer a getter returns.
	#[test]
	fn an_opened_store_holds_only_ciphertext() {
		let fixture = original_format_fixture();
		let store = Store::<HeapKey>::deserialize(&fixture).unwrap();
		for needle in [
			"password 🔑".as_bytes(),
			b"private note",
			b"example",
			b"alice",
		] {
			for (_, sealed) in store.entries.entries.values() {
				assert!(
					!sealed.ciphertext.windows(needle.len()).any(|w| w == needle),
					"record plaintext in the atlas"
				);
			}
		}
		assert_eq!(store.entries.len(), 1);
		let entry = store.get_password_entry_by_name("example").unwrap();
		assert!(entry.fields.get(field::PASSWORD).is_none());
		assert_eq!(entry.get_password().as_str(), "password 🔑");
	}

	#[test]
	fn a_database_encodes_and_reopens_through_the_envelope() {
		let key = HeapKey::from_bytes(&[42; KEY_SIZE]).unwrap();
		let db = Database::new(key, "example", &[7; crypto::SALT_SIZE]);
		let mut entry = Entry::new();
		entry.set_name("bank");
		entry.set_password("hunter2");
		db.set_password_entry(entry);
		let file = db.encode(false, KdfParams::DEBUG).unwrap();
		let envelope = Envelope::parse(&file, KdfParams::RELEASE).unwrap();
		assert_eq!(envelope.revision, Some(1));
		assert_eq!(
			envelope.kdf,
			KdfParams::DEBUG,
			"the opening cost was recorded"
		);
		assert!(envelope.aad.is_empty());
		let before = db.modified_ts();
		let second = Envelope::parse(
			&db.encode(false, KdfParams::DEBUG).unwrap(),
			KdfParams::DEBUG,
		)
		.unwrap();
		assert_eq!(second.revision, Some(2));
		assert!(second.modified > before - 1, "time never goes backwards");
		assert_ne!(second.nonce, envelope.nonce);
		let reopened = Database::open(&envelope, HeapKey::from_bytes(&[42; KEY_SIZE]).unwrap())
			.unwrap_or_else(|_| panic!("reopens"));
		assert_eq!(reopened.meta("db_name").as_deref(), Some("example"));
		assert_eq!(
			reopened
				.get_password_entry_by_name("bank")
				.unwrap()
				.get_password()
				.as_str(),
			"hunter2"
		);
		assert!(
			Database::open(&envelope, HeapKey::from_bytes(&[1; KEY_SIZE]).unwrap()).is_err(),
			"the key comes back on failure"
		);
		let marked = Envelope::parse(
			&db.encode(true, KdfParams::DEBUG).unwrap(),
			KdfParams::DEBUG,
		)
		.unwrap();
		assert!(!marked.aad.is_empty());
		assert!(Database::open(&marked, HeapKey::from_bytes(&[42; KEY_SIZE]).unwrap()).is_ok());
		db.zeroize();
		assert!(db.names().is_empty());
	}

	/// A vault file with exactly the meta entries the database holds: the
	/// save path's cryptography without its bookkeeping, for copies whose
	/// revision and timestamps a test wants to control.
	fn file_as_is(db: &Database<HeapKey>, outer_revision: Option<&str>) -> Vec<u8> {
		let counter: u128 = db.meta("nonce").unwrap().parse().unwrap();
		let mut nonce = [0u8; NONCE_SIZE];
		nonce[..16].copy_from_slice(&counter.to_le_bytes());
		let compressed = crypto::compress(&db.serialize());
		let ciphertext = db
			.master_key
			.read()
			.unwrap()
			.with_key(|key| crypto::encrypt(&compressed, key, &nonce, &[]));
		let mut meta = db.meta_pairs();
		if let Some(revision) = outer_revision {
			for (name, value) in &mut meta {
				if name == "revision" {
					*value = revision.to_owned();
				}
			}
		}
		encode_envelope(&meta, &ciphertext)
	}

	#[test]
	fn a_save_over_budget_is_refused_and_leaves_the_bookkeeping_alone() {
		let db = Database::new(
			HeapKey::from_bytes(&[3; KEY_SIZE]).unwrap(),
			"big",
			&[1; 32],
		);
		let mut entry = Entry::new();
		entry.set_name("note");
		db.set_password_entry(entry);
		let before = (db.revision(), db.modified_ts());
		// A record whose plaintext would be one byte over the budget, placed
		// in the atlas as ciphertext: the guard measures without opening it,
		// which is also what keeps this test cheap in a debug build.
		let (id, (tag, sealed)) = {
			let store = db.read();
			let (id, (tag, sealed)) = store.entries.entries.iter().next().unwrap();
			(*id, (*tag, sealed.clone()))
		};
		let oversized = ProtectedBytes {
			ciphertext: vec![0; format::MAX_DATABASE_BYTES - 5 + 1 + 16],
			nonce: sealed.nonce,
			key: Arc::clone(&sealed.key),
		};
		db.write().entries.entries.insert(id + 1, (tag, oversized));
		assert_eq!(
			db.encode(false, KdfParams::DEBUG).err(),
			Some(FormatError::TooLarge)
		);
		assert_eq!((db.revision(), db.modified_ts()), before);
		db.write().entries.entries.remove(&(id + 1));
		assert!(db.encode(false, KdfParams::DEBUG).is_ok());
		// Exactly at the boundary before bookkeeping on a database never saved:
		// the first save adds revision and cost entries, which push it over,
		// so the save is refused and the bookkeeping left absent.
		let fresh = Database::new(
			HeapKey::from_bytes(&[4; KEY_SIZE]).unwrap(),
			"edge",
			&[2; 32],
		);
		let mut entry = Entry::new();
		entry.set_name("x");
		fresh.set_password_entry(entry);
		let (fid, (ftag, fsealed)) = {
			let store = fresh.read();
			let (id, (tag, sealed)) = store.entries.entries.iter().next_back().unwrap();
			(*id, (*tag, sealed.clone()))
		};
		let room = format::MAX_DATABASE_BYTES - fresh.read().entries.serialized_len();
		let boundary = ProtectedBytes {
			ciphertext: vec![0; room - 5 + 16],
			nonce: fsealed.nonce,
			key: Arc::clone(&fsealed.key),
		};
		fresh
			.write()
			.entries
			.entries
			.insert(fid + 1, (ftag, boundary));
		assert_eq!(
			fresh.read().entries.serialized_len(),
			format::MAX_DATABASE_BYTES
		);
		let before = (fresh.revision(), fresh.modified_ts(), fresh.meta("kdf_m"));
		assert_eq!(
			fresh.encode(false, KdfParams::DEBUG).err(),
			Some(FormatError::TooLarge)
		);
		assert_eq!(
			(fresh.revision(), fresh.modified_ts(), fresh.meta("kdf_m")),
			before
		);
		assert_eq!(before.0, None, "revision stays absent");
		// One record over the field budget is refused even when the database
		// as a whole is within its budget: the reader would refuse it.
		let one_field = ProtectedBytes {
			ciphertext: vec![0; format::MAX_FIELD_BYTES + 1 + 16],
			nonce: sealed.nonce,
			key: Arc::clone(&sealed.key),
		};
		db.write().entries.entries.insert(id + 1, (tag, one_field));
		assert_eq!(
			db.encode(false, KdfParams::DEBUG).err(),
			Some(FormatError::TooLarge)
		);
		db.write().entries.entries.remove(&(id + 1));
	}

	#[test]
	fn the_open_key_is_recognized_and_any_other_is_not() {
		let salt = [1u8; crypto::SALT_SIZE];
		let db = Database::new(test_key(&salt, KdfParams::DEBUG), "example", &salt);
		let mut key = [0u8; KEY_SIZE];
		test_key(&salt, KdfParams::DEBUG).with_key(|bytes| key = *bytes);
		assert!(db.is_master_key(&key));
		for index in [0, KEY_SIZE - 1] {
			let mut other = key;
			other[index] ^= 1;
			assert!(!db.is_master_key(&other));
		}
		// After a rekey only the new key is the open one.
		let new_salt = [2u8; crypto::SALT_SIZE];
		db.rekey(test_key(&new_salt, KdfParams::DEBUG), &new_salt);
		assert!(!db.is_master_key(&key));
	}

	#[test]
	fn a_rekeyed_database_opens_only_under_the_new_key_and_names_the_new_salt() {
		let old_salt = [1u8; crypto::SALT_SIZE];
		let new_salt = [2u8; crypto::SALT_SIZE];
		let db = Database::new(test_key(&old_salt, KdfParams::DEBUG), "example", &old_salt);
		let mut entry = Entry::new();
		entry.set_name("kept");
		entry.set_password("through the rekey");
		db.set_password_entry(entry);
		assert_eq!(db.salt(), Some(old_salt));
		let before = db.encode(false, KdfParams::DEBUG).unwrap();
		db.rekey(test_key(&new_salt, KdfParams::DEBUG), &new_salt);
		assert_eq!(db.salt(), Some(new_salt));
		let after = db.encode(false, KdfParams::DEBUG).unwrap();
		let parse = |file: &[u8]| Envelope::parse(file, KdfParams::DEBUG).unwrap();
		assert_eq!(parse(&before).salt, old_salt);
		assert_eq!(parse(&after).salt, new_salt);
		assert!(parse(&after).revision > parse(&before).revision);
		assert!(Database::open(&parse(&after), test_key(&old_salt, KdfParams::DEBUG)).is_err());
		let reopened = Database::open(&parse(&after), test_key(&new_salt, KdfParams::DEBUG))
			.map_err(|(_, e)| e)
			.unwrap();
		assert_eq!(
			reopened
				.get_password_entry_by_name("kept")
				.unwrap()
				.get_password()
				.as_str(),
			"through the rekey"
		);
		// The old file still opens under the old key: a copy from before the
		// rekey is a copy, not a corruption.
		assert!(Database::open(&parse(&before), test_key(&old_salt, KdfParams::DEBUG)).is_ok());
	}

	/// A deterministic test key from the salt and cost, as a head's
	/// derivation would make one.
	fn test_key(salt: &[u8; 32], cost: KdfParams) -> HeapKey {
		let mut bytes = [0u8; KEY_SIZE];
		bytes.copy_from_slice(
			blake3::hash(&[salt.as_slice(), &cost.m_cost.to_le_bytes()].concat()).as_bytes(),
		);
		HeapKey::from_bytes(&bytes).unwrap()
	}

	/// A vault whose envelope carries key slots, as a head with security keys
	/// would save it: the slots are meta entries, the key takes the roaming
	/// secret.
	fn slotted_vault(roaming: &[u8; 32], hmac_secrets: &[[u8; 32]]) -> (Vec<u8>, HeapKey) {
		use crate::roaming::{KeySlot, UvMode};
		let salt = [5u8; crypto::SALT_SIZE];
		let key = test_roaming_key(&salt, roaming);
		let db = Database::new(key, "example", &salt);
		for (index, secret) in hmac_secrets.iter().enumerate() {
			let slot = KeySlot::wrap(
				UvMode::Verified,
				&[index as u8 + 1; 16],
				[index as u8; 32],
				secret,
				roaming,
			)
			.unwrap();
			db.set_meta_entry(MetaEntry::new(&KeySlot::entry_name(index), &slot.encode()));
		}
		let file = db.encode(false, KdfParams::DEBUG).unwrap();
		(file, test_roaming_key(&salt, roaming))
	}

	fn test_roaming_key(salt: &[u8; 32], roaming: &[u8; 32]) -> HeapKey {
		let mut bytes = [0u8; KEY_SIZE];
		bytes.copy_from_slice(blake3::hash(&[salt.as_slice(), roaming].concat()).as_bytes());
		HeapKey::from_bytes(&bytes).unwrap()
	}

	#[test]
	fn unlock_hands_the_slots_to_the_head_and_reuses_a_key_only_in_the_same_context() {
		let roaming = [0x33u8; 32];
		let secret_a = [0xA1u8; 32];
		let secret_b = [0xB2u8; 32];
		let (one_slot, _) = slotted_vault(&roaming, &[secret_a]);
		let (two_slots, _) = slotted_vault(&roaming, &[secret_a, secret_b]);
		let parse = |file: &[u8]| Envelope::parse(file, KdfParams::DEBUG).unwrap();
		assert_eq!(parse(&one_slot).slots.len(), 1);
		assert_eq!(parse(&two_slots).slots.len(), 2);

		// A head that holds key B: it opens only the copy that has B's slot.
		let seen = std::cell::RefCell::new(Vec::new());
		let mut with_b = |candidate: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			seen.borrow_mut()
				.push((candidate.source, candidate.slots.len()));
			match candidate
				.slots
				.iter()
				.find_map(|slot| slot.unwrap(&secret_b))
			{
				Some(r) => Derived::Key(test_roaming_key(candidate.salt, &r)),
				None => Derived::Unavailable,
			}
		};
		// Local (one slot) is preferred by timestamp order? Both were made in
		// the same second; local wins a tie. It has no slot for B, so the
		// remote copy opens and uploads are paused.
		let opened = unlock(
			"example",
			Some(parse(&one_slot)),
			Some(parse(&two_slots)),
			KdfParams::DEBUG,
			&mut with_b,
		)
		.unwrap();
		assert_eq!(opened.source, Source::Remote);
		assert_eq!(
			opened.caution,
			Some(Caution::OtherCopyFailed(Source::Local))
		);
		assert_eq!(
			*seen.borrow(),
			vec![(Source::Local, 1), (Source::Remote, 2)]
		);
		opened.database.zeroize();

		// Alone, the copy without B's slot is unavailable, not a decryption error.
		assert_eq!(
			unlock(
				"example",
				Some(parse(&one_slot)),
				None,
				KdfParams::DEBUG,
				&mut with_b
			)
			.err(),
			Some(UnlockError::Unavailable)
		);

		// A wrong roaming secret opens neither copy; the key made for the
		// first copy is not reused on the second because their slots differ.
		let derivations = std::cell::Cell::new(0);
		let mut wrong = |candidate: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			derivations.set(derivations.get() + 1);
			Derived::Key(test_roaming_key(candidate.salt, &[0x34u8; 32]))
		};
		assert_eq!(
			unlock(
				"example",
				Some(parse(&one_slot)),
				Some(parse(&two_slots)),
				KdfParams::DEBUG,
				&mut wrong
			)
			.err(),
			Some(UnlockError::Open(OpenError::Decryption))
		);
		assert_eq!(derivations.get(), 2, "different slots, no reuse");
		derivations.set(0);
		assert_eq!(
			unlock(
				"example",
				Some(parse(&two_slots)),
				Some(parse(&two_slots)),
				KdfParams::DEBUG,
				&mut wrong
			)
			.err(),
			Some(UnlockError::Open(OpenError::Decryption))
		);
		assert_eq!(derivations.get(), 1, "same slots, the key is reused");

		// Cancellation ends the unlock even with a second copy present.
		let asked = std::cell::Cell::new(0);
		let mut cancel = |_: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			asked.set(asked.get() + 1);
			Derived::Canceled
		};
		assert_eq!(
			unlock(
				"example",
				Some(parse(&one_slot)),
				Some(parse(&two_slots)),
				KdfParams::DEBUG,
				&mut cancel
			)
			.err(),
			Some(UnlockError::Canceled)
		);
		assert_eq!(asked.get(), 1);

		// Stripping the slots leaves a file the password alone cannot open.
		let stripped = {
			let envelope = parse(&two_slots);
			let db = Database::open(&envelope, test_roaming_key(&envelope.salt, &roaming))
				.map_err(|(_, e)| e)
				.unwrap();
			db.remove_meta_entry("fido_slot_1");
			db.remove_meta_entry("fido_slot_2");
			db.encode(false, KdfParams::DEBUG).unwrap()
		};
		let envelope = parse(&stripped);
		assert!(envelope.slots.is_empty());
		let mut plain = |candidate: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			Derived::Key(test_key(candidate.salt, candidate.cost))
		};
		assert_eq!(
			unlock(
				"example",
				Some(envelope),
				None,
				KdfParams::DEBUG,
				&mut plain
			)
			.err(),
			Some(UnlockError::Open(OpenError::Decryption))
		);
	}

	#[test]
	fn a_new_vault_records_the_creation_cost_and_saves_keep_any_recorded_cost() {
		let derived = std::cell::Cell::new(None);
		let mut derive = |candidate: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			derived.set(Some(candidate.cost));
			Derived::Key(test_key(candidate.salt, candidate.cost))
		};
		let created = unlock("example", None, None, KdfParams::CREATE, &mut derive).unwrap();
		assert_eq!(
			derived.get(),
			Some(KdfParams::CREATE),
			"derived at the creation cost"
		);
		let db = created.database;
		let file = db.encode(true, KdfParams::CREATE).unwrap();
		let envelope = Envelope::parse(&file, KdfParams::RELEASE).unwrap();
		assert_eq!(envelope.kdf, KdfParams::CREATE);
		assert_eq!(
			[db.meta("kdf_m"), db.meta("kdf_t"), db.meta("kdf_p")],
			[Some("262144".into()), Some("3".into()), Some("1".into())]
		);
		// A later save on a release build passes the legacy fallback; the
		// recorded cost wins.
		let saved = db.encode(true, KdfParams::RELEASE).unwrap();
		assert_eq!(
			Envelope::parse(&saved, KdfParams::RELEASE).unwrap().kdf,
			KdfParams::CREATE
		);
		// A vault already recording 4 GiB keeps it.
		let key = HeapKey::from_bytes(&[42; KEY_SIZE]).unwrap();
		let old = Database::new(key, "old", &[7; crypto::SALT_SIZE]);
		old.encode(false, KdfParams::RELEASE).unwrap();
		let resaved = old.encode(false, KdfParams::CREATE).unwrap();
		assert_eq!(
			Envelope::parse(&resaved, KdfParams::CREATE).unwrap().kdf,
			KdfParams::RELEASE
		);
	}

	#[test]
	fn unlock_orders_the_copies_falls_back_and_derives_once() {
		let derivations = std::cell::Cell::new(0);
		let mut counted = |candidate: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			derivations.set(derivations.get() + 1);
			Derived::Key(test_key(candidate.salt, candidate.cost))
		};
		let created = unlock("example", None, None, KdfParams::DEBUG, &mut counted).unwrap();
		assert_eq!((created.source, created.caution), (Source::New, None));
		assert_eq!(created.database.meta("db_name").as_deref(), Some("example"));
		let mut entry = Entry::new();
		entry.set_name("first");
		created.database.set_password_entry(entry);
		let older = created.database.encode(false, KdfParams::DEBUG).unwrap();
		let mut entry = Entry::new();
		entry.set_name("second");
		created.database.set_password_entry(entry);
		let newer = created.database.encode(false, KdfParams::DEBUG).unwrap();
		let parse = |file: &[u8]| Envelope::parse(file, KdfParams::DEBUG).unwrap();
		derivations.set(0);
		let opened = unlock(
			"example",
			Some(parse(&older)),
			Some(parse(&newer)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!((opened.source, opened.caution), (Source::Remote, None));
		assert_eq!(opened.database.names().len(), 2);
		assert_eq!(opened.cost, KdfParams::DEBUG);
		assert_eq!(derivations.get(), 1);
		let opened = unlock(
			"example",
			Some(parse(&newer)),
			Some(parse(&older)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(opened.source, Source::Local);
		let opened = unlock(
			"example",
			Some(parse(&older)),
			Some(parse(&older)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(opened.source, Source::Local, "local wins a tie");
		let opened = unlock(
			"example",
			None,
			Some(parse(&older)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(opened.source, Source::Remote);

		// The preferred copy fails its mirror check; the other opens under
		// the same key, derived once.
		let damaged = file_as_is(&opened.database, Some("9"));
		derivations.set(0);
		let recovered = unlock(
			"example",
			Some(parse(&older)),
			Some(parse(&damaged)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(recovered.source, Source::Local);
		assert_eq!(
			recovered.caution,
			Some(Caution::OtherCopyFailed(Source::Remote))
		);
		assert_eq!(derivations.get(), 1);
		assert_eq!(
			unlock(
				"example",
				None,
				Some(parse(&damaged)),
				KdfParams::DEBUG,
				&mut counted
			)
			.err(),
			Some(UnlockError::Open(OpenError::Decryption))
		);
		let wrong = |_: &Candidate<'_>| -> Derived<HeapKey, Infallible> {
			Derived::Key(HeapKey::from_bytes(&[1; KEY_SIZE]).unwrap())
		};
		assert_eq!(
			unlock(
				"example",
				Some(parse(&older)),
				None,
				KdfParams::DEBUG,
				wrong
			)
			.err(),
			Some(UnlockError::Open(OpenError::Decryption))
		);
		let failing =
			|_: &Candidate<'_>| -> Derived<HeapKey, &'static str> { Derived::Failed("no memory") };
		assert_eq!(
			unlock(
				"example",
				Some(parse(&older)),
				None,
				KdfParams::DEBUG,
				failing
			)
			.err(),
			Some(UnlockError::Derive("no memory"))
		);

		// A copy from another vault of the same name.
		let other = unlock("example", None, None, KdfParams::DEBUG, &mut counted).unwrap();
		let foreign = other.database.encode(false, KdfParams::DEBUG).unwrap();
		assert_eq!(
			unlock(
				"example",
				Some(parse(&older)),
				Some(parse(&foreign)),
				KdfParams::DEBUG,
				&mut counted
			)
			.err(),
			Some(UnlockError::DifferentVault)
		);

		// A legacy local copy, newer by timestamp, over a versioned remote.
		let db = &opened.database;
		db.set_meta_entry(MetaEntry::new("revision", "5"));
		db.set_meta_entry(MetaEntry::new("modified_ts", "100"));
		let versioned = file_as_is(db, None);
		db.remove_meta_entry("revision");
		db.set_meta_entry(MetaEntry::new("modified_ts", "200"));
		let legacy = file_as_is(db, None);
		let legacy_envelope = parse(&legacy);
		assert_eq!(legacy_envelope.revision, None);
		let rollout = unlock(
			"example",
			Some(legacy_envelope),
			Some(parse(&versioned)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(rollout.source, Source::Local);
		assert_eq!(
			rollout.caution,
			Some(Caution::LegacyLocalOverVersionedRemote)
		);
		let settled = unlock(
			"example",
			Some(parse(&versioned)),
			Some(parse(&legacy)),
			KdfParams::DEBUG,
			&mut counted,
		)
		.unwrap();
		assert_eq!(
			(settled.source, settled.caution),
			(Source::Remote, None),
			"a legacy remote never pauses uploads"
		);
	}
}
