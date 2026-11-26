use crate::{
	logger::{error, info, warn},
	storage::{
		atlas::{FieldAtlas, next_tlv},
		database::{Database, EntryTag, InteriorDatabase},
		entry::{MetaEntry, MetaField},
		remote::Remote,
		secret::SecretMemory,
	},
};
use std::{
	collections::HashMap,
	env, fs,
	io::Write,
	mem,
	os::unix::fs::{DirBuilderExt, OpenOptionsExt},
	path::{Path, PathBuf},
	process::Command,
	time::SystemTime,
};
use zeroize::{Zeroize, Zeroizing};

const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 32;
const PEPPER_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

/// Newest envelope format this build reads. Format 1 is the original file:
/// plaintext metadata beside the ciphertext, nothing binding the two. Format
/// 2 authenticates the metadata as associated data and carries a revision.
const CURRENT_FORMAT: u32 = 2;
/// Whether a vault that is still format 1 is rewritten as format 2 on save.
/// Off until the Android reader understands format 2, so both platforms keep
/// opening each other's files; a vault that is already format 2 is never
/// written back as format 1.
const WRITE_FORMAT_2: bool = false;
const AAD_PREFIX: &[u8] = b"keptino-envelope-v2";

fn revision_path(db_name: &str) -> PathBuf {
	base_path().join(format!("{db_name}.revision"))
}

fn revision_temp_path(db_name: &str) -> PathBuf {
	base_path().join(format!(".{db_name}.revision"))
}

/// The highest revision of this database opened or saved on this machine,
/// kept outside the synced object so a replayed older copy is noticed.
fn last_seen_revision(db_name: &str) -> Option<u64> {
	fs::read_to_string(revision_path(db_name))
		.ok()?
		.trim()
		.parse()
		.ok()
}

fn remember_revision(db_name: &str, revision: u64) {
	if last_seen_revision(db_name).is_none_or(|seen| revision > seen)
		&& let Err(err) = write_atomic(
			&revision_temp_path(db_name),
			&revision_path(db_name),
			revision.to_string().as_bytes(),
		)
	{
		error(&format!("Cannot record the vault revision: {err}"));
	}
}

/// Refuses a copy older than one already opened here, unless the user has
/// removed the record to accept it deliberately.
fn check_revision(opened: Option<u64>, last_seen: Option<u64>, db_name: &str) -> Result<(), String> {
	match (opened, last_seen) {
		(Some(opened), Some(seen)) if opened < seen => Err(format!(
			"This copy is revision {opened}, but revision {seen} was already opened here. \
			 To accept the older copy, remove ~/.config/keptino/{db_name}.revision and unlock again."
		)),
		_ => Ok(()),
	}
}

/// Associated data of a format-2 envelope: every plaintext meta entry except
/// the ciphertext itself, length-prefixed and sorted by name. A reader needs
/// no field list, and a changed, added or dropped field fails authentication.
fn envelope_aad(meta: &[(String, String)]) -> Vec<u8> {
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

fn current_revision(db: &Database) -> Option<u64> {
	db.get_meta_entry("revision")?.get_value().parse().ok()
}

fn base_path() -> PathBuf {
	let mut apath = env::home_dir().unwrap_or_default();
	apath.push(".config/keptino/");
	// Private to the user from the first run, before setup.sh has chmod'ed it.
	fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(&apath)
		.ok();
	apath
}

fn db_path(db_name: &str) -> PathBuf {
	let mut apath = base_path();
	apath.push(format!("{}.keptino", db_name));
	apath
}

fn temp_path(db_name: &str) -> PathBuf {
	let mut apath = base_path();
	apath.push(format!(".{}.keptino", db_name));
	apath
}

fn pepper_path() -> String {
	let mut apath = base_path();
	apath.push("pepper.cred");
	apath.to_str().unwrap().to_string()
}

#[derive(Clone)]
pub struct OpenedVault {
	pub database: Database,
	remote: Result<Remote, String>,
}

impl OpenedVault {
	pub fn status(&self) -> String {
		match &self.remote {
			Ok(_) => "Unlocked".into(),
			Err(err) => format!("{err} Uploads paused until next unlock."),
		}
	}

	pub fn save(&self) -> impl Future<Output = String> + use<> {
		let db = &self.database;
		let db_name = db.get_meta_entry("db_name").unwrap().get_value().to_owned();
		// The revision this session holds, before the save advances it.
		let held = current_revision(db);
		// Snapshot the encrypted vault before the UI can lock and clear its keys.
		let bytes = db_to_vec(db, WRITE_FORMAT_2);
		let saved = current_revision(db);
		let remote = self.remote.clone();
		async move {
			if to_file(&bytes, &db_name).is_err() {
				return "Local save failed. Check disk space and file permissions.".into();
			}
			if let Some(revision) = saved {
				remember_revision(&db_name, revision);
			}
			let result = match remote {
				Ok(provider) => match remote_revision(&provider, &db_name).await {
					// The remote field is plaintext, so a forged value can only
					// stop an upload, never cause one.
					Ok(Some(theirs)) if held.is_none_or(|ours| theirs > ours) => Err(format!(
						"The remote vault has newer changes (revision {theirs}). Saved locally only; unlock again to load them before uploading."
					)),
					Ok(_) => provider.upload(&base_path(), &db_name, &bytes).await,
					Err(err) => Err(err),
				},
				Err(_) => Err("Unlock again to reconnect storage.".into()),
			};
			match result {
				Ok(()) => {
					info("Database saved and synced.");
					"Database saved and synced.".into()
				}
				Err(err) => {
					let msg = format!("Saved locally only. {err}");
					error(&msg);
					msg
				}
			}
		}
	}

	#[cfg(test)]
	pub fn for_test(database: Database) -> Self {
		Self {
			database,
			remote: Err("Test session".into()),
		}
	}
}

pub async fn load(
	db_name: &str,
	master_password: Zeroizing<String>,
) -> Result<OpenedVault, String> {
	if db_name.contains(['/', '\0']) {
		return Err("Use a database name without path separators or NUL bytes.".into());
	}
	let dir = base_path();
	let local = match fs::read(db_path(db_name)) {
		Ok(bytes) => Some(Envelope::decode(&bytes).map_err(|err| format!("Local vault: {err}"))?),
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
		Err(_) => return Err("Cannot read local vault.".into()),
	};
	let download = async {
		let (remote, bytes) = Remote::download(&dir, db_name).await?;
		let envelope = bytes
			.as_deref()
			.map(|b| Envelope::decode(b).map_err(|err| format!("Remote vault: {err}")))
			.transpose()?;
		Ok::<_, String>((remote, envelope))
	}
	.await;
	let (mut provider, remote) = match download {
		Ok((provider, envelope)) => (Ok(provider), envelope),
		Err(err) if local.is_some() => (Err(format!("Opened local copy. {err}")), None),
		Err(err) => return Err(err),
	};
	let local = local.map(|envelope| Candidate {
		envelope,
		source: "local",
	});
	let remote = remote.map(|envelope| Candidate {
		envelope,
		source: "remote",
	});
	let database = match (local, remote) {
		(None, None) => new_db(db_name, master_password),
		(Some(only), None) | (None, Some(only)) => open_candidates(only, None, master_password)?.0,
		(Some(local), Some(remote)) => {
			if local.envelope.salt != remote.envelope.salt {
				return Err(
					"A different vault already uses this name in the selected bucket.".into(),
				);
			}
			let (first, second) = if prefer_local(&local.envelope, &remote.envelope) {
				(local, remote)
			} else {
				(remote, local)
			};
			let (database, rejected) = open_candidates(first, Some(second), master_password)?;
			if let Some(rejected) = rejected {
				provider = Err(rejected);
			}
			database
		}
	};
	let opened = current_revision(&database);
	if let Err(err) = check_revision(opened, last_seen_revision(db_name), db_name) {
		database.zeroize();
		return Err(err);
	}
	if let Some(revision) = opened {
		remember_revision(db_name, revision);
	}
	// Imported files may have been renamed. Keep subsequent saves at the
	// validated name the user opened, including for Android exports.
	database.set_meta_entry(MetaEntry::new("db_name", db_name));
	Ok(OpenedVault {
		database,
		remote: provider,
	})
}

struct Candidate {
	envelope: Envelope,
	source: &'static str,
}

/// Which of two copies to try first: the higher revision when both carry
/// one, else the later modification time, local winning a tie. Both fields
/// are plaintext, so the loser is tried when the winner fails to open.
fn prefer_local(local: &Envelope, remote: &Envelope) -> bool {
	match (local.revision, remote.revision) {
		(Some(ours), Some(theirs)) if ours != theirs => ours > theirs,
		_ => local.modified >= remote.modified,
	}
}

/// Derives the key once (both candidates share a salt) and opens the first
/// copy that authenticates. A copy that fails while the other opens is
/// reported, and the caller pauses uploads so it is not overwritten blindly.
fn open_candidates(
	first: Candidate,
	second: Option<Candidate>,
	password: Zeroizing<String>,
) -> Result<(Database, Option<String>), String> {
	let key = master_key_derivation(password, first.envelope.salt);
	if let Some(idb) = first.envelope.unlock(&key) {
		info(&format!("{} database loaded.", first.source));
		return Ok((Database::old(key, idb), None));
	}
	if let Some(second) = second
		&& let Some(idb) = second.envelope.unlock(&key)
	{
		let rejected = format!(
			"The {} copy failed authentication and may be corrupt or tampered with; opened the {} copy.",
			first.source, second.source
		);
		warn(&rejected);
		return Ok((Database::old(key, idb), Some(rejected)));
	}
	key.zeroize().ok();
	Err("Cannot decrypt vault. Check the master password and pepper.".into())
}

/// The revision the remote object carries right now, if it is format 2.
async fn remote_revision(provider: &Remote, db_name: &str) -> Result<Option<u64>, String> {
	match provider.fetch(&base_path(), db_name).await? {
		Some(bytes) => Ok(Envelope::decode(&bytes)
			.map_err(|err| format!("Remote vault: {err}"))?
			.revision),
		None => Ok(None),
	}
}

fn new_db(db_name: &str, master_password: Zeroizing<String>) -> Database {
	let created_ts = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		.to_string();
	let mut salt = [0u8; SALT_SIZE];
	getrandom::fill(&mut salt).unwrap();
	let master_key = master_key_derivation(master_password, salt);
	let db = Database::new(master_key);
	db.set_meta_entry(MetaEntry::new("db_name", db_name));
	db.set_meta_entry(MetaEntry::new("nonce", "0"));
	db.set_meta_entry(MetaEntry::new("salt", &to_base64(&salt)));
	db.set_meta_entry(MetaEntry::new("created_ts", &created_ts));
	db.set_meta_entry(MetaEntry::new("modified_ts", &created_ts));
	db
}

/// The plaintext layer of a vault file. `aad` is empty for format 1 and the
/// canonical metadata for format 2, so `unlock` needs no format branch.
struct Envelope {
	modified: u64,
	revision: Option<u64>,
	nonce: [u8; NONCE_SIZE],
	salt: [u8; SALT_SIZE],
	ciphertext: Vec<u8>,
	aad: Vec<u8>,
}

impl Envelope {
	fn decode(bytes: &[u8]) -> Result<Self, String> {
		Self::parse(bytes).ok_or_else(|| "the file is damaged beyond repair.".to_string())?
	}

	/// `None` for a file that cannot be read at all; `Some(Err)` for one that
	/// is intact but from a newer Keptino.
	fn parse(bytes: &[u8]) -> Option<Result<Self, String>> {
		use base64ct::{Base64, Encoding};
		let recovered = decode_erasure(bytes)?;
		let mut entries = recovered.as_slice();
		let mut pairs = Vec::new();
		let mut metadata = HashMap::new();
		while !entries.is_empty() {
			let (tag, fields) = next_tlv(&mut entries)?;
			if tag != EntryTag::Meta as u8 {
				return None;
			}
			let record = FieldAtlas::try_deserialize(fields)?;
			let name = record.get_str(MetaField::Name as u8)?.to_owned();
			let value = record.get_str(MetaField::Value as u8)?.to_owned();
			pairs.push((name.clone(), value.clone()));
			metadata.insert(name, value);
		}
		let format: u32 = match metadata.get("format") {
			Some(format) => format.parse().ok()?,
			None => 1,
		};
		if format > CURRENT_FORMAT {
			return Some(Err(format!(
				"the file was written by a newer Keptino (format {format}). Update Keptino to open it."
			)));
		}
		let (revision, aad) = if format >= 2 {
			(Some(metadata.get("revision")?.parse().ok()?), envelope_aad(&pairs))
		} else {
			(None, Vec::new())
		};
		let mut nonce = [0; NONCE_SIZE];
		nonce[..16].copy_from_slice(&metadata.get("nonce")?.parse::<u128>().ok()?.to_le_bytes());
		Some(Ok(Self {
			modified: metadata.get("modified_ts")?.parse().ok()?,
			revision,
			salt: Base64::decode_vec(metadata.get("salt")?)
				.ok()?
				.try_into()
				.ok()?,
			nonce,
			ciphertext: Base64::decode_vec(metadata.get("db")?).ok()?,
			aad,
		}))
	}

	fn unlock(&self, key: &SecretMemory) -> Option<InteriorDatabase> {
		let compressed = decrypt(self.ciphertext.clone(), key, self.nonce, &self.aad)?;
		Some(InteriorDatabase::deserialize(&decompress(compressed)))
	}
}

/// Encrypts the database into the bytes of a vault file. A format-2 vault is
/// always written as format 2; a format-1 vault is upgraded when `upgrade`
/// is set.
fn db_to_vec(db: &Database, upgrade: bool) -> Vec<u8> {
	let modified_ts = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		.to_string();
	db.set_meta_entry(MetaEntry::new("modified_ts", &modified_ts));
	// Local copies can be saved independently while a provider is unavailable.
	// Keep the existing decimal u128 field while giving each save a fresh nonce.
	let mut nonce = [0u8; NONCE_SIZE];
	getrandom::fill(&mut nonce[..16]).unwrap();
	let stored_nonce = u128::from_le_bytes(nonce[..16].try_into().unwrap());
	db.set_meta_entry(MetaEntry::new("nonce", &stored_nonce.to_string()));
	let format_2 = upgrade || db.get_meta_entry("format").is_some();
	if format_2 {
		let revision = current_revision(db).unwrap_or(0) + 1;
		db.set_meta_entry(MetaEntry::new("format", &CURRENT_FORMAT.to_string()));
		db.set_meta_entry(MetaEntry::new("revision", &revision.to_string()));
	}
	let db_core = db.serialize();
	let db_core_compressed = compress(&db_core);
	// The envelope mirrors every meta entry, so the inner copy is what the
	// associated data authenticates against after decryption as well.
	let db_envelope = db.meta_only();
	let aad = if format_2 {
		envelope_aad(&db_envelope.meta_pairs())
	} else {
		Vec::new()
	};
	let db_core_encrypted = encrypt(
		&db_core_compressed,
		&db.clone_master_key().read().unwrap(),
		nonce,
		&aad,
	);
	db_envelope.set_meta_entry(MetaEntry::new("db", &to_base64(&db_core_encrypted)));
	let db_bin = db_envelope.serialize();
	encode_erasure(&db_bin)
}

fn load_pepper() -> [u8; PEPPER_SIZE] {
	let pepper_output = Command::new("systemd-creds")
		.args(["decrypt", "--user", "--name=pepper", &pepper_path()])
		.output()
		.unwrap();
	let pepper_hex = Zeroizing::new(pepper_output.stdout);
	let mut pepper = [0u8; PEPPER_SIZE];
	hex::decode_to_slice(
		std::str::from_utf8(&pepper_hex).unwrap().trim(),
		&mut pepper,
	)
	.unwrap();
	pepper
}

fn master_key_derivation(password: Zeroizing<String>, salt: [u8; SALT_SIZE]) -> SecretMemory {
	use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
	use sha3::{Digest, Sha3_256};
	let pepper = load_pepper();
	let mut pre_hasher = Sha3_256::new();
	pre_hasher.update(salt);
	pre_hasher.update(pepper);
	pre_hasher.update(password.as_bytes());
	let mut pre_hash = pre_hasher.finalize();
	let m_cost = if cfg!(debug_assertions) {
		2u32.pow(12)
	} else {
		2u32.pow(22)
	};
	let main_params = ParamsBuilder::new()
		.m_cost(m_cost)
		.t_cost(1)
		.p_cost(1)
		.output_len(KEY_SIZE)
		.build()
		.unwrap();
	let main_hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, main_params);
	let mut main_hash = [0u8; KEY_SIZE];
	let mut derivation_salt = Zeroizing::new([0u8; SALT_SIZE + PEPPER_SIZE]);
	derivation_salt[..SALT_SIZE].copy_from_slice(&salt);
	derivation_salt[SALT_SIZE..].copy_from_slice(&pepper);
	main_hasher
		.hash_password_into(&pre_hash, &*derivation_salt, &mut main_hash)
		.unwrap();
	let mut post_hasher = Sha3_256::new();
	post_hasher.update(main_hash);
	post_hasher.update(pepper);
	post_hasher.update(salt);
	let mut post_hash: [u8; KEY_SIZE] = post_hasher.finalize().into();
	let mut pepper = pepper;
	pepper.zeroize();
	pre_hash.zeroize();
	main_hash.zeroize();
	let master_key = SecretMemory::new_pages(1).unwrap();
	master_key.write(0, &post_hash).unwrap();
	post_hash.zeroize();
	master_key
}

fn to_base64(msg: &[u8]) -> String {
	use base64ct::{Base64, Encoding};
	Base64::encode_string(msg)
}

// Grow by copying into a new wiping allocation, so a realloc never abandons
// plaintext in the allocator's old buffer.
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

fn compress(msg: &[u8]) -> Zeroizing<Vec<u8>> {
	let mut encoder = lz4::EncoderBuilder::new()
		.level(9)
		.build(WipingWriter::default())
		.unwrap();
	encoder.write_all(msg).unwrap();
	let (writer, result) = encoder.finish();
	result.unwrap();
	writer.0
}

fn decompress(msg_enc: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
	let mut writer = WipingWriter::default();
	let mut decoder = lz4::Decoder::new(&msg_enc[..]).unwrap();
	// std::io::copy's ordinary scratch buffer would retain plaintext.
	let mut scratch = Zeroizing::new([0u8; 8192]);
	loop {
		let size = std::io::Read::read(&mut decoder, &mut *scratch).unwrap();
		if size == 0 {
			break;
		}
		writer.write_all(&scratch[..size]).unwrap();
	}
	writer.0
}

fn encrypt(msg: &[u8], key: &SecretMemory, nonce: [u8; NONCE_SIZE], aad: &[u8]) -> Vec<u8> {
	use chacha20poly1305::{
		XChaCha20Poly1305,
		aead::{AeadInPlace, KeyInit},
	};
	let mapped = key.read().unwrap();
	let cipher = XChaCha20Poly1305::new_from_slice(&mapped).unwrap();
	drop(mapped);
	let mut buffer = Zeroizing::new(Vec::with_capacity(msg.len() + 16));
	buffer.extend_from_slice(msg);
	cipher
		.encrypt_in_place((&nonce).into(), aad, &mut *buffer)
		.unwrap();
	mem::take(&mut *buffer)
}

fn decrypt(
	msg_enc: Vec<u8>,
	key: &SecretMemory,
	nonce: [u8; NONCE_SIZE],
	aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
	use chacha20poly1305::{
		XChaCha20Poly1305,
		aead::{AeadInPlace, KeyInit},
	};
	let mapped = key.read().unwrap();
	let cipher = XChaCha20Poly1305::new_from_slice(&mapped).unwrap();
	drop(mapped);
	let mut buffer = Zeroizing::new(msg_enc);
	cipher
		.decrypt_in_place((&nonce).into(), aad, &mut *buffer)
		.ok()?;
	Some(buffer)
}

const ERASURE_DATA_SHARDS: usize = 8;
const ERASURE_PARITY_SHARDS: usize = 4;
const ERASURE_TOTAL_SHARDS: usize = ERASURE_DATA_SHARDS + ERASURE_PARITY_SHARDS;
const ERASURE_MIN_SHARD_SIZE: usize = 4096;

fn encode_erasure(data: &[u8]) -> Vec<u8> {
	use reed_solomon_erasure::galois_8::ReedSolomon;
	let original_len = data.len() as u64;
	let shard_size = std::cmp::max(
		data.len().div_ceil(ERASURE_DATA_SHARDS),
		ERASURE_MIN_SHARD_SIZE,
	);
	let mut padded = data.to_vec();
	padded.resize(shard_size * ERASURE_DATA_SHARDS, 0);
	let mut shards: Vec<Vec<u8>> = padded
		.chunks_exact(shard_size)
		.map(|chunk| chunk.to_vec())
		.collect();
	for _ in 0..ERASURE_PARITY_SHARDS {
		shards.push(vec![0; shard_size]);
	}
	let rs = ReedSolomon::new(ERASURE_DATA_SHARDS, ERASURE_PARITY_SHARDS).unwrap();
	rs.encode(&mut shards).unwrap();
	let mut output = Vec::new();
	for shard in shards {
		let hash = blake3::hash(&shard);
		output.extend_from_slice(&original_len.to_le_bytes());
		output.extend_from_slice(hash.as_bytes());
		output.extend_from_slice(&shard);
	}
	output
}

fn decode_erasure(encoded: &[u8]) -> Option<Vec<u8>> {
	use reed_solomon_erasure::galois_8::ReedSolomon;
	let chunk_size = encoded.len() / ERASURE_TOTAL_SHARDS;
	if chunk_size < 40 + ERASURE_MIN_SHARD_SIZE
		|| !encoded.len().is_multiple_of(ERASURE_TOTAL_SHARDS)
	{
		return None;
	}
	let mut original_len = None;
	let mut shards: Vec<Option<Vec<u8>>> = Vec::new();
	for chunk in encoded.chunks_exact(chunk_size) {
		let len = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
		let hash = &chunk[8..40];
		let data = &chunk[40..];
		if blake3::hash(data).as_bytes() == hash {
			original_len.get_or_insert(len);
			shards.push(Some(data.to_vec()));
		} else {
			shards.push(None);
		}
	}
	let rs = ReedSolomon::new(ERASURE_DATA_SHARDS, ERASURE_PARITY_SHARDS).unwrap();
	rs.reconstruct_data(&mut shards).ok()?;
	let mut recovered: Vec<u8> = shards
		.iter()
		.take(ERASURE_DATA_SHARDS)
		.filter_map(|shard| shard.as_ref())
		.flatten()
		.copied()
		.collect();
	let length = usize::try_from(original_len?).ok()?;
	if length > recovered.len() {
		return None;
	}
	recovered.truncate(length);
	Some(recovered)
}

fn to_file(dat: &[u8], db_name: &str) -> std::io::Result<()> {
	write_atomic(&temp_path(db_name), &db_path(db_name), dat)
}

/// Writes the vault through a temporary file that is readable by its owner
/// only, whatever the process umask, then renames it into place. A temporary
/// left by an interrupted save is replaced, never appended to or reused.
fn write_atomic(tmp_path: &Path, path: &Path, dat: &[u8]) -> std::io::Result<()> {
	match fs::remove_file(tmp_path) {
		Ok(()) => {}
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
		Err(err) => return Err(err),
	}
	let mut file = fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(tmp_path)?;
	file.write_all(dat)?;
	file.sync_all()?;
	mem::drop(file);
	fs::rename(tmp_path, path)?;
	if let Some(parent) = path.parent() {
		let dir = fs::File::open(parent)?;
		dir.sync_all()?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn vault_files_are_private_and_replace_stale_temporaries() {
		use std::os::unix::fs::PermissionsExt;
		let dir = env::temp_dir().join(format!("keptino-write-{}", std::process::id()));
		fs::create_dir_all(&dir).unwrap();
		let tmp = dir.join(".main.keptino");
		let path = dir.join("main.keptino");
		fs::write(&tmp, b"interrupted").unwrap();
		fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();
		write_atomic(&tmp, &path, b"vault").unwrap();
		assert_eq!(fs::read(&path).unwrap(), b"vault");
		assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
		assert!(!tmp.exists());
		write_atomic(&tmp, &path, b"second").unwrap();
		assert_eq!(fs::read(&path).unwrap(), b"second");
		fs::remove_dir_all(&dir).unwrap();
	}

	fn fixture_database() -> Database {
		let db = Database::test_database();
		db.set_meta_entry(MetaEntry::new("db_name", "example"));
		db.set_meta_entry(MetaEntry::new("salt", &to_base64(&[42; SALT_SIZE])));
		db.set_meta_entry(MetaEntry::new("nonce", "7"));
		db
	}

	#[test]
	fn cloud_envelopes_roundtrip_and_reject_damaged_input() {
		let db = fixture_database();
		let encoded = db_to_vec(&db, false);
		let envelope = Envelope::decode(&encoded).unwrap();
		assert_eq!(envelope.salt, [42; SALT_SIZE]);
		assert_eq!(envelope.revision, None);
		assert!(envelope.aad.is_empty());
		assert!(envelope.unlock(&db.clone_master_key().read().unwrap()).is_some());
		db.set_meta_entry(MetaEntry::new("nonce", "7"));
		assert_ne!(
			Envelope::decode(&db_to_vec(&db, false)).unwrap().nonce,
			envelope.nonce
		);
		assert!(Envelope::decode(&encoded[1..]).is_err());
		assert!(Envelope::decode(&[]).is_err());
		assert!(Envelope::decode(&encode_erasure(&[0, 100, 0, 0, 0])).is_err());
	}

	/// Re-encodes a vault file with one plaintext meta value altered.
	fn tamper(encoded: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
		let mut recovered = decode_erasure(encoded).unwrap();
		let at = recovered
			.windows(from.len())
			.position(|window| window == from)
			.expect("plaintext field present");
		recovered[at..at + from.len()].copy_from_slice(to);
		encode_erasure(&recovered)
	}

	#[test]
	fn format_two_binds_the_plaintext_metadata_and_never_downgrades() {
		let db = fixture_database();
		let key = db.clone_master_key();
		let encoded = db_to_vec(&db, true);
		let envelope = Envelope::decode(&encoded).unwrap();
		assert_eq!(envelope.revision, Some(1));
		assert!(envelope.aad.starts_with(AAD_PREFIX));
		assert!(envelope.unlock(&key.read().unwrap()).is_some());
		// Changing a plaintext field that selection or identity depends on
		// breaks authentication even though the ciphertext is untouched.
		let renamed = Envelope::decode(&tamper(&encoded, b"example", b"exampel")).unwrap();
		assert!(renamed.unlock(&key.read().unwrap()).is_none());
		let bumped = tamper(&encoded, b"revision", b"revisioN");
		assert!(Envelope::decode(&bumped).is_err(), "revision is required in format 2");
		// A vault that is format 2 stays format 2 when the upgrade switch is off.
		let again = Envelope::decode(&db_to_vec(&db, false)).unwrap();
		assert_eq!(again.revision, Some(2));
		assert!(again.unlock(&key.read().unwrap()).is_some());
		// A format from the future is refused with an explanation, not a guess.
		let future = tamper(&db_to_vec(&db, false), b"format\x02\x01\x00\x00\x002", b"format\x02\x01\x00\x00\x009");
		assert!(Envelope::decode(&future).err().unwrap().contains("newer Keptino"));
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
		assert_ne!(
			envelope_aad(&[("salt".to_string(), "t".to_string())]),
			envelope_aad(&[("salt".to_string(), "s".to_string())])
		);
	}

	#[test]
	fn the_newer_revision_is_tried_first_and_older_copies_are_refused() {
		let mut local = Envelope::decode(&db_to_vec(&fixture_database(), true)).unwrap();
		let mut remote = Envelope::decode(&db_to_vec(&fixture_database(), true)).unwrap();
		local.modified = 10;
		remote.modified = 20;
		assert!(!prefer_local(&local, &remote), "later timestamp wins without revisions");
		local.revision = Some(3);
		remote.revision = Some(2);
		assert!(prefer_local(&local, &remote), "revision outranks timestamp");
		remote.revision = Some(3);
		assert!(!prefer_local(&local, &remote), "equal revisions fall back to timestamp");
		local.revision = None;
		assert!(!prefer_local(&local, &remote), "a legacy copy is compared by timestamp");
		assert!(check_revision(Some(2), Some(5), "x").unwrap_err().contains("revision 2"));
		assert!(check_revision(Some(5), Some(5), "x").is_ok());
		assert!(check_revision(Some(6), Some(5), "x").is_ok());
		assert!(check_revision(None, Some(5), "x").is_ok());
		assert!(check_revision(Some(1), None, "x").is_ok());
	}
	#[test]
	fn existing_compression_and_cipher_format_are_preserved() {
		use chacha20poly1305::{
			XChaCha20Poly1305,
			aead::{Aead, KeyInit},
		};
		let plaintext = b"synthetic vault record\n".repeat(10000);
		let mut old_encoder = lz4::EncoderBuilder::new()
			.level(9)
			.build(Vec::new())
			.unwrap();
		old_encoder.write_all(&plaintext).unwrap();
		let original_compressed = old_encoder.finish().0;
		let compressed = compress(&plaintext);
		assert_eq!(&*compressed, &original_compressed);
		let key = SecretMemory::new_pages(1).unwrap();
		key.write(0, &[42; 32]).unwrap();
		let nonce = [7; NONCE_SIZE];
		let cipher = XChaCha20Poly1305::new_from_slice(&[42; 32]).unwrap();
		let original_encrypted = cipher
			.encrypt((&nonce).into(), &original_compressed[..])
			.unwrap();
		assert_eq!(encrypt(&compressed, &key, nonce, &[]), original_encrypted);
		let decoded = decompress(decrypt(original_encrypted.clone(), &key, nonce, &[]).unwrap());
		assert_eq!(&*decoded, &plaintext);
		let mut damaged = original_encrypted;
		damaged[0] ^= 1;
		assert!(decrypt(damaged, &key, nonce, &[]).is_none());
	}
}
