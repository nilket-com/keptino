//! Where the Linux head keeps a vault and how it opens one: files under
//! `~/.config/keptino`, the TPM-sealed pepper through systemd-creds, the
//! storage provider, and the choice between the local and remote copies.
//! The file format, the cryptography and the selection rules themselves are
//! `keptino_core`'s; this module supplies the I/O around them.

use crate::{
	logger::{error, info, warn},
	storage::{
		SYSTEMD_CREDS,
		database::{Database, InteriorDatabase},
		entry::MetaEntry,
		remote::Remote,
		secret::SecretMemory,
	},
};
use keptino_core::{
	crypto::{self, KEY_SIZE, NONCE_SIZE, PEPPER_SIZE, SALT_SIZE},
	format::{AAD_FORMAT, Envelope, KdfParams, encode_envelope, envelope_aad},
	policy,
};
use std::{
	env, fs,
	io::Write,
	mem,
	os::unix::fs::{DirBuilderExt, OpenOptionsExt},
	path::{Path, PathBuf},
	process::Command,
	sync::{Arc, Mutex},
	time::SystemTime,
};
use zeroize::Zeroizing;

/// Writes the marked AAD form instead of the unmarked mirrored form. Off:
/// both platforms read unmarked vaults with a revision. The interop harness
/// turns it on only to regenerate the marked fixtures.
const WRITE_AAD_FORMAT: bool = cfg!(feature = "write-format-2");

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
		) {
		error(&format!("Cannot record the vault revision: {err}"));
	}
}

/// The core's rollback rule, with the way out named for this machine.
fn check_revision(
	opened: Option<u64>,
	last_seen: Option<u64>,
	db_name: &str,
) -> Result<(), String> {
	policy::check_revision(opened, last_seen).map_err(|rollback| {
		format!(
			"{rollback} To accept the older copy, remove ~/.config/keptino/{db_name}.revision and unlock again."
		)
	})
}

fn current_revision(db: &Database) -> Option<u64> {
	db.get_meta_entry("revision")?.get_value().parse().ok()
}

/// The master key's bytes, copied briefly out of secret memory for a cipher
/// operation and wiped after.
fn key_bytes(key: &SecretMemory) -> Zeroizing<[u8; KEY_SIZE]> {
	let mapped = key.read().expect("Master key mapping failed");
	let mut bytes = Zeroizing::new([0u8; KEY_SIZE]);
	bytes.copy_from_slice(&mapped[..KEY_SIZE]);
	bytes
}

pub(crate) fn base_path() -> PathBuf {
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
	/// Fingerprint of the remote object this session last loaded or uploaded,
	/// `None` when the bucket held nothing. A save uploads only over exactly
	/// that object, so a copy written elsewhere in the meantime is never
	/// overwritten, and a refused upload stays refused on retry.
	synced: Arc<Mutex<Option<blake3::Hash>>>,
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
		// Snapshot the encrypted vault before the UI can lock and clear its keys.
		let bytes = db_to_vec(db, WRITE_AAD_FORMAT);
		let saved = current_revision(db);
		let remote = self.remote.clone();
		let synced = Arc::clone(&self.synced);
		async move {
			if to_file(&bytes, &db_name).is_err() {
				return "Local save failed. Check disk space and file permissions.".into();
			}
			if let Some(revision) = saved {
				remember_revision(&db_name, revision);
			}
			let result = match remote {
				Ok(provider) => match provider.fetch(&base_path(), &db_name).await {
					Ok(current) => {
						let current = current.as_deref().map(blake3::hash);
						if current != *synced.lock().unwrap_or_else(|e| e.into_inner()) {
							Err("The remote vault changed since this session synced it. Saved locally only; unlock again to load the newer copy before uploading.".into())
						} else {
							let uploaded = provider.upload(&base_path(), &db_name, &bytes).await;
							if uploaded.is_ok() {
								*synced.lock().unwrap_or_else(|e| e.into_inner()) =
									Some(blake3::hash(&bytes));
							}
							uploaded
						}
					}
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
			synced: Arc::default(),
		}
	}
}

fn parse_envelope(bytes: &[u8], what: &str) -> Result<Envelope, String> {
	Envelope::parse(bytes, KdfParams::BUILD_DEFAULT).map_err(|err| format!("{what} vault: {err}"))
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
		Ok(bytes) => Some(parse_envelope(&bytes, "Local")?),
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
		Err(_) => return Err("Cannot read local vault.".into()),
	};
	let download = async {
		let (remote, bytes) = Remote::download(&dir, db_name).await?;
		let fingerprint = bytes.as_deref().map(blake3::hash);
		let envelope = bytes
			.as_deref()
			.map(|b| parse_envelope(b, "Remote"))
			.transpose()?;
		Ok::<_, String>((remote, envelope, fingerprint))
	}
	.await;
	let (mut provider, remote, synced) = match download {
		Ok((provider, envelope, fingerprint)) => (Ok(provider), envelope, fingerprint),
		Err(err) if local.is_some() => (Err(format!("Opened local copy. {err}")), None, None),
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
		(None, None) => new_db(db_name, master_password)?,
		(Some(only), None) | (None, Some(only)) => open_candidates(only, None, master_password)?.0,
		(Some(local), Some(remote)) => {
			if local.envelope.salt != remote.envelope.salt {
				return Err(
					"A different vault already uses this name in the selected bucket.".into(),
				);
			}
			let (first, second) = if policy::prefer_local(&local.envelope, &remote.envelope) {
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
		synced: Arc::new(Mutex::new(synced)),
	})
}

struct Candidate {
	envelope: Envelope,
	source: &'static str,
}

/// Derives the key once (both candidates share a salt) and opens the first
/// copy that authenticates. A copy that fails while the other opens is
/// reported, and the caller pauses uploads so it is not overwritten blindly.
fn open_candidates(
	first: Candidate,
	second: Option<Candidate>,
	password: Zeroizing<String>,
) -> Result<(Database, Option<String>), String> {
	// The password is consumed by the first derivation; the second copy
	// shares the salt and, except across a rekey, the cost, so the same key
	// serves it. A different cost on the second copy is reported as a
	// failure to open it, which is also what a forged cost would produce.
	let key = master_key_derivation(password, first.envelope.salt, first.envelope.kdf)?;
	let bytes = key_bytes(&key);
	if let Some(database) = first.envelope.open(&bytes) {
		info(&format!("{} database loaded.", first.source));
		return Ok((
			Database::old(key, InteriorDatabase::deserialize(&database)),
			None,
		));
	}
	if let Some(second) = second
		&& second.envelope.kdf == first.envelope.kdf
		&& let Some(database) = second.envelope.open(&bytes)
	{
		let rejected = format!(
			"The {} copy failed authentication and may be corrupt or tampered with; opened the {} copy.",
			first.source, second.source
		);
		warn(&rejected);
		return Ok((
			Database::old(key, InteriorDatabase::deserialize(&database)),
			Some(rejected),
		));
	}
	key.zeroize().ok();
	Err("Cannot decrypt vault. Check the master password and pepper.".into())
}

fn new_db(db_name: &str, master_password: Zeroizing<String>) -> Result<Database, String> {
	let created_ts = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		.to_string();
	let mut salt = [0u8; SALT_SIZE];
	getrandom::fill(&mut salt).unwrap();
	let master_key = master_key_derivation(master_password, salt, KdfParams::BUILD_DEFAULT)?;
	let db = Database::new(master_key);
	db.set_meta_entry(MetaEntry::new("db_name", db_name));
	db.set_meta_entry(MetaEntry::new("nonce", "0"));
	db.set_meta_entry(MetaEntry::new("salt", &to_base64(&salt)));
	db.set_meta_entry(MetaEntry::new("created_ts", &created_ts));
	db.set_meta_entry(MetaEntry::new("modified_ts", &created_ts));
	Ok(db)
}

/// Encrypts the database into the bytes of a vault file: unmarked and
/// mirrored, or the marked AAD form when `aad_form` is set. Every save
/// advances the revision and records the derivation cost it was opened with.
fn db_to_vec(db: &Database, aad_form: bool) -> Vec<u8> {
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
	let revision = current_revision(db).unwrap_or(0) + 1;
	db.set_meta_entry(MetaEntry::new("revision", &revision.to_string()));
	// A vault that never recorded its cost was opened with the build's
	// constants; record them so every build reads it back the same way.
	if db.get_meta_entry("kdf_m").is_none() {
		for (name, value) in KdfParams::BUILD_DEFAULT.meta_pairs() {
			db.set_meta_entry(MetaEntry::new(&name, &value));
		}
	}
	if aad_form {
		db.set_meta_entry(MetaEntry::new("format", &AAD_FORMAT.to_string()));
	} else {
		db.remove_meta_entry("format");
	}
	let compressed = crypto::compress(&db.serialize());
	// The envelope mirrors every meta entry; the inner copy is what a reader
	// compares it against after decryption.
	let meta = db.meta_pairs();
	let aad = if aad_form {
		envelope_aad(&meta)
	} else {
		Vec::new()
	};
	let key = db.clone_master_key();
	let ciphertext = crypto::encrypt(&compressed, &key_bytes(&key.read().unwrap()), &nonce, &aad);
	encode_envelope(&meta, &ciphertext)
}

/// The TPM-sealed pepper, released by systemd-creds for this user. A missing
/// or refused credential is an unlock error the user can act on, not a crash.
fn load_pepper() -> Result<Zeroizing<[u8; PEPPER_SIZE]>, String> {
	let pepper_output = Command::new(SYSTEMD_CREDS)
		.args(["decrypt", "--user", "--name=pepper", &pepper_path()])
		.output()
		.map_err(|_| "Cannot run systemd-creds to read the pepper.")?;
	let pepper_hex = Zeroizing::new(pepper_output.stdout);
	if !pepper_output.status.success() {
		return Err(
			"The pepper credential cannot be decrypted. Run setup, or --restore-pepper with the original seed."
				.into(),
		);
	}
	let mut pepper = Zeroizing::new([0u8; PEPPER_SIZE]);
	let text = std::str::from_utf8(&pepper_hex).map_err(|_| "Invalid pepper credential.")?;
	hex::decode_to_slice(text.trim(), &mut *pepper).map_err(|_| "Invalid pepper credential.")?;
	Ok(pepper)
}

/// Derives the master key straight into secret memory.
fn master_key_derivation(
	password: Zeroizing<String>,
	salt: [u8; SALT_SIZE],
	kdf: KdfParams,
) -> Result<SecretMemory, String> {
	let pepper = load_pepper()?;
	let mut key = Zeroizing::new([0u8; KEY_SIZE]);
	crypto::derive_master_key(password.as_bytes(), &pepper, &salt, kdf, &mut key)
		.map_err(|err| err.to_string())?;
	let master_key = SecretMemory::new_pages(1).map_err(|_| "Secret memory unavailable.")?;
	master_key
		.write(0, &*key)
		.map_err(|_| "Secret memory unavailable.")?;
	Ok(master_key)
}

fn to_base64(msg: &[u8]) -> String {
	use base64ct::{Base64, Encoding};
	Base64::encode_string(msg)
}

/// Previous saves kept beside the vault as `<db>.keptino.1` (the newest)
/// through `.keptino.3`, so a bad save or a sync that chose the wrong copy
/// can be undone by copying one back over the vault file.
const GENERATIONS: usize = 3;

fn to_file(dat: &[u8], db_name: &str) -> std::io::Result<()> {
	write_atomic_keeping(&temp_path(db_name), &db_path(db_name), dat, GENERATIONS)
}

fn write_atomic(tmp_path: &Path, path: &Path, dat: &[u8]) -> std::io::Result<()> {
	write_atomic_keeping(tmp_path, path, dat, 0)
}

/// Writes through a temporary file that is readable by its owner only,
/// whatever the process umask, then renames it into place. A temporary left
/// by an interrupted save is replaced, never appended to or reused. The
/// previous `keep` contents survive as numbered generations.
fn write_atomic_keeping(
	tmp_path: &Path,
	path: &Path,
	dat: &[u8],
	keep: usize,
) -> std::io::Result<()> {
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
	if keep > 0 && path.exists() {
		rotate_generations(path, keep)?;
	}
	fs::rename(tmp_path, path)?;
	if let Some(parent) = path.parent() {
		let dir = fs::File::open(parent)?;
		dir.sync_all()?;
	}
	Ok(())
}

fn generation_path(path: &Path, n: usize) -> PathBuf {
	let mut name = path.as_os_str().to_owned();
	name.push(format!(".{n}"));
	PathBuf::from(name)
}

/// Shifts `.1` through `.keep-1` up one and links the current file as `.1`.
/// The current file stays in place until the caller's rename replaces it,
/// so there is never a moment without a vault file.
fn rotate_generations(path: &Path, keep: usize) -> std::io::Result<()> {
	for n in (1..keep).rev() {
		let from = generation_path(path, n);
		if from.exists() {
			fs::rename(&from, generation_path(path, n + 1))?;
		}
	}
	let newest = generation_path(path, 1);
	match fs::remove_file(&newest) {
		Ok(()) => {}
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
		Err(err) => return Err(err),
	}
	fs::hard_link(path, newest)
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
		assert_eq!(
			fs::metadata(&path).unwrap().permissions().mode() & 0o777,
			0o600
		);
		assert!(!tmp.exists());
		write_atomic(&tmp, &path, b"second").unwrap();
		assert_eq!(fs::read(&path).unwrap(), b"second");
		assert!(
			!generation_path(&path, 1).exists(),
			"no generations without keep"
		);
		for content in [&b"third"[..], b"fourth", b"fifth", b"sixth"] {
			write_atomic_keeping(&tmp, &path, content, 2).unwrap();
		}
		assert_eq!(fs::read(&path).unwrap(), b"sixth");
		assert_eq!(fs::read(generation_path(&path, 1)).unwrap(), b"fifth");
		assert_eq!(fs::read(generation_path(&path, 2)).unwrap(), b"fourth");
		assert!(
			!generation_path(&path, 3).exists(),
			"older generations are dropped"
		);
		assert_eq!(
			fs::metadata(generation_path(&path, 1))
				.unwrap()
				.permissions()
				.mode()
				& 0o777,
			0o600
		);
		fs::remove_dir_all(&dir).unwrap();
	}

	fn fixture_database() -> Database {
		let db = Database::test_database();
		db.set_meta_entry(MetaEntry::new("db_name", "example"));
		db.set_meta_entry(MetaEntry::new("salt", &to_base64(&[42; SALT_SIZE])));
		db.set_meta_entry(MetaEntry::new("nonce", "7"));
		db
	}

	fn parse(bytes: &[u8]) -> Envelope {
		Envelope::parse(bytes, KdfParams::BUILD_DEFAULT).unwrap()
	}

	#[test]
	fn saves_are_unmarked_mirrored_files_that_reopen_and_advance_the_revision() {
		let db = fixture_database();
		let key = db.clone_master_key();
		let encoded = db_to_vec(&db, false);
		let envelope = parse(&encoded);
		assert_eq!(envelope.salt, [42; SALT_SIZE]);
		assert_eq!(envelope.revision, Some(1));
		assert_eq!(envelope.kdf, KdfParams::BUILD_DEFAULT);
		assert!(envelope.aad.is_empty());
		assert!(!envelope.mirror.iter().any(|(name, _)| name == "format"));
		let inner = envelope.open(&key_bytes(&key.read().unwrap())).unwrap();
		let reopened = InteriorDatabase::deserialize(&inner);
		assert_eq!(
			reopened.get_meta_entry("db_name").unwrap().get_value(),
			"example"
		);
		assert_eq!(
			reopened.get_meta_entry("revision").unwrap().get_value(),
			"1"
		);
		// Each save takes a fresh nonce and the next revision.
		let next = parse(&db_to_vec(&db, false));
		assert_ne!(next.nonce, envelope.nonce);
		assert_eq!(next.revision, Some(2));
		assert!(Envelope::parse(&encoded[1..], KdfParams::DEBUG).is_err());
	}

	#[test]
	fn the_marked_form_is_written_on_request_and_converted_back() {
		let db = fixture_database();
		let key = db.clone_master_key();
		let marked = parse(&db_to_vec(&db, true));
		assert!(!marked.aad.is_empty());
		assert_eq!(marked.revision, Some(1));
		assert!(marked.open(&key_bytes(&key.read().unwrap())).is_some());
		let converted = parse(&db_to_vec(&db, false));
		assert!(converted.aad.is_empty());
		assert!(!converted.mirror.iter().any(|(name, _)| name == "format"));
		assert_eq!(converted.revision, Some(2));
		assert!(converted.open(&key_bytes(&key.read().unwrap())).is_some());
	}

	#[test]
	fn the_rollback_message_names_the_way_out() {
		let err = check_revision(Some(2), Some(5), "main").unwrap_err();
		assert!(
			err.starts_with("This copy is revision 2, but revision 5 was already opened here.")
		);
		assert!(err.contains("~/.config/keptino/main.revision"));
		assert!(check_revision(Some(5), Some(5), "main").is_ok());
	}
}
