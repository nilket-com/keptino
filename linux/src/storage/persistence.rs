//! Where the Linux head keeps a vault and how it opens one: files under
//! `~/.config/keptino`, the TPM-sealed pepper through systemd-creds, the
//! storage provider, and the choice between the local and remote copies.
//! The file format, the cryptography, the database model and the selection
//! rules are `libkeptino`'s; this module supplies the I/O around them.

use crate::storage::keys::{self, RekeyMarker};
use crate::{
	logger::{error, info, warn},
	storage::{Database, MetaEntry, SYSTEMD_CREDS, SecretMemory, remote::Remote},
};
use libkeptino::{
	crypto::{self, KEY_SIZE, PEPPER_SIZE, SALT_SIZE},
	format::{Envelope, KdfParams, MAX_FILE_BYTES},
	policy,
	vault::{Candidate, Caution, Derived, KeyStore, Source, UnlockError, unlock},
};
use std::{
	env, fs,
	io::Write,
	mem,
	os::unix::fs::{DirBuilderExt, OpenOptionsExt},
	path::{Path, PathBuf},
	process::Command,
	sync::{Arc, Mutex},
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
	/// A rekey committed in this session and not yet uploaded. The next save
	/// writes the marker before it uploads and removes it after.
	rekey: Arc<Mutex<Option<RekeyMarker>>>,
}

impl OpenedVault {
	pub fn status(&self) -> String {
		match &self.remote {
			Ok(_) => "Unlocked".into(),
			Err(err) => format!("{err} Uploads paused until next unlock."),
		}
	}

	/// The database was rekeyed: the next save carries the marker naming
	/// the remote object this session opened as the predecessor.
	pub fn note_rekey(&self) {
		let predecessor = *self.synced.lock().unwrap_or_else(|e| e.into_inner());
		let marker = RekeyMarker {
			predecessor,
			salt: self.database.salt().unwrap_or_default(),
			// The save about to happen writes this revision.
			revision: self.database.revision().unwrap_or(0) + 1,
		};
		*self.rekey.lock().unwrap_or_else(|e| e.into_inner()) = Some(marker);
	}

	pub fn save(&self) -> impl Future<Output = String> + use<> {
		let db = &self.database;
		let db_name = db.meta("db_name").unwrap_or_default();
		// Snapshot the encrypted vault before the UI can lock and clear its keys.
		let encoded = db.encode(WRITE_AAD_FORMAT, KdfParams::BUILD_DEFAULT);
		let saved = db.revision();
		let remote = self.remote.clone();
		let synced = Arc::clone(&self.synced);
		let rekey = Arc::clone(&self.rekey);
		async move {
			let bytes = match encoded {
				Ok(bytes) => bytes,
				Err(err) => return format!("Not saved: {err}"),
			};
			// The marker goes down before the file: a crash between the two
			// leaves a marker naming a successor that is not here, which
			// reconcile_marker drops; the other order could leave a rekeyed
			// local with no record of what it may replace.
			let pending = rekey.lock().unwrap_or_else(|e| e.into_inner()).clone();
			if let Some(marker) = &pending {
				let marker = RekeyMarker {
					revision: saved.unwrap_or(marker.revision),
					..marker.clone()
				};
				if marker.write(&db_name).is_err() {
					return "Local save failed: cannot record the rekey.".into();
				}
			}
			if to_file(&bytes, &db_name).is_err() {
				return "Local save failed. Check disk space and file permissions.".into();
			}
			if let Some(revision) = saved {
				remember_revision(&db_name, revision);
			}
			let result = match remote {
				Ok(provider) => match provider.fetch(&base_path(), &db_name).await {
					Ok(fetched) => {
						let current = fetched.bytes.as_deref().map(blake3::hash);
						if current != *synced.lock().unwrap_or_else(|e| e.into_inner()) {
							Err("The remote vault changed since this session synced it. Saved locally only; unlock again to load the newer copy before uploading.".into())
						} else {
							// The store is asked to refuse the write if the
							// object moved between the fetch and now; an S3
							// object without a usable tag is not replaced.
							let uploaded = match fetched.precondition() {
								Ok(precondition) => {
									provider
										.upload(&base_path(), &db_name, &bytes, precondition)
										.await
								}
								Err(err) => Err(err),
							};
							if uploaded.is_ok() {
								*synced.lock().unwrap_or_else(|e| e.into_inner()) =
									Some(blake3::hash(&bytes));
								if pending.is_some() {
									*rekey.lock().unwrap_or_else(|e| e.into_inner()) = None;
									RekeyMarker::remove(&db_name);
								}
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
			rekey: Arc::default(),
		}
	}
}

/// What the unlock screen asks for: the master password and, when a slot
/// needs user verification, the security key's PIN.
pub struct UnlockInput {
	pub password: Zeroizing<String>,
	pub pin: Option<Zeroizing<String>>,
}

/// Whether the local copy of `db_name` carries key slots, so the unlock
/// screen can show the PIN field before the user presses Unlock.
pub fn local_has_slots(db_name: &str) -> bool {
	read_bounded(&db_path(db_name))
		.ok()
		.and_then(|bytes| Envelope::parse(&bytes, KdfParams::BUILD_DEFAULT).ok())
		.is_some_and(|envelope| !envelope.slots.is_empty())
}

fn parse_envelope(bytes: &[u8], what: &str) -> Result<Envelope, String> {
	Envelope::parse(bytes, KdfParams::BUILD_DEFAULT).map_err(|err| format!("{what} vault: {err}"))
}

/// The message for two copies with different salts, naming the way out.
pub const DIFFERENT_VAULT_HELP: &str = "The copy in the bucket has a different salt: it was rekeyed on another device, or another vault uses this name. To take the bucket copy and keep this one as a generation, use Adopt bucket copy.";

pub async fn load(db_name: &str, input: UnlockInput) -> Result<OpenedVault, String> {
	open(db_name, input, false).await
}

/// Opens the bucket copy alone, after keeping the local file as a
/// generation: the explicit way across a rekey done elsewhere.
pub async fn adopt_remote(db_name: &str, input: UnlockInput) -> Result<OpenedVault, String> {
	open(db_name, input, true).await
}

async fn open(db_name: &str, input: UnlockInput, adopt: bool) -> Result<OpenedVault, String> {
	if db_name.contains(['/', '\0']) {
		return Err("Use a database name without path separators or NUL bytes.".into());
	}
	let dir = base_path();
	let local_bytes = match read_bounded(&db_path(db_name)) {
		Ok(bytes) => Some(bytes),
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
		Err(_) => return Err("Cannot read local vault.".into()),
	};
	let local = local_bytes
		.as_deref()
		.map(|bytes| parse_envelope(bytes, "Local"))
		.transpose()?;
	let download = async {
		let (remote, fetched) = Remote::download(&dir, db_name).await?;
		let bytes = fetched.bytes;
		let fingerprint = bytes.as_deref().map(blake3::hash);
		let envelope = bytes
			.as_deref()
			.map(|b| parse_envelope(b, "Remote"))
			.transpose()?;
		Ok::<_, String>((remote, envelope, fingerprint, bytes))
	}
	.await;
	let (mut provider, mut remote, synced, remote_bytes) = match download {
		Ok((provider, envelope, fingerprint, bytes)) => {
			(Ok(provider), envelope, fingerprint, bytes)
		}
		Err(err) if local.is_some() => (Err(format!("Opened local copy. {err}")), None, None, None),
		Err(err) => return Err(err),
	};
	// A rekey this device committed and has not uploaded: the remote is the
	// predecessor it names, so it is withheld and the local copy opens
	// alone, with uploads enabled to finish the rekey.
	let pending_rekey = keys::reconcile_marker(db_name, local.as_ref(), synced);
	if pending_rekey.is_some() {
		info("Finishing a rekey: the bucket still holds the copy from before it.");
		remote = None;
	}
	// Adopting opens the bucket copy alone; the local file is touched only
	// after that copy opened and passed the revision floor.
	let local = if adopt {
		if local.is_none() || remote.is_none() {
			return Err("Adopting needs both a local and a bucket copy.".into());
		}
		None
	} else {
		local
	};
	// One derivation serves both copies, which share a salt and, except
	// across a rekey, a cost; the password is wiped when the closure drops.
	let UnlockInput { password, pin } = input;
	let pepper = load_pepper()?;
	let cancel = std::sync::atomic::AtomicBool::new(false);
	let derive = |candidate: &Candidate<'_>| {
		let roaming = if candidate.slots.is_empty() {
			None
		} else {
			match keys::roaming_from_keys(candidate.slots, pin.clone(), &cancel) {
				Ok(roaming) => Some(roaming),
				Err(libkeptino::fido::ceremony::Failure::Canceled) => return Derived::Canceled,
				Err(failure) => {
					warn(&format!("Security key: {failure}"));
					return Derived::Unavailable;
				}
			}
		};
		match master_key_derivation(
			&password,
			&pepper,
			candidate.salt,
			roaming.as_deref(),
			candidate.cost,
		) {
			Ok(key) => Derived::Key(key),
			Err(err) => Derived::Failed(err),
		}
	};
	let unlocked = unlock(db_name, local, remote, KdfParams::BUILD_DEFAULT, derive).map_err(
		|err| match err {
			UnlockError::Open(_) => {
				"Cannot decrypt vault. Check the master password and pepper.".to_owned()
			}
			UnlockError::Unavailable => {
				"No enrolled security key answered. Plug in a key enrolled for this vault and unlock again.".to_owned()
			}
			UnlockError::DifferentVault => DIFFERENT_VAULT_HELP.to_owned(),
			other => other.to_string(),
		},
	)?;
	let database = unlocked.database;
	match unlocked.source {
		Source::New => info("New database created."),
		Source::Local => info("Local database loaded."),
		Source::Remote => info("Remote database loaded."),
	}
	if let Some(caution) = unlocked.caution {
		let note = match caution {
			Caution::OtherCopyFailed(Source::Remote) => {
				"The remote copy failed authentication and may be corrupt or tampered with; opened the local copy."
			}
			Caution::OtherCopyFailed(_) => {
				"The local copy failed authentication and may be corrupt or tampered with; opened the remote copy."
			}
			Caution::LegacyLocalOverVersionedRemote => {
				"The local copy predates revisions and was opened; the remote copy carries a revision."
			}
		};
		warn(note);
		provider = Err(note.to_owned());
	}
	let opened = database.revision();
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
	if adopt {
		// The exact bucket bytes become the local file, rotating the copy
		// from before into a generation once; nothing is re-encoded.
		match &remote_bytes {
			Some(bytes) if to_file(bytes, db_name).is_ok() => {}
			_ => {
				warn("The adopted copy could not be written locally; it will be on the next save.")
			}
		}
		RekeyMarker::remove(db_name);
	}
	Ok(OpenedVault {
		database,
		remote: provider,
		synced: Arc::new(Mutex::new(synced)),
		rekey: Arc::new(Mutex::new(pending_rekey)),
	})
}

/// Reads a vault file into memory, never more than the file budget plus
/// one byte, so an oversized or special file cannot fill locked memory
/// before the parser refuses it.
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
	use std::io::Read;
	let mut bytes = Vec::new();
	fs::File::open(path)?
		.take(MAX_FILE_BYTES as u64 + 1)
		.read_to_end(&mut bytes)?;
	Ok(bytes)
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

/// The cost a database was derived with, from its meta entries, or the
/// build default for a vault that records none.
pub fn vault_cost(db: &Database) -> KdfParams {
	let meta: std::collections::HashMap<String, String> = db.meta_pairs().into_iter().collect();
	KdfParams::from_meta(&meta, KdfParams::BUILD_DEFAULT).unwrap_or(KdfParams::BUILD_DEFAULT)
}

/// A master key for `salt` under the vault's cost and this machine's
/// pepper, with or without a roaming secret: what a rekey derives.
pub fn derive_master(
	db: &Database,
	password: &str,
	salt: &[u8; SALT_SIZE],
	roaming: Option<&[u8; crypto::ROAMING_SIZE]>,
) -> Result<SecretMemory, String> {
	let pepper = load_pepper()?;
	master_key_derivation(password, &pepper, salt, roaming, vault_cost(db))
}

/// Derives the master key and moves it into secret memory.
fn master_key_derivation(
	password: &str,
	pepper: &[u8; PEPPER_SIZE],
	salt: &[u8; SALT_SIZE],
	roaming: Option<&[u8; crypto::ROAMING_SIZE]>,
	kdf: KdfParams,
) -> Result<SecretMemory, String> {
	let mut key = Zeroizing::new([0u8; KEY_SIZE]);
	crypto::derive_master_key(password.as_bytes(), pepper, salt, roaming, kdf, &mut key)
		.map_err(|err| err.to_string())?;
	SecretMemory::from_bytes(&key).map_err(|_| "Secret memory unavailable.".into())
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
	use crate::storage::test_database;

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

	/// The ADR 0011 fixture through the shared unlock with secret memory
	/// keys: a simulated security key answers for the slots, the roaming
	/// secret goes into the derivation, and a stranger's key never reaches
	/// the Argon2 arena.
	#[test]
	fn the_two_slot_fixture_opens_through_unlock_with_a_simulated_key() {
		use libkeptino::fido::ceremony::{Ceremony, Failure, Outcome, Step};
		use libkeptino::fido::sim::{Authenticator, Device, HidDevice};
		use libkeptino::vault::{Candidate, Derived, unlock};
		const FIXTURE: &[u8] =
			include_bytes!("../../../android/droid/tests/fixtures/linux-debug-fido.keptino");
		const SEED: [u8; 32] = *b"keptino-fixture-security-key-001";
		let mut pepper = [0u8; PEPPER_SIZE];
		hex::decode_to_slice(
			"3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1",
			&mut pepper,
		)
		.unwrap();
		let derivations = std::cell::Cell::new(0);
		let open_with = |seed: [u8; 32]| {
			let mut device = Device::Hid(HidDevice::new(Authenticator::new(seed).with_pin("1234")));
			let derive = |candidate: &Candidate<'_>| {
				let (mut ceremony, step) =
					Ceremony::assert(device.transport(), candidate.slots.to_vec());
				match device.drive(&mut ceremony, step, Some("1234")) {
					Step::Done(Outcome::Asserted { roaming, .. }) => {
						derivations.set(derivations.get() + 1);
						match master_key_derivation(
							"correct horse battery staple",
							&pepper,
							candidate.salt,
							Some(&roaming),
							candidate.cost,
						) {
							Ok(key) => Derived::Key(key),
							Err(err) => Derived::Failed(err),
						}
					}
					Step::Failed(Failure::Canceled) => Derived::Canceled,
					_ => Derived::Unavailable,
				}
			};
			let envelope = Envelope::parse(FIXTURE, KdfParams::DEBUG).unwrap();
			unlock("vaultfido", Some(envelope), None, KdfParams::DEBUG, derive)
		};
		let opened = open_with(SEED).unwrap();
		assert_eq!(derivations.get(), 1);
		assert_eq!(
			opened.database.names(),
			vec!["bank".to_string(), "mail".to_string()]
		);
		assert_eq!(
			opened
				.database
				.get_password_entry_by_name("mail")
				.unwrap()
				.get_username(),
			"alice@example.com"
		);
		opened.database.zeroize();
		assert_eq!(open_with([9; 32]).err(), Some(UnlockError::Unavailable));
		assert_eq!(
			derivations.get(),
			1,
			"a stranger's key never reached the arena"
		);
	}

	/// The core model over real secret memory: the save path and the reopen
	/// path through `memfd_secret`-backed keys.
	#[test]
	fn saves_reopen_through_secret_memory_keys() {
		let db = test_database();
		let mut entry = crate::storage::PasswordEntry::new();
		entry.set_name("bank");
		entry.set_password("hunter2");
		db.set_password_entry(entry);
		let encoded = db.encode(false, KdfParams::BUILD_DEFAULT).unwrap();
		let envelope = Envelope::parse(&encoded, KdfParams::BUILD_DEFAULT).unwrap();
		assert_eq!(envelope.revision, Some(1));
		assert_eq!(envelope.kdf, KdfParams::BUILD_DEFAULT);
		assert!(envelope.aad.is_empty());
		let reopened = Database::open(&envelope, SecretMemory::from_bytes(&[42; 32]).unwrap())
			.unwrap_or_else(|(_, why)| panic!("reopens under the same key: {why}"));
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
			Database::open(&envelope, SecretMemory::from_bytes(&[1; 32]).unwrap()).is_err(),
			"a wrong key is handed back"
		);
		let marked = Envelope::parse(
			&db.encode(true, KdfParams::BUILD_DEFAULT).unwrap(),
			KdfParams::BUILD_DEFAULT,
		)
		.unwrap();
		assert!(!marked.aad.is_empty());
		assert_eq!(marked.revision, Some(2));
		let converted = Envelope::parse(
			&db.encode(false, KdfParams::BUILD_DEFAULT).unwrap(),
			KdfParams::BUILD_DEFAULT,
		)
		.unwrap();
		assert!(converted.aad.is_empty());
		assert_eq!(converted.revision, Some(3));
		assert!(Envelope::parse(&encoded[1..], KdfParams::DEBUG).is_err());
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
