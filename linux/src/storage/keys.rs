//! Security keys at the vault level: the derive closure that asks a key for
//! the roaming secret, the ceremonies that enroll and remove keys, and the
//! rekey marker that lets the device which rekeyed finish its upload. The
//! transport lives in `crate::fido`; the protocol in `libkeptino::fido`.

use crate::fido::{self, Prompt};
use crate::logger::{info, warn};
use crate::storage::persistence::base_path;
use libkeptino::crypto::{ROAMING_SIZE, SALT_SIZE};
use libkeptino::fido::ceremony::{Failure, Outcome};
use libkeptino::roaming::{KeySlot, MAX_SLOTS, UvMode};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use zeroize::Zeroizing;

/// What the user is told while a key is in play.
pub fn prompt_text(prompt: Prompt) -> &'static str {
	match prompt {
		Prompt::Touch => "Touch your security key.",
	}
}

/// Asks the keys present for the roaming secret behind one of `slots`.
pub fn roaming_from_keys(
	slots: &[KeySlot],
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
) -> Result<Zeroizing<[u8; ROAMING_SIZE]>, Failure> {
	match fido::assert_with_any_key(slots, pin, cancel, |prompt| info(prompt_text(prompt)))? {
		Outcome::Asserted { roaming, .. } => Ok(roaming),
		Outcome::Enrolled(_) => Err(Failure::Mismatch),
	}
}

/// Enrolls the first key present into a new slot wrapping `roaming`.
pub fn enroll_key(
	uv_mode: UvMode,
	roaming: &Zeroizing<[u8; ROAMING_SIZE]>,
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
) -> Result<KeySlot, Failure> {
	fido::enroll_with_first_key(uv_mode, roaming, pin, cancel, |prompt| {
		info(prompt_text(prompt))
	})
}

/// The mode a key should be enrolled in: verified when it can verify the
/// user, touch-only otherwise. The user may still choose touch-only.
pub fn default_mode(prefer_touch_only: bool) -> UvMode {
	if prefer_touch_only {
		UvMode::TouchOnly
	} else {
		UvMode::Verified
	}
}

/// A fresh roaming secret and salt for a rekey or a first protection.
pub fn fresh_secret() -> (Zeroizing<[u8; ROAMING_SIZE]>, [u8; SALT_SIZE]) {
	let mut roaming = Zeroizing::new([0u8; ROAMING_SIZE]);
	getrandom::fill(&mut *roaming).expect("Random generation failed");
	let mut salt = [0u8; SALT_SIZE];
	getrandom::fill(&mut salt).expect("Random generation failed");
	(roaming, salt)
}

/// The slots a database carries, in order, from its meta entries.
pub fn slots_of(db: &crate::storage::Database) -> Vec<KeySlot> {
	let pairs = db.meta_pairs();
	libkeptino::roaming::slots_from_meta(
		pairs
			.iter()
			.map(|(name, value)| (name.as_str(), value.as_str())),
	)
	.unwrap_or_default()
}

/// Replaces the database's slots with `slots`.
pub fn set_slots(db: &crate::storage::Database, slots: &[KeySlot]) {
	for index in 0..MAX_SLOTS {
		db.remove_meta_entry(&KeySlot::entry_name(index));
	}
	for (index, slot) in slots.iter().enumerate() {
		db.set_meta_entry(libkeptino::vault::MetaEntry::new(
			&KeySlot::entry_name(index),
			&slot.encode(),
		));
	}
}

/// What a key ceremony on the keys screen produced, applied to the open
/// vault on the GUI thread and then saved.
#[derive(Clone)]
pub enum KeysOutcome {
	/// A key was added to a vault that already had slots: no rekey.
	Added(KeySlot),
	/// The vault was rekeyed: the new master key, its salt and the slots
	/// that now wrap the roaming secret; empty slots turn protection off.
	Rekeyed {
		key: std::sync::Arc<crate::storage::SecretMemory>,
		salt: [u8; SALT_SIZE],
		slots: Vec<KeySlot>,
	},
}

/// The security key side of the keys screen: enroll into an existing
/// protected vault.
pub fn add_key(
	slots: &[KeySlot],
	pin: Option<Zeroizing<String>>,
	touch_only: bool,
) -> Result<KeysOutcome, String> {
	if slots.len() >= MAX_SLOTS {
		return Err(format!("A vault holds at most {MAX_SLOTS} keys."));
	}
	let cancel = AtomicBool::new(false);
	let roaming = roaming_from_keys(slots, pin.clone(), &cancel).map_err(|f| f.to_string())?;
	info("Now plug in or touch the key to add.");
	let slot = fido::enroll_new_key(
		slots,
		default_mode(touch_only),
		&roaming,
		pin,
		&cancel,
		|prompt| info(prompt_text(prompt)),
	)
	.map_err(|f| f.to_string())?;
	Ok(KeysOutcome::Added(slot))
}

/// Protects a vault without slots: a fresh secret and salt, the first key
/// enrolled, the master key re-derived.
/// Derives a master key for a salt and an optional roaming secret: the
/// persistence layer's derivation with the vault's cost and this machine's
/// pepper, or a test's stand-in.
pub type Derive<'a> = &'a dyn Fn(
	&[u8; SALT_SIZE],
	Option<&[u8; ROAMING_SIZE]>,
) -> Result<crate::storage::SecretMemory, String>;

pub fn protect(
	derive: Derive<'_>,
	pin: Option<Zeroizing<String>>,
	touch_only: bool,
) -> Result<KeysOutcome, String> {
	let cancel = AtomicBool::new(false);
	let (roaming, salt) = fresh_secret();
	let slot =
		enroll_key(default_mode(touch_only), &roaming, pin, &cancel).map_err(|f| f.to_string())?;
	let key = derive(&salt, Some(&roaming))?;
	Ok(KeysOutcome::Rekeyed {
		key: std::sync::Arc::new(key),
		salt,
		slots: vec![slot],
	})
}

/// Removes the slot at `index` by rekeying: a fresh secret and salt, every
/// other key touched in turn for a new slot, the master key re-derived.
/// A key in `dropped` is left out without being asked, after the user
/// confirmed it by name. Removing the last key turns protection off.
pub fn remove_key(
	derive: Derive<'_>,
	slots: &[KeySlot],
	index: usize,
	dropped: &[usize],
	pin: Option<Zeroizing<String>>,
) -> Result<KeysOutcome, String> {
	if index >= slots.len() {
		return Err("No such key.".into());
	}
	let remaining: Vec<(usize, &KeySlot)> = slots
		.iter()
		.enumerate()
		.filter(|(i, _)| *i != index && !dropped.contains(i))
		.collect();
	if remaining.is_empty() {
		let (_, salt) = fresh_secret();
		let key = derive(&salt, None)?;
		return Ok(KeysOutcome::Rekeyed {
			key: std::sync::Arc::new(key),
			salt,
			slots: Vec::new(),
		});
	}
	let cancel = AtomicBool::new(false);
	let (roaming, salt) = fresh_secret();
	let mut new_slots = Vec::with_capacity(remaining.len());
	for (position, slot) in remaining {
		info(&format!("Touch key {} to keep it enrolled.", position + 1));
		match fido::reenroll_owner(slot, &roaming, pin.clone(), &cancel, |prompt| {
			info(prompt_text(prompt))
		}) {
			Ok(new_slot) => new_slots.push(new_slot),
			Err(Failure::Canceled) => return Err("Canceled; nothing changed.".into()),
			Err(failure) => {
				return Err(format!(
					"Key {} did not answer ({failure}). Plug it in and try again, or remove it too.",
					position + 1
				));
			}
		}
	}
	let key = derive(&salt, Some(&roaming))?;
	Ok(KeysOutcome::Rekeyed {
		key: std::sync::Arc::new(key),
		salt,
		slots: new_slots,
	})
}

/// A rekey this device committed locally and has not yet uploaded: the
/// remote object it opened, and the successor it wrote. Kept beside the
/// vault until the upload lands, so a restart or a failed upload does not
/// leave the remote a predecessor forever.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyMarker {
	/// BLAKE3 of the remote object this session opened before the rekey;
	/// `None` when the bucket held nothing.
	pub predecessor: Option<blake3::Hash>,
	pub salt: [u8; SALT_SIZE],
	pub revision: u64,
}

fn marker_path(db_name: &str) -> PathBuf {
	base_path().join(format!("{db_name}.keptino.rekey"))
}

impl RekeyMarker {
	pub fn read(db_name: &str) -> Option<Self> {
		let text = fs::read_to_string(marker_path(db_name)).ok()?;
		let mut lines = text.lines();
		let predecessor = match lines.next()? {
			"none" => None,
			hex => Some(blake3::Hash::from_hex(hex).ok()?),
		};
		let salt = hex::decode(lines.next()?).ok()?.try_into().ok()?;
		let revision = lines.next()?.parse().ok()?;
		Some(Self {
			predecessor,
			salt,
			revision,
		})
	}

	pub fn write(&self, db_name: &str) -> std::io::Result<()> {
		let predecessor = self
			.predecessor
			.map(|hash| hash.to_hex().to_string())
			.unwrap_or_else(|| "none".into());
		let text = format!(
			"{predecessor}\n{}\n{}\n",
			hex::encode(self.salt),
			self.revision
		);
		let path = marker_path(db_name);
		let temp = base_path().join(format!(".{db_name}.keptino.rekey"));
		{
			use std::io::Write;
			use std::os::unix::fs::OpenOptionsExt;
			// Owner-only from creation, like every file beside the vault.
			let mut file = fs::OpenOptions::new()
				.write(true)
				.create(true)
				.truncate(true)
				.mode(0o600)
				.open(&temp)?;
			file.write_all(text.as_bytes())?;
			file.sync_all()?;
		}
		fs::rename(temp, path)
	}

	pub fn remove(db_name: &str) {
		if fs::remove_file(marker_path(db_name)).is_ok() {
			info("Rekey finished; the bucket holds the new copy.");
		}
	}

	/// Whether `remote` is exactly the predecessor this marker names and
	/// `local` is the successor it committed, so the remote may be withheld
	/// from the unlock and replaced by the next upload.
	pub fn covers(
		&self,
		local: &libkeptino::format::Envelope,
		remote_fingerprint: Option<blake3::Hash>,
	) -> bool {
		self.predecessor == remote_fingerprint
			&& local.salt == self.salt
			&& local
				.revision
				.is_some_and(|revision| revision >= self.revision)
	}
}

/// Keeps a stale marker from granting anything: if the local copy is not
/// the successor the marker names, the marker is dropped with a warning.
pub fn reconcile_marker(
	db_name: &str,
	local: Option<&libkeptino::format::Envelope>,
	remote_fingerprint: Option<blake3::Hash>,
) -> Option<RekeyMarker> {
	let marker = RekeyMarker::read(db_name)?;
	match local {
		Some(local) if marker.covers(local, remote_fingerprint) => Some(marker),
		Some(local) if local.salt == marker.salt => {
			// The successor is here but the remote moved on: someone else
			// wrote the bucket since. The ordinary rules decide; the marker
			// no longer grants an overwrite.
			warn(
				"The bucket changed since this device rekeyed; the rekey upload is no longer automatic.",
			);
			RekeyMarker::remove(db_name);
			None
		}
		_ => {
			warn("A rekey marker named a vault that is not here; ignoring it.");
			RekeyMarker::remove(db_name);
			None
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fido::test_support::{SimKey, with_keys};
	use libkeptino::vault::KeyStore;

	/// A test derivation: the key is a hash of salt and roaming secret, so a
	/// rekey is visible and cheap.
	fn test_derive(
		salt: &[u8; SALT_SIZE],
		roaming: Option<&[u8; ROAMING_SIZE]>,
	) -> Result<crate::storage::SecretMemory, String> {
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(
			blake3::hash(
				&[
					salt.as_slice(),
					roaming.map(|r| r.as_slice()).unwrap_or(&[]),
				]
				.concat(),
			)
			.as_bytes(),
		);
		crate::storage::SecretMemory::from_bytes(&bytes).map_err(|_| "no secret memory".to_string())
	}

	fn key(seed: u8, pin: Option<&'static str>) -> SimKey {
		SimKey {
			seed: [seed; 32],
			pin,
			silent_reads: 0,
		}
	}

	#[test]
	fn protect_add_and_remove_rekey_as_the_decision_says() {
		let pin = || Some(Zeroizing::new("1234".to_string()));
		let protected = with_keys(vec![key(1, Some("1234"))], || {
			protect(&test_derive, pin(), false)
		})
		.unwrap();
		let KeysOutcome::Rekeyed {
			salt: first_salt,
			slots,
			..
		} = protected
		else {
			panic!("protect rekeys");
		};
		assert_eq!(slots.len(), 1);
		assert_eq!(slots[0].uv_mode, UvMode::Verified);

		// Add a touch-only backup key: the first key releases the secret, the
		// backup wraps it; no rekey.
		let added = with_keys(vec![key(1, Some("1234")), key(2, None)], || {
			add_key(&slots, pin(), true)
		})
		.unwrap();
		let KeysOutcome::Added(backup) = added else {
			panic!("add does not rekey");
		};
		assert_eq!(backup.uv_mode, UvMode::TouchOnly);
		let both = vec![slots[0].clone(), backup];
		let four = [both.clone(), both.clone()].concat();
		assert!(matches!(
			with_keys(vec![key(1, Some("1234"))], || add_key(&four, pin(), true)),
			Err(ref e) if e.contains("at most")
		));

		// Remove the first key with the backup present: a new salt, one new
		// slot wrapping a new secret, touch-only as before.
		let removed = with_keys(vec![key(2, None)], || {
			remove_key(&test_derive, &both, 0, &[], None)
		})
		.unwrap();
		let KeysOutcome::Rekeyed {
			salt, slots: left, ..
		} = removed
		else {
			panic!("remove rekeys");
		};
		assert_ne!(salt, first_salt);
		assert_eq!(left.len(), 1);
		assert_eq!(left[0].uv_mode, UvMode::TouchOnly);
		assert_ne!(
			left[0].cred_id, both[1].cred_id,
			"a new credential, not the old slot"
		);

		// The backup is not in hand: the removal names it and changes nothing.
		let Err(err) = with_keys(vec![key(1, Some("1234"))], || {
			remove_key(&test_derive, &both, 0, &[], pin())
		}) else {
			panic!("a missing key must stop the removal");
		};
		assert!(err.starts_with("Key 2 did not answer"), "{err}");
		// Dropping it too turns protection off: no slots, a plain key.
		let off = with_keys(vec![key(1, Some("1234"))], || {
			remove_key(&test_derive, &both, 0, &[1], pin())
		})
		.unwrap();
		assert!(matches!(off, KeysOutcome::Rekeyed { slots, .. } if slots.is_empty()));
		// Removing the last key of a one-key vault likewise.
		let off = with_keys(vec![], || remove_key(&test_derive, &slots, 0, &[], None)).unwrap();
		assert!(matches!(off, KeysOutcome::Rekeyed { slots, .. } if slots.is_empty()));
		assert!(remove_key(&test_derive, &slots, 5, &[], None).is_err());
		// Nothing to enroll with.
		assert!(with_keys(vec![], || protect(&test_derive, None, false)).is_err());
	}

	#[test]
	fn the_marker_round_trips_and_covers_only_its_own_transition() {
		let db_name = format!("marker-test-{}", std::process::id());
		let marker = RekeyMarker {
			predecessor: Some(blake3::hash(b"old remote")),
			salt: [7u8; SALT_SIZE],
			revision: 12,
		};
		marker.write(&db_name).unwrap();
		assert_eq!(RekeyMarker::read(&db_name), Some(marker.clone()));
		let mut local = test_envelope([7u8; SALT_SIZE], Some(12));
		assert!(marker.covers(&local, Some(blake3::hash(b"old remote"))));
		local.revision = Some(13);
		assert!(
			marker.covers(&local, Some(blake3::hash(b"old remote"))),
			"a later save still covers"
		);
		assert!(!marker.covers(&local, Some(blake3::hash(b"changed remote"))));
		assert!(!marker.covers(&local, None));
		local.salt = [8u8; SALT_SIZE];
		assert!(!marker.covers(&local, Some(blake3::hash(b"old remote"))));
		// A restored older generation under the successor salt grants nothing.
		let older = test_envelope([7u8; SALT_SIZE], Some(11));
		assert!(!marker.covers(&older, Some(blake3::hash(b"old remote"))));
		// Reconcile drops a marker whose successor is gone.
		assert!(
			reconcile_marker(
				&db_name,
				Some(&test_envelope([9u8; SALT_SIZE], Some(1))),
				None
			)
			.is_none()
		);
		assert!(RekeyMarker::read(&db_name).is_none());
		// And one whose bucket moved on.
		marker.write(&db_name).unwrap();
		assert!(
			reconcile_marker(&db_name, Some(&local), Some(blake3::hash(b"someone else"))).is_none()
		);
		assert!(RekeyMarker::read(&db_name).is_none());
		// The empty-bucket predecessor.
		let first = RekeyMarker {
			predecessor: None,
			salt: [1u8; SALT_SIZE],
			revision: 1,
		};
		first.write(&db_name).unwrap();
		assert_eq!(RekeyMarker::read(&db_name), Some(first.clone()));
		assert_eq!(
			reconcile_marker(
				&db_name,
				Some(&test_envelope([1u8; SALT_SIZE], Some(1))),
				None
			),
			Some(first)
		);
		RekeyMarker::remove(&db_name);
	}

	fn test_envelope(salt: [u8; SALT_SIZE], revision: Option<u64>) -> libkeptino::format::Envelope {
		libkeptino::format::Envelope {
			modified: 1,
			revision,
			kdf: libkeptino::format::KdfParams::DEBUG,
			nonce: [0; 24],
			salt,
			ciphertext: Vec::new(),
			mirror: Vec::new(),
			aad: Vec::new(),
			slots: Vec::new(),
		}
	}
}
