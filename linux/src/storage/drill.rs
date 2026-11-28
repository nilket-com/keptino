//! The recovery drill for a lost security key (ADR 0033), end to end through
//! real vault files: the shared unlock, the real key derivation at the test
//! cost, simulated keys behind the Linux HID driver, and the keys screen's
//! own protect, add and remove steps, applied as the window applies them.
//! The pepper and bucket paths are drilled by `linux/recovery-drill.sh`.

#[cfg(test)]
mod tests {
	use crate::fido::test_support::{SimKey, with_keys};
	use crate::storage::keys::{self, KeysOutcome};
	use crate::storage::{Database, PasswordEntry, SecretMemory};
	use libkeptino::crypto::{self, KEY_SIZE, ROAMING_SIZE, SALT_SIZE};
	use libkeptino::format::{Envelope, KdfParams};
	use libkeptino::vault::{Candidate, Derived, KeyStore, unlock};
	use std::sync::atomic::AtomicBool;
	use zeroize::Zeroizing;

	const PEPPER: [u8; 32] = [0x5a; 32];
	const PASSWORD: &str = "drill horse battery staple";
	const COST: KdfParams = KdfParams::DEBUG;

	fn derive(
		salt: &[u8; SALT_SIZE],
		roaming: Option<&[u8; ROAMING_SIZE]>,
	) -> Result<SecretMemory, String> {
		let mut key = Zeroizing::new([0u8; KEY_SIZE]);
		crypto::derive_master_key(PASSWORD.as_bytes(), &PEPPER, salt, roaming, COST, &mut key)
			.map_err(|err| err.to_string())?;
		SecretMemory::from_bytes(&key).map_err(|_| "no secret memory".to_string())
	}

	/// The keys screen's password check, against the open vault.
	fn verify(db: &Database, roaming: Option<&[u8; ROAMING_SIZE]>) -> Result<(), String> {
		let mut key = zeroize::Zeroizing::new([0u8; KEY_SIZE]);
		crypto::derive_master_key(
			PASSWORD.as_bytes(),
			&PEPPER,
			&db.salt().unwrap(),
			roaming,
			COST,
			&mut key,
		)
		.map_err(|err| err.to_string())?;
		db.is_master_key(&key)
			.then_some(())
			.ok_or_else(|| "wrong password".to_string())
	}

	/// The daily key has a PIN and holds a verified slot.
	fn daily() -> SimKey {
		SimKey {
			seed: [1; 32],
			pin: Some("1234"),
			silent_reads: 0,
		}
	}

	/// The backup key has no PIN and holds a touch-only slot.
	fn backup() -> SimKey {
		SimKey {
			seed: [2; 32],
			pin: None,
			silent_reads: 0,
		}
	}

	/// The key bought to replace the lost one.
	fn replacement() -> SimKey {
		SimKey {
			seed: [3; 32],
			pin: None,
			silent_reads: 0,
		}
	}

	fn pin_for(keys: &[SimKey]) -> Option<Zeroizing<String>> {
		keys.iter()
			.find_map(|key| key.pin)
			.map(|pin| Zeroizing::new(pin.to_string()))
	}

	/// Opens a vault file with only `keys` at hand, as Unlock does.
	fn open(file: &[u8], keys: Vec<SimKey>) -> Result<Database, String> {
		let envelope = Envelope::parse(file, COST).map_err(|err| err.to_string())?;
		let pin = pin_for(&keys);
		with_keys(keys, || {
			let derive_copy = |candidate: &Candidate<'_>| -> Derived<SecretMemory, String> {
				let roaming = if candidate.slots.is_empty() {
					None
				} else {
					let cancel = AtomicBool::new(false);
					match keys::roaming_from_keys(candidate.slots, pin.clone(), &cancel) {
						Ok(roaming) => Some(roaming),
						Err(_) => return Derived::Unavailable,
					}
				};
				match derive(candidate.salt, roaming.as_deref()) {
					Ok(key) => Derived::Key(key),
					Err(err) => Derived::Failed(err),
				}
			};
			unlock("drill", Some(envelope), None, COST, derive_copy)
				.map(|opened| opened.database)
				.map_err(|err| err.to_string())
		})
	}

	/// What the window does with a keys screen result.
	fn apply(db: &Database, outcome: KeysOutcome) {
		match outcome {
			KeysOutcome::Added(slot) => {
				let mut slots = keys::slots_of(db);
				slots.push(slot);
				keys::set_slots(db, &slots);
			}
			KeysOutcome::Rekeyed { key, salt, slots } => {
				let key = std::sync::Arc::try_unwrap(key)
					.unwrap_or_else(|_| unreachable!("the ceremony owns its key"));
				db.rekey(key, &salt);
				keys::set_slots(db, &slots);
			}
		}
	}

	fn password_of(db: &Database, name: &str) -> Option<String> {
		db.get_password_entry_by_name(name)
			.map(|entry| entry.get_password().as_str().to_string())
	}

	#[test]
	fn losing_the_daily_key_is_survived_with_the_backup_and_the_lost_key_is_revoked() {
		// Before the loss: a vault protected by a daily and a backup key.
		let db = unlock("drill", None, None, COST, |candidate: &Candidate<'_>| {
			Derived::<_, String>::Key(derive(candidate.salt, None).unwrap())
		})
		.unwrap()
		.database;
		let mut entry = PasswordEntry::new();
		entry.set_name("bank");
		entry.set_password("hunter2");
		db.set_password_entry(entry);
		let protected = with_keys(vec![daily()], || {
			keys::protect(
				&derive,
				&|roaming| verify(&db, roaming),
				pin_for(&[daily()]),
				false,
			)
		})
		.unwrap();
		apply(&db, protected);
		let added = with_keys(vec![daily(), backup()], || {
			keys::add_key(&keys::slots_of(&db), pin_for(&[daily()]), true)
		})
		.unwrap();
		apply(&db, added);
		assert_eq!(keys::slots_of(&db).len(), 2);
		let before = db.encode(true, COST).unwrap();
		assert!(open(&before, vec![daily()]).is_ok(), "the daily key opens");
		assert!(
			open(&before, vec![]).is_err(),
			"the password alone does not"
		);

		// The daily key is lost. The backup alone opens the vault.
		let recovered = open(&before, vec![backup()]).expect("the backup opens");
		assert_eq!(password_of(&recovered, "bank").as_deref(), Some("hunter2"));

		// Remove the lost key: the vault is rekeyed under a fresh secret
		// that only the backup wraps.
		let slots = keys::slots_of(&recovered);
		let removed = with_keys(vec![backup()], || {
			keys::remove_key(
				&derive,
				&|roaming| verify(&recovered, roaming),
				&slots,
				0,
				&[],
				None,
				false,
			)
		})
		.unwrap();
		apply(&recovered, removed);
		assert_eq!(keys::slots_of(&recovered).len(), 1);
		let after = recovered.encode(true, COST).unwrap();
		assert!(
			open(&after, vec![daily()]).is_err(),
			"the lost key no longer opens the rekeyed vault"
		);
		assert!(open(&after, vec![]).is_err());
		let reopened = open(&after, vec![backup()]).expect("the backup still opens");
		assert_eq!(password_of(&reopened, "bank").as_deref(), Some("hunter2"));
		// A copy written before the removal still opens with the lost key,
		// the password and the pepper: old backups of the file stay a risk
		// until they are deleted (ADR 0033, Limits).
		assert!(open(&before, vec![daily()]).is_ok());

		// Enroll a replacement next to the backup.
		let added = with_keys(vec![backup(), replacement()], || {
			keys::add_key(&keys::slots_of(&reopened), None, true)
		})
		.unwrap();
		apply(&reopened, added);
		let restored = reopened.encode(true, COST).unwrap();
		let with_replacement = open(&restored, vec![replacement()]).expect("the replacement opens");
		assert_eq!(
			password_of(&with_replacement, "bank").as_deref(),
			Some("hunter2")
		);
		assert!(open(&restored, vec![backup()]).is_ok());
		assert!(open(&restored, vec![daily()]).is_err());
	}
}
