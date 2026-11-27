//! The two-slot fixture of ADR 0011 and the tests that open it: a debug-cost
//! vault whose roaming secret is wrapped for two simulated security keys, a
//! daily key with a PIN holding the verified slot and a backup key without
//! one holding the touch slot. Both heads' harnesses open it the same way.
//! `KEPTINO_WRITE_FIXTURES=1 cargo test -p keptino-fido
//! write_the_two_slot_fixture -- --ignored` rewrites the file; the committed
//! bytes are what every test reads.

use crate::ceremony::{Ceremony, Failure, Outcome, Step};
use crate::sim::{Authenticator, Device, HidDevice, NfcDevice};
use keptino_core::crypto::{self, KEY_SIZE};
use keptino_core::format::{Envelope, KdfParams};
use keptino_core::roaming::{KeySlot, UvMode};
use keptino_core::vault::{
	Candidate, Caution, Database, Derived, KeyStore, MetaEntry, OpenError, PasswordEntry, Source,
	UnlockError, unlock,
};
use std::convert::Infallible;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

pub const FIXTURE_PATH: &str = "../../android/droid/tests/fixtures/linux-debug-fido.keptino";
pub const FIXTURE: &[u8] =
	include_bytes!("../../../android/droid/tests/fixtures/linux-debug-fido.keptino");
/// The daily key: has a PIN, holds slot 1 in verified mode.
pub const KEY_SEED: [u8; 32] = *b"keptino-fixture-security-key-001";
pub const KEY_PIN: &str = "1234";
/// The backup key: no PIN, holds slot 2 in touch-only mode.
pub const BACKUP_SEED: [u8; 32] = *b"keptino-fixture-security-key-002";
pub const PASSWORD: &[u8] = b"correct horse battery staple";
/// The same pepper as every other committed fixture (manifest.json).
pub const PEPPER_HEX: &str = "3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1";
pub const DB_NAME: &str = "vaultfido";
const ROAMING: [u8; 32] = [0x33; 32];

/// A heap key store for the tests of this crate.
pub struct TestKey(Mutex<Zeroizing<[u8; KEY_SIZE]>>);

impl KeyStore for TestKey {
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

fn pepper() -> [u8; 32] {
	let mut pepper = [0u8; 32];
	hex::decode_to_slice(PEPPER_HEX, &mut pepper).unwrap();
	pepper
}

/// The master key for a copy, with or without a roaming secret.
pub fn derive(salt: &[u8; 32], cost: KdfParams, roaming: Option<&[u8; 32]>) -> TestKey {
	let mut key = Zeroizing::new([0u8; KEY_SIZE]);
	crypto::derive_master_key(PASSWORD, &pepper(), salt, roaming, cost, &mut key).unwrap();
	TestKey::from_bytes(&key).unwrap()
}

/// A head's derive closure with a security key present: run the assert
/// ceremony over the candidate's slots, then derive with the secret. The
/// counter records how many times the Argon2 arena was entered.
pub fn derive_with_key<'a>(
	device: &'a mut Device,
	pin: Option<&'a str>,
	derivations: &'a std::cell::Cell<u32>,
) -> impl FnMut(&Candidate<'_>) -> Derived<TestKey, Infallible> + 'a {
	move |candidate| {
		if candidate.slots.is_empty() {
			derivations.set(derivations.get() + 1);
			return Derived::Key(derive(candidate.salt, candidate.cost, None));
		}
		let (mut ceremony, step) = Ceremony::assert(device.transport(), candidate.slots.to_vec());
		match device.drive(&mut ceremony, step, pin) {
			Step::Done(Outcome::Asserted { roaming, .. }) => {
				derivations.set(derivations.get() + 1);
				Derived::Key(derive(candidate.salt, candidate.cost, Some(&roaming)))
			}
			Step::Failed(Failure::Canceled) => Derived::Canceled,
			_ => Derived::Unavailable,
		}
	}
}

fn parse(file: &[u8]) -> Envelope {
	Envelope::parse(file, KdfParams::DEBUG).unwrap()
}

fn enroll(device: &mut Device, uv_mode: UvMode, pin: Option<&str>) -> KeySlot {
	let (mut ceremony, step) =
		Ceremony::enroll(device.transport(), uv_mode, Zeroizing::new(ROAMING));
	match device.drive(&mut ceremony, step, pin) {
		Step::Done(Outcome::Enrolled(slot)) => slot,
		other => panic!("{other:?}"),
	}
}

fn daily() -> Device {
	Device::Hid(HidDevice::new(
		Authenticator::new(KEY_SEED).with_pin(KEY_PIN),
	))
}

fn backup() -> Device {
	Device::Nfc(NfcDevice::new(Authenticator::new(BACKUP_SEED)))
}

/// Writes the fixture. Ignored: the committed bytes are the fixture, and
/// rewriting them is a deliberate act with a new decision behind it.
#[test]
#[ignore = "rewrites the committed fixture"]
fn write_the_two_slot_fixture() {
	if std::env::var_os("KEPTINO_WRITE_FIXTURES").is_none() {
		return;
	}
	let verified = enroll(&mut daily(), UvMode::Verified, Some(KEY_PIN));
	let touch = enroll(&mut backup(), UvMode::TouchOnly, None);
	let salt = *b"fixture-salt-for-adr-0011-vault!";
	let db = Database::new(
		derive(&salt, KdfParams::DEBUG, Some(&ROAMING)),
		DB_NAME,
		&salt,
	);
	for (index, slot) in [verified, touch].iter().enumerate() {
		db.set_meta_entry(MetaEntry::new(&KeySlot::entry_name(index), &slot.encode()));
	}
	for (name, username, password, url) in [
		(
			"bank",
			"alice",
			"hunter2 ünïcödé 🔑",
			"https://bank.example",
		),
		(
			"mail",
			"alice@example.com",
			"a long passphrase here",
			"https://mail.example",
		),
	] {
		let mut entry = PasswordEntry::new();
		entry.set_name(name);
		entry.set_username(username);
		entry.set_password(password);
		entry.set_url(url);
		db.set_password_entry(entry);
	}
	let file = db.encode(false, KdfParams::DEBUG).unwrap();
	std::fs::write(FIXTURE_PATH, &file).unwrap();
	eprintln!("wrote {} bytes to {FIXTURE_PATH}", file.len());
}

#[test]
fn the_fixture_opens_with_either_key_and_refuses_others_before_the_arena() {
	let envelope = parse(FIXTURE);
	assert_eq!(envelope.slots.len(), 2);
	assert_eq!(envelope.slots[0].uv_mode, UvMode::Verified);
	assert_eq!(envelope.slots[1].uv_mode, UvMode::TouchOnly);
	assert_ne!(envelope.slots[0].cred_id, envelope.slots[1].cred_id);

	// Both keys see the whole slot list, as a head hands it over. The daily
	// key opens slot 1 with its PIN over HID; the backup key, which cannot
	// verify a user, passes over slot 1 and opens slot 2 over NFC.
	for (mut device, pin) in [(daily(), Some(KEY_PIN)), (backup(), None)] {
		let derivations = std::cell::Cell::new(0);
		let opened = unlock(
			DB_NAME,
			Some(parse(FIXTURE)),
			None,
			KdfParams::DEBUG,
			derive_with_key(&mut device, pin, &derivations),
		)
		.unwrap();
		assert_eq!(opened.source, Source::Local);
		assert_eq!(derivations.get(), 1);
		assert_eq!(
			opened.database.names(),
			vec!["bank".to_string(), "mail".to_string()]
		);
		let bank = opened.database.get_password_entry_by_name("bank").unwrap();
		assert_eq!(bank.get_password().as_str(), "hunter2 ünïcödé 🔑");
		opened.database.zeroize();
	}

	// An unenrolled key: no credential, no arena.
	let derivations = std::cell::Cell::new(0);
	let mut stranger = Device::Hid(HidDevice::new(
		Authenticator::new([7; 32]).with_pin(KEY_PIN),
	));
	assert_eq!(
		unlock(
			DB_NAME,
			Some(parse(FIXTURE)),
			None,
			KdfParams::DEBUG,
			derive_with_key(&mut stranger, Some(KEY_PIN), &derivations)
		)
		.err(),
		Some(UnlockError::Unavailable)
	);
	assert_eq!(derivations.get(), 0);

	// The daily key with its slot's mode flipped: the tag fails, no arena.
	let mut flipped = parse(FIXTURE);
	flipped.slots.truncate(1);
	flipped.slots[0].uv_mode = UvMode::TouchOnly;
	let mut device = daily();
	assert_eq!(
		unlock(
			DB_NAME,
			Some(flipped),
			None,
			KdfParams::DEBUG,
			derive_with_key(&mut device, Some(KEY_PIN), &derivations)
		)
		.err(),
		Some(UnlockError::Unavailable)
	);
	assert_eq!(derivations.get(), 0);

	// Stripped of its slots the file does not open with the password alone,
	// though the legacy derivation runs once.
	let mut stripped = parse(FIXTURE);
	stripped.slots.clear();
	assert_eq!(
		unlock(
			DB_NAME,
			Some(stripped),
			None,
			KdfParams::DEBUG,
			derive_with_key(&mut device, None, &derivations)
		)
		.err(),
		Some(UnlockError::Open(OpenError::Decryption))
	);
	assert_eq!(derivations.get(), 1);
}

#[test]
fn a_local_and_a_remote_copy_with_different_slot_sets_and_a_cancellation() {
	// The remote copy carries only the daily key's slot, as if the backup
	// key had been enrolled on this machine and not yet synced.
	let full = parse(FIXTURE);
	let remote_file = {
		let db = Database::open(&full, derive(&full.salt, KdfParams::DEBUG, Some(&ROAMING)))
			.map_err(|(_, e)| e)
			.unwrap();
		db.remove_meta_entry(&KeySlot::entry_name(1));
		db.encode(false, KdfParams::DEBUG).unwrap()
	};
	let remote = parse(&remote_file);
	assert_eq!(remote.slots.len(), 1);
	assert!(remote.revision > full.revision);

	// The backup key: the remote copy (newer, preferred) has no slot it
	// owns, so the local copy opens and uploads pause.
	let derivations = std::cell::Cell::new(0);
	let mut device = backup();
	let opened = unlock(
		DB_NAME,
		Some(parse(FIXTURE)),
		Some(parse(&remote_file)),
		KdfParams::DEBUG,
		derive_with_key(&mut device, None, &derivations),
	)
	.unwrap();
	assert_eq!(opened.source, Source::Local);
	assert_eq!(
		opened.caution,
		Some(Caution::OtherCopyFailed(Source::Remote))
	);
	assert_eq!(derivations.get(), 1);
	opened.database.zeroize();

	// Declining the PIN on the preferred copy cancels the unlock outright,
	// although the other copy is present and would have opened.
	let derivations = std::cell::Cell::new(0);
	let mut device = daily();
	assert_eq!(
		unlock(
			DB_NAME,
			Some(parse(FIXTURE)),
			Some(parse(&remote_file)),
			KdfParams::DEBUG,
			derive_with_key(&mut device, None, &derivations),
		)
		.err(),
		Some(UnlockError::Canceled)
	);
	assert_eq!(derivations.get(), 0);
}
