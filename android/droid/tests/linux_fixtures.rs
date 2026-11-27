//! Vaults written by the Linux application's own code (regenerate with
//! `android/interop/run.sh fixtures`) must open, edit and reopen here.

use droid::{Commit, Error, Source, Vault, field, security};
use libkeptino::fido::sim::{Device, HidDevice, NfcDevice};
use libkeptino::format::KdfParams;
use libkeptino::roaming::UvMode;
use libkeptino::vault::KeyStore;

#[path = "support/fido.rs"]
mod fixture_key;

const PASSWORD: &[u8] = b"correct horse battery staple";
const PEPPER_SEED: &[u8] = b"digisafe test pepper seed";
const PEPPER_HEX: &str = "3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1";

fn pepper() -> [u8; 32] {
	let mut pepper = [0u8; 32];
	hex::decode_to_slice(PEPPER_HEX, &mut pepper).unwrap();
	pepper
}

fn text(vault: &Vault, id: u8) -> String {
	String::from_utf8(vault.get_field(id).unwrap().to_vec()).unwrap()
}

fn check(file: &[u8], name: &str, mem_kib: u32, initial_revision: u64) {
	let mut vault = Vault::open(name, PASSWORD, &pepper(), Some(file), None, mem_kib).unwrap();
	assert_eq!(vault.source(), Source::Local);
	assert_eq!(vault.revision(), initial_revision);
	assert_eq!(vault.meta("db_name").as_deref(), Some(name));
	assert_eq!(vault.names(), ["bank", "mail", "wifi"]);
	assert!(vault.query("bank"));
	assert_eq!(text(&vault, field::USERNAME), "alice");
	assert_eq!(text(&vault, field::PASSWORD), "hunter2 ünïcödé 🔑");
	assert_eq!(text(&vault, field::PIN), "4921");
	assert_eq!(
		text(&vault, field::NOTE),
		"Security question: first pet\nAnswer: Rex"
	);
	assert_eq!(text(&vault, field::URL), "https://bank.example");
	assert_eq!(text(&vault, field::TAGS), "money, work");
	let created = text(&vault, field::CREATED_TS);
	assert!(created.parse::<u64>().unwrap() > 1_700_000_000);
	assert!(vault.query("work.2"));
	assert_eq!(text(&vault, field::NAME), "mail");
	assert!(vault.query("home"));
	assert_eq!(text(&vault, field::NAME), "wifi");

	assert!(vault.query("bank"));
	vault.set_field(field::PASSWORD, b"replaced").unwrap();
	assert_eq!(vault.commit(), Commit::Updated);
	let before = vault.modified_ts();
	let saved = vault.save().unwrap();
	let mut reopened =
		Vault::open(name, PASSWORD, &pepper(), Some(file), Some(&saved), mem_kib).unwrap();
	assert_eq!(reopened.source(), Source::Remote);
	assert_eq!(reopened.revision(), initial_revision + 1);
	assert!(
		reopened.meta("format").is_none(),
		"every save uses the unmarked form"
	);
	assert!(reopened.modified_ts() > before);
	assert!(reopened.query("bank"));
	assert_eq!(text(&reopened, field::PASSWORD), "replaced");
	assert_eq!(text(&reopened, field::PIN), "4921");
	assert_eq!(text(&reopened, field::CREATED_TS), created);
	assert_eq!(reopened.names(), ["bank", "mail", "wifi"]);

	assert_eq!(
		Vault::open(name, b"wrong", &pepper(), Some(file), None, mem_kib).err(),
		Some(Error::Decryption)
	);
}

#[test]
fn opens_the_two_slot_fixture_with_either_enrolled_key() {
	use fixture_key::{FILE, PIN, assert_slots, backup_key, daily_key};

	for (mut device, index, mode, pin) in [
		(
			Device::Hid(HidDevice::new(daily_key())),
			0,
			UvMode::Verified,
			Some(PIN),
		),
		(
			Device::Nfc(NfcDevice::new(backup_key())),
			1,
			UvMode::TouchOnly,
			None,
		),
	] {
		let mut vault = Vault::open_with_security_key(
			"vaultfido",
			PASSWORD,
			&pepper(),
			Some(FILE),
			None,
			KdfParams::DEBUG,
			|candidate| {
				assert_eq!(candidate.slots.len(), 2);
				let slot = &candidate.slots[index];
				assert_eq!(slot.uv_mode, mode);
				assert_slots(&mut device, candidate.slots, pin, index)
			},
		)
		.unwrap();
		assert_eq!(vault.source(), Source::Local);
		assert_eq!(vault.revision(), 1);
		assert_eq!(vault.meta("db_name").as_deref(), Some("vaultfido"));
		assert_eq!(vault.names(), ["bank", "mail"]);
		for (entry, user, password, url) in [
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
			assert!(vault.query(entry));
			assert_eq!(text(&vault, field::USERNAME), user);
			assert_eq!(text(&vault, field::PASSWORD), password);
			assert_eq!(text(&vault, field::URL), url);
		}
	}
}

#[test]
fn opens_and_edits_a_linux_debug_vault() {
	check(
		include_bytes!("fixtures/linux-debug.keptino"),
		"vaultdebug",
		KdfParams::DEBUG.m_cost,
		0,
	);
	check(
		include_bytes!("fixtures/linux-debug-v2.keptino"),
		"vaultdebug-v2",
		KdfParams::RELEASE.m_cost,
		1,
	);
	check(
		include_bytes!("fixtures/linux-debug-unmarked.keptino"),
		"vaultdebug-unmarked",
		KdfParams::RELEASE.m_cost,
		1,
	);
}

/// Needs 4 GiB of free memory several times over: `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn opens_and_edits_a_linux_release_vault() {
	check(
		include_bytes!("fixtures/linux-release.keptino"),
		"vaultrelease",
		KdfParams::RELEASE.m_cost,
		0,
	);
	check(
		include_bytes!("fixtures/linux-release-v2.keptino"),
		"vaultrelease-v2",
		KdfParams::DEBUG.m_cost,
		1,
	);
	check(
		include_bytes!("fixtures/linux-release-unmarked.keptino"),
		"vaultrelease-unmarked",
		KdfParams::DEBUG.m_cost,
		1,
	);
}

#[test]
#[ignore]
fn derives_the_pepper_of_linux_setup() {
	let derived = security::derive_pepper(PEPPER_SEED, KdfParams::RELEASE.m_cost).unwrap();
	derived.with_key(|key| assert_eq!(key, &pepper()));
}
