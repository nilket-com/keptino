//! Vaults written by the Linux application's own code (regenerate with
//! `android/interop/run.sh fixtures`) must open, edit and reopen here.

use droid::{Commit, Error, Source, Vault, crypto, field};

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

fn check(file: &[u8], mem_kib: u32) {
	let name = if mem_kib == crypto::DEBUG_MEM_KIB {
		"vaultdebug"
	} else {
		"vaultrelease"
	};
	let mut vault = Vault::open(name, PASSWORD, &pepper(), Some(file), None, mem_kib).unwrap();
	assert_eq!(vault.source(), Source::Local);
	assert_eq!(vault.meta("db_name").as_deref(), Some(name));
	assert_eq!(vault.names(), ["bank", "mail", "wifi"]);
	assert!(vault.query("bank"));
	assert_eq!(text(&vault, field::USERNAME), "alice");
	assert_eq!(text(&vault, field::PASSWORD), "hunter2 ünïcödé 🔑");
	assert_eq!(text(&vault, field::PIN), "4921");
	assert_eq!(text(&vault, field::NOTE), "Security question: first pet\nAnswer: Rex");
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
	let mut reopened = Vault::open(name, PASSWORD, &pepper(), Some(file), Some(&saved), mem_kib).unwrap();
	assert_eq!(reopened.source(), Source::Remote);
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
fn opens_and_edits_a_linux_debug_vault() {
	check(include_bytes!("fixtures/linux-debug.digisafe"), crypto::DEBUG_MEM_KIB);
}

/// Needs 4 GiB of free memory several times over: `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn opens_and_edits_a_linux_release_vault() {
	check(include_bytes!("fixtures/linux-release.digisafe"), crypto::RELEASE_MEM_KIB);
}

#[test]
#[ignore]
fn derives_the_pepper_of_linux_setup() {
	let derived = crypto::derive_pepper(PEPPER_SEED, crypto::RELEASE_MEM_KIB).unwrap();
	assert_eq!(*derived, pepper());
}
