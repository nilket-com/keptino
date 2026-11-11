//! Reads and writes a vault file with the Android core, on the host.
//!
//!   android-vault read <file> <password> <pepper-hex> <mem-kib>
//!   android-vault write <file> <password> <pepper-hex> <mem-kib> < json
//!
//! `write` sets the given entries the way the app does and rewrites the
//! file in place; a missing file is a new database named after it.

use droid::{Commit, Vault, field};
use serde_json::{Map, Value, json};
use std::{io::Read, path::Path};

const FIELDS: [(&str, u8); 7] = [
	("name", field::NAME),
	("username", field::USERNAME),
	("password", field::PASSWORD),
	("pin", field::PIN),
	("note", field::NOTE),
	("url", field::URL),
	("tags", field::TAGS),
];

fn working_entry(vault: &Vault) -> Value {
	let mut entry = Map::new();
	for (key, id) in FIELDS {
		let value = vault.get_field(id).unwrap();
		entry.insert(key.into(), json!(String::from_utf8(value.to_vec()).unwrap()));
	}
	Value::Object(entry)
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let [_, command, file, password, pepper, mem_kib] = args.as_slice() else {
		eprintln!("Usage: android-vault read|write <file> <password> <pepper-hex> <mem-kib>");
		std::process::exit(2);
	};
	let path = Path::new(file);
	let mut pepper_bytes = [0u8; 32];
	hex::decode_to_slice(pepper.trim(), &mut pepper_bytes).expect("pepper is 64 hex characters");
	let db_name = path.file_stem().unwrap().to_str().unwrap();
	let local = std::fs::read(path).ok();
	let mut vault = Vault::open(
		db_name,
		password.as_bytes(),
		&pepper_bytes,
		local.as_deref(),
		None,
		mem_kib.parse().expect("memory in KiB"),
	)
	.unwrap_or_else(|error| {
		eprintln!("{error}");
		std::process::exit(1);
	});
	match command.as_str() {
		"read" => {
			let mut entries = Vec::new();
			vault.clear();
			while vault.next() {
				entries.push(working_entry(&vault));
			}
			println!("{}", Value::Array(entries));
		}
		"write" => {
			let mut input = String::new();
			std::io::stdin().read_to_string(&mut input).unwrap();
			let entries: Vec<Map<String, Value>> = serde_json::from_str(&input).unwrap();
			for fields in &entries {
				let name = fields.get("name").and_then(Value::as_str).unwrap_or_default();
				// Start from the stored entry, as the app does after a query.
				vault.query(name);
				for (key, id) in FIELDS {
					if let Some(value) = fields.get(key).and_then(Value::as_str) {
						vault.set_field(id, value.as_bytes()).unwrap();
					}
				}
				assert_ne!(vault.commit(), Commit::EmptyName, "Name cannot be empty.");
			}
			let bytes = vault.save().unwrap();
			let temporary = path.with_extension("digisafe.part");
			std::fs::write(&temporary, bytes).unwrap();
			std::fs::rename(&temporary, path).unwrap();
		}
		_ => std::process::exit(2),
	}
}
