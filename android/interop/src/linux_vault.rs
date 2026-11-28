//! Reads and writes a vault with the Linux application's own storage code.
//!
//! The environment decides where that code looks: HOME for the vault and
//! credential files, PATH for `systemd-creds`, HTTPS_PROXY and SSL_CERT_FILE
//! for Backblaze. See run.sh.
//!
//!   linux-vault read <db> <password>           entries as a JSON array
//!   linux-vault write <db> <password> < json   set those entries, then save
//!   linux-vault create <db> <password> < json  create the vault, then as write

use keptino::storage::{Database, PasswordEntry, persistence};
use serde_json::{Map, Value, json};
use std::io::Read;
use zeroize::Zeroizing;

fn entry_json(entry: &PasswordEntry) -> Value {
	json!({
		"name": entry.get_name(),
		"username": entry.get_username(),
		"password": entry.get_password().as_str(),
		"pin": entry.get_pin().as_str(),
		"note": entry.get_note().as_str(),
		"url": entry.get_url(),
		"tags": entry.get_tags(),
	})
}

fn read(db: &Database) -> Value {
	let mut entries = Vec::new();
	let mut name = String::new();
	while let Some(entry) = db.next(&name) {
		name = entry.get_name().to_string();
		entries.push(entry_json(&entry));
	}
	Value::Array(entries)
}

/// What the password screen does on "Set".
fn set(db: &Database, fields: &Map<String, Value>) {
	let text = |key: &str| fields.get(key).and_then(Value::as_str).unwrap_or_default();
	let name = text("name");
	assert!(!name.is_empty(), "Name cannot be empty.");
	let mut entry = db.get_password_entry_by_name(name).unwrap_or_else(|| {
		let mut entry = PasswordEntry::new();
		entry.set_name(name);
		entry
	});
	entry.set_username(text("username"));
	entry.set_password(text("password"));
	entry.set_pin(text("pin"));
	entry.set_url(text("url"));
	entry.set_tags(text("tags"));
	entry.set_note(text("note"));
	db.set_password_entry(entry);
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let [_, command, db_name, password] = args.as_slice() else {
		eprintln!("Usage: linux-vault read|write|create <db> <password>");
		std::process::exit(2);
	};
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	// Unlock never creates (ADR 0018): a new vault is made by `create`,
	// which then writes its entries as `write` does.
	let opened = if command == "create" {
		runtime.block_on(persistence::create(
			db_name,
			Zeroizing::new(password.clone()),
		))
	} else {
		runtime.block_on(persistence::load(
			db_name,
			persistence::UnlockInput {
				password: Zeroizing::new(password.clone()),
				pin: None,
			},
		))
	};
	let vault = match opened {
		Ok(vault) => vault,
		Err(err) => {
			eprintln!("{err}");
			std::process::exit(4);
		}
	};
	match command.as_str() {
		"read" => println!("{}", read(&vault.database)),
		"write" | "create" => {
			let mut input = String::new();
			std::io::stdin().read_to_string(&mut input).unwrap();
			let entries: Vec<Map<String, Value>> = serde_json::from_str(&input).unwrap();
			for fields in &entries {
				set(&vault.database, fields);
			}
			// A harness may change the bucket between the open and the save,
			// to see the save refuse the upload.
			if let Ok(between) = std::env::var("KEPTINO_INTEROP_BETWEEN") {
				let status = std::process::Command::new("sh")
					.arg("-c")
					.arg(between)
					.status()
					.expect("run the between hook");
				assert!(status.success(), "the between hook failed");
			}
			let saved = runtime.block_on(vault.save());
			if saved != "Database saved and synced." {
				eprintln!("{saved}");
				std::process::exit(3);
			}
		}
		_ => std::process::exit(2),
	}
}
