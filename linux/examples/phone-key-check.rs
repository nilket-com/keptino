//! Interoperability check with a physical key and the public Android fixture.
//! This uses no settings, production credentials, or network provider.
use keptino::storage::{Database, SecretMemory, keys};
use keptino_core::{
	crypto::derive_master_key,
	format::{Envelope, KdfParams},
	vault::KeyStore,
};
use std::{fs, io::Write, sync::atomic::AtomicBool};
use zeroize::Zeroizing;

fn main() -> Result<(), String> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let (command, path, mut pin) = match args.as_slice() {
		[command, path] => (command, path, None),
		[command, path, flag] if flag == "--pin-stdin" => {
			use std::io::IsTerminal;
			if std::io::stdin().is_terminal() {
				return Err("Pipe the PIN from a password prompt with hidden input".into());
			}
			let mut pin = Zeroizing::new(String::with_capacity(66));
			use std::io::{BufRead, Read};
			let length = std::io::stdin()
				.lock()
				.take(66)
				.read_line(&mut pin)
				.map_err(|e| e.to_string())?;
			if pin.ends_with('\n') {
				pin.pop();
			}
			if length == 66 || pin.is_empty() || pin.len() > 63 {
				return Err("Invalid PIN length".into());
			}
			(command, path, Some(pin))
		}
		_ => return Err("Usage: phone-key-check enroll|unlock FILE [--pin-stdin]".into()),
	};
	let input = match command.as_str() {
		"enroll" => {
			include_bytes!("../../android/droid/tests/fixtures/linux-debug.keptino").to_vec()
		}
		"unlock" => fs::read(path).map_err(|e| e.to_string())?,
		_ => return Err("Expected enroll or unlock".into()),
	};
	let envelope = Envelope::parse(&input, KdfParams::DEBUG).map_err(|e| e.to_string())?;
	if envelope.kdf != KdfParams::DEBUG {
		return Err("Expected the debug-cost test fixture".into());
	}
	let mut pepper = [0; 32];
	hex::decode_to_slice(
		"3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1",
		&mut pepper,
	)
	.unwrap();
	let derive = |salt: &[u8; 32], roaming: Option<&[u8; 32]>| {
		let mut key = Zeroizing::new([0; 32]);
		derive_master_key(
			b"correct horse battery staple",
			&pepper,
			salt,
			roaming,
			envelope.kdf,
			&mut key,
		)
		.map_err(|e| e.to_string())?;
		SecretMemory::from_bytes(&key).map_err(|e| e.to_string())
	};
	let roaming = if command == "unlock" {
		if envelope.slots.is_empty() {
			return Err("Expected a protected phone fixture".into());
		}
		Some(
			keys::roaming_from_keys(&envelope.slots, pin.take(), &AtomicBool::new(false))
				.map_err(|e| e.to_string())?,
		)
	} else {
		None
	};
	let key = derive(&envelope.salt, roaming.as_deref())?;
	let db = Database::open(&envelope, key).map_err(|_| "Could not open fixture")?;
	if db.meta("db_name").as_deref() != Some("vaultdebug") {
		return Err("Unexpected fixture name".into());
	}
	if command == "enroll" {
		let keys::KeysOutcome::Rekeyed { key, salt, slots } = keys::protect(&derive, pin, true)?
		else {
			return Err("Expected a rekey".into());
		};
		db.rekey(std::sync::Arc::into_inner(key).ok_or("shared key")?, &salt);
		keys::set_slots(&db, &slots);
		let bytes = db.encode(false, envelope.kdf).map_err(|e| e.to_string())?;
		fs::File::create_new(path)
			.and_then(|mut file| file.write_all(&bytes))
			.map_err(|e| e.to_string())?;
	}
	println!("Physical key fixture {command} passed.");
	Ok(())
}
