//! The command line form of the binary. `keptino --derive-pepper` replaces
//! the external `argon2` tool that setup used to derive the pepper from the
//! seed: same input, same derivation, same output framing, but with the
//! seed and the arena in locked, non-dumpable memory and wiped afterwards.

use keptino_core::crypto::{self, PEPPER_SIZE};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// The memory the pepper derivation has always used: 4 GiB, in KiB.
pub const PEPPER_MEM_KIB: u32 = 1 << 22;
/// The longest seed the `argon2` tool accepted; a longer one it refused, so
/// no credential was ever derived from one.
pub const MAX_SEED_BYTES: usize = 127;

const USAGE: &str = "Usage: keptino [--derive-pepper]\n  With no argument, opens the vault window.\n  --derive-pepper reads the seed from standard input and writes the pepper as hex.";

/// Runs the command line form named by `args`, returning its exit status, or
/// `None` when there is no argument and the GUI should start.
pub fn run(args: &[String]) -> Option<i32> {
	match args {
		[] => None,
		[flag] if flag == "--derive-pepper" => {
			crate::security::preflight_command_line();
			// Sized once, so the seed never moves to a larger buffer unwiped.
			let mut seed = Zeroizing::new(Vec::with_capacity(MAX_SEED_BYTES + 1));
			if io::stdin()
				.lock()
				.take(MAX_SEED_BYTES as u64 + 1)
				.read_to_end(&mut seed)
				.is_err()
			{
				eprintln!("The seed could not be read.");
				return Some(1);
			}
			let stdout = io::stdout();
			let mut out = stdout.lock();
			match derive_pepper(&seed, PEPPER_MEM_KIB, &mut out) {
				Ok(()) => Some(0),
				Err(err) => {
					eprintln!("{err}");
					Some(1)
				}
			}
		}
		_ => {
			eprintln!("{USAGE}");
			Some(2)
		}
	}
}

/// Derives the pepper from `seed` at `mem_kib` and writes it as 64 lowercase
/// hex characters and a newline, the framing of `argon2 -r`. The seed is
/// used byte for byte, newline included, as the tool used it, and a seed
/// longer than the tool accepted is refused as the tool refused it.
pub fn derive_pepper(seed: &[u8], mem_kib: u32, out: &mut impl Write) -> Result<(), String> {
	if seed.is_empty() {
		return Err("No seed read.".into());
	}
	if seed.len() > MAX_SEED_BYTES {
		return Err(format!("The seed is longer than {MAX_SEED_BYTES} bytes."));
	}
	let mut pepper = Zeroizing::new([0u8; PEPPER_SIZE]);
	crypto::derive_pepper(seed, mem_kib, &mut pepper)
		.map_err(|err| format!("Pepper derivation failed: {err}"))?;
	// Encoded in place: no temporary string carries the pepper.
	let mut line = Zeroizing::new([0u8; PEPPER_SIZE * 2 + 1]);
	hex::encode_to_slice(*pepper, &mut line[..PEPPER_SIZE * 2]).expect("64 hex characters fit");
	line[PEPPER_SIZE * 2] = b'\n';
	out.write_all(&*line)
		.and_then(|()| out.flush())
		.map_err(|err| format!("The pepper could not be written: {err}"))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// `printf 'correct horse' | argon2 digipepper -id -t 4 -m 12 -p 1 -l 32 -r -v 13`
	const LOW_COST_VECTOR: &str = include_str!("../../android/droid/tests/fixtures/pepper_m12.hex");

	#[test]
	fn the_pepper_is_written_as_the_argon2_tool_wrote_it() {
		let mut out = Vec::new();
		derive_pepper(b"correct horse", 4096, &mut out).unwrap();
		assert_eq!(out, format!("{}\n", LOW_COST_VECTOR.trim()).into_bytes());
		assert_eq!(out.len(), 65);

		let mut with_newline = Vec::new();
		derive_pepper(b"correct horse\n", 4096, &mut with_newline).unwrap();
		assert_ne!(with_newline, out, "a trailing newline is part of the seed");

		let mut none = Vec::new();
		assert_eq!(
			derive_pepper(b"", 4096, &mut none),
			Err("No seed read.".to_string())
		);
		assert!(none.is_empty());

		// 127 bytes is the most the tool took; 128 it refused.
		let mut longest = Vec::new();
		derive_pepper(&[b'0'; MAX_SEED_BYTES], 4096, &mut longest).unwrap();
		assert_eq!(longest.len(), 65);
		assert_eq!(
			derive_pepper(&[b'0'; MAX_SEED_BYTES + 1], 4096, &mut none),
			Err("The seed is longer than 127 bytes.".to_string())
		);
		assert!(none.is_empty());
	}

	#[test]
	fn only_the_one_flag_is_a_command_line_form() {
		assert_eq!(run(&[]), None);
		assert_eq!(run(&["--help".to_string()]), Some(2));
		assert_eq!(
			run(&["--derive-pepper".to_string(), "extra".to_string()]),
			Some(2)
		);
	}

	/// The installed cost against the tool this replaces, on a host that has
	/// it: `cargo test -p keptino --release -- --ignored installed_cost`.
	#[test]
	#[ignore = "4 GiB and the external argon2 tool"]
	fn the_installed_cost_matches_the_argon2_tool() {
		use std::process::{Command, Stdio};
		let seed = b"correct horse battery staple";
		let mut child = Command::new("argon2")
			.args([
				"digipepper",
				"-id",
				"-t",
				"4",
				"-m",
				"22",
				"-p",
				"1",
				"-l",
				"32",
				"-r",
				"-v",
				"13",
			])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.expect("the argon2 tool is installed");
		child.stdin.take().unwrap().write_all(seed).unwrap();
		let tool = child.wait_with_output().unwrap();
		assert!(tool.status.success());
		let mut ours = Vec::new();
		derive_pepper(seed, PEPPER_MEM_KIB, &mut ours).unwrap();
		assert_eq!(ours, tool.stdout);
	}
}
