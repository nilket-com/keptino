//! An offline report on the passwords in a vault: reused, weak, stale and
//! empty. The report names entries and gives figures; nothing from a secret
//! field is in it. Reuse is decided on keyed hashes under a key drawn for the
//! one report, and each password is opened, hashed and wiped before the next
//! is read, so no two plaintexts are in memory together.

use crate::vault::{Database, KeyStore};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// A password estimated below this many bits is weak.
pub const WEAK_BITS: u32 = 50;
/// An entry last edited longer ago than this is stale.
pub const STALE_AFTER_SECONDS: u64 = 365 * 24 * 60 * 60;

/// An entry whose password is estimated below `WEAK_BITS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Weak {
	pub name: String,
	/// The estimate, a ceiling: what a random draw of that shape would have.
	pub bits: u32,
}

/// An entry last edited more than `STALE_AFTER_SECONDS` before the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stale {
	pub name: String,
	/// Seconds since the Unix epoch; any edit advances it.
	pub last_edited: i64,
}

/// The health of one vault at one moment. Names and numbers only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
	pub entries: usize,
	/// Groups of two or more entries sharing one password, by name.
	pub reused: Vec<Vec<String>>,
	pub weak: Vec<Weak>,
	pub stale: Vec<Stale>,
	/// Entries with no password.
	pub empty: Vec<String>,
}

impl Report {
	/// Whether every list is empty.
	pub fn is_clean(&self) -> bool {
		self.reused.is_empty()
			&& self.weak.is_empty()
			&& self.stale.is_empty()
			&& self.empty.is_empty()
	}
}

/// The estimated bits of a password: its length times the base-2 log of the
/// alphabet it draws from, the alphabet being the sum of the classes present.
/// A word or a date scores higher than it deserves; the figure is a ceiling.
pub fn estimate_bits(password: &str) -> u32 {
	if password.is_empty() {
		return 0;
	}
	let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
	for c in password.chars() {
		if c.is_ascii_lowercase() {
			lower = true;
		} else if c.is_ascii_uppercase() {
			upper = true;
		} else if c.is_ascii_digit() {
			digit = true;
		} else {
			other = true;
		}
	}
	let alphabet = [(lower, 26u32), (upper, 26), (digit, 10), (other, 33)]
		.iter()
		.filter(|(on, _)| *on)
		.map(|(_, size)| size)
		.sum::<u32>();
	(password.chars().count() as f64 * f64::from(alphabet).log2()).floor() as u32
}

/// Builds the report for `db` as of `now`, seconds since the Unix epoch.
pub fn report<K: KeyStore>(db: &Database<K>, now: u64) -> Report {
	let mut key = Zeroizing::new([0u8; 32]);
	getrandom::fill(&mut *key).expect("Report key generation failed");
	let mut by_hash: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
	let mut out = Report::default();
	for name in db.names() {
		let Some(entry) = db.get_password_entry_by_name(&name) else {
			continue;
		};
		out.entries += 1;
		let has_password = {
			let password = entry.get_password();
			if password.is_empty() {
				out.empty.push(name.clone());
			} else {
				let bits = estimate_bits(&password);
				if bits < WEAK_BITS {
					out.weak.push(Weak {
						name: name.clone(),
						bits,
					});
				}
				let digest = blake3::keyed_hash(&key, password.as_bytes());
				by_hash
					.entry(*digest.as_bytes())
					.or_default()
					.push(name.clone());
			}
			// `password` is wiped here, before the next entry is opened.
			!password.is_empty()
		};
		// An entry without a password is only empty, however old it is.
		if has_password
			&& let Some(last_edited) = entry.modified()
			&& u64::try_from(last_edited).is_ok_and(|edited| edited + STALE_AFTER_SECONDS < now)
		{
			out.stale.push(Stale { name, last_edited });
		}
	}
	out.reused = by_hash
		.into_values()
		.filter(|names| names.len() > 1)
		.collect();
	// One order: weakest first, oldest first, otherwise by name. Names come
	// from `names()` already sorted, so `empty` and each group are in order.
	out.reused.sort();
	out.weak
		.sort_by(|a, b| (a.bits, &a.name).cmp(&(b.bits, &b.name)));
	out.stale
		.sort_by(|a, b| (a.last_edited, &a.name).cmp(&(b.last_edited, &b.name)));
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::format::FieldAtlas;
	use crate::format::field;
	use crate::vault::{PasswordEntry, tests::HeapKey};

	fn entry(name: &str, password: &str, modified: u64) -> PasswordEntry<HeapKey> {
		let mut fields = FieldAtlas::default();
		fields.set(field::NAME, name.as_bytes());
		if !password.is_empty() {
			fields.set(field::PASSWORD, password.as_bytes());
		}
		fields.set(field::CREATED_TS, modified.to_string().as_bytes());
		fields.set(field::MODIFIED_TS, modified.to_string().as_bytes());
		PasswordEntry::from(fields)
	}

	const NOW: u64 = 2_000_000_000;
	const DAY: u64 = 24 * 60 * 60;

	#[test]
	fn the_estimate_follows_the_classes_present() {
		assert_eq!(estimate_bits(""), 0);
		assert_eq!(estimate_bits("123456"), 19);
		assert_eq!(estimate_bits("password"), 37);
		assert_eq!(estimate_bits("Passw0rd!"), 59);
		assert_eq!(estimate_bits("Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!"), 157);
		assert_eq!(estimate_bits("ñandú"), 29);
	}

	#[test]
	fn the_report_names_reused_weak_stale_and_empty_entries_without_secrets() {
		let db = Database::new(
			HeapKey::from_bytes(&[5; 32]).unwrap(),
			"example",
			&[1; crate::crypto::SALT_SIZE],
		);
		assert_eq!(report(&db, NOW), Report::default());
		assert!(report(&db, NOW).is_clean());

		let strong = crate::generator::password(24);
		db.set_password_entry(entry("bank", "correct-horse-battery", NOW - DAY));
		db.set_password_entry(entry("shop", "correct-horse-battery", NOW - 400 * DAY));
		db.set_password_entry(entry("mail", &strong, NOW - 10 * DAY));
		db.set_password_entry(entry("pin", "123456", NOW - DAY));
		db.set_password_entry(entry("blank", "", NOW - DAY));
		let got = report(&db, NOW);
		assert_eq!(got.entries, 5);
		assert_eq!(
			got.reused,
			vec![vec!["bank".to_string(), "shop".to_string()]]
		);
		assert_eq!(
			got.weak,
			vec![Weak {
				name: "pin".into(),
				bits: 19
			}]
		);
		assert_eq!(
			got.stale,
			vec![Stale {
				name: "shop".into(),
				last_edited: (NOW - 400 * DAY) as i64
			}]
		);
		assert_eq!(got.empty, vec!["blank".to_string()]);
		assert!(!got.is_clean());
		let rendered = format!("{got:?}");
		for secret in ["correct-horse-battery", "123456", strong.as_str()] {
			assert!(!rendered.contains(secret));
		}
	}

	#[test]
	fn reuse_is_decided_per_report_and_a_key_never_repeats_across_them() {
		let db = Database::new(
			HeapKey::from_bytes(&[6; 32]).unwrap(),
			"example",
			&[2; crate::crypto::SALT_SIZE],
		);
		db.set_password_entry(entry("a", "same-password-here", NOW));
		db.set_password_entry(entry("b", "same-password-here", NOW));
		db.set_password_entry(entry("c", "other-password-here", NOW));
		let first = report(&db, NOW);
		let second = report(&db, NOW);
		assert_eq!(first.reused, vec![vec!["a".to_string(), "b".to_string()]]);
		assert_eq!(first, second);
		// A stale entry is one edited longer ago than the threshold, to the second.
		let edge = NOW - STALE_AFTER_SECONDS;
		db.set_password_entry(entry("edge", "x-marks-the-spot-123", edge));
		db.set_password_entry(entry("over", "x-marks-the-spot-124", edge - 1));
		let third = report(&db, NOW);
		let names: Vec<&str> = third.stale.iter().map(|s| s.name.as_str()).collect();
		assert_eq!(names, vec!["over"]);
	}

	#[test]
	fn empty_passwords_are_only_empty_and_a_missing_timestamp_is_not_stale() {
		let db = Database::new(
			HeapKey::from_bytes(&[7; 32]).unwrap(),
			"example",
			&[3; crate::crypto::SALT_SIZE],
		);
		db.set_password_entry(entry("one", "", NOW));
		db.set_password_entry(entry("two", "", NOW - 800 * DAY));
		let mut fields = FieldAtlas::default();
		fields.set(field::NAME, b"legacy");
		fields.set(field::PASSWORD, b"no-timestamps-at-all");
		db.set_password_entry(PasswordEntry::from(fields));
		let got = report(&db, NOW);
		assert_eq!(got.entries, 3);
		assert_eq!(got.empty, vec!["one".to_string(), "two".to_string()]);
		assert!(got.reused.is_empty() && got.weak.is_empty() && got.stale.is_empty());
	}

	#[test]
	fn the_lists_come_out_weakest_and_oldest_first() {
		let db = Database::new(
			HeapKey::from_bytes(&[8; 32]).unwrap(),
			"example",
			&[4; crate::crypto::SALT_SIZE],
		);
		db.set_password_entry(entry("b", "abcdefgh", NOW - 500 * DAY));
		db.set_password_entry(entry("a", "abcdefgh", NOW - 400 * DAY));
		db.set_password_entry(entry("c", "1234", NOW - 600 * DAY));
		let got = report(&db, NOW);
		let weak: Vec<(&str, u32)> = got.weak.iter().map(|w| (w.name.as_str(), w.bits)).collect();
		assert_eq!(weak, vec![("c", 13), ("a", 37), ("b", 37)]);
		let stale: Vec<&str> = got.stale.iter().map(|s| s.name.as_str()).collect();
		assert_eq!(stale, vec!["c", "b", "a"]);
		assert_eq!(got.reused, vec![vec!["a".to_string(), "b".to_string()]]);
	}
}
