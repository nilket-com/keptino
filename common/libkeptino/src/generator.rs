//! Random passwords and passphrases. Every character or word is drawn
//! uniformly by rejection sampling from OS randomness, so no position is
//! biased and the entropy is exactly what `bits` reports. Results are kept
//! in a wiping buffer like every other secret.

pub use crate::wordlist::WORDS;
use zeroize::Zeroizing;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+[]{}:,.?";

/// Default length used by both password editors.
pub const LENGTH: usize = 24;
/// Default word count for a passphrase: about 78 bits.
pub const WORD_COUNT: usize = 6;
/// Longest password `generate` makes.
pub const MAX_LENGTH: usize = 256;
/// Most words `generate` joins.
pub const MAX_WORDS: usize = 32;
/// What separates the words of a passphrase.
pub const SEPARATOR: char = '-';

/// Which character classes a password draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classes {
	pub upper: bool,
	pub lower: bool,
	pub digits: bool,
	pub symbols: bool,
}

impl Classes {
	pub const ALL: Self = Self {
		upper: true,
		lower: true,
		digits: true,
		symbols: true,
	};

	/// Bit 1 uppercase, 2 lowercase, 4 digits, 8 symbols; the JNI shape.
	pub fn from_bits(bits: u8) -> Self {
		Self {
			upper: bits & 1 != 0,
			lower: bits & 2 != 0,
			digits: bits & 4 != 0,
			symbols: bits & 8 != 0,
		}
	}

	fn alphabet(self) -> Vec<u8> {
		let mut out = Vec::with_capacity(UPPER.len() + LOWER.len() + DIGITS.len() + SYMBOLS.len());
		for (on, class) in [
			(self.upper, UPPER),
			(self.lower, LOWER),
			(self.digits, DIGITS),
			(self.symbols, SYMBOLS),
		] {
			if on {
				out.extend_from_slice(class);
			}
		}
		out
	}
}

/// What to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
	Characters { length: usize, classes: Classes },
	Passphrase { words: usize },
}

impl Kind {
	pub const DEFAULT: Self = Self::Characters {
		length: LENGTH,
		classes: Classes::ALL,
	};

	fn is_valid(self) -> bool {
		match self {
			Self::Characters { length, classes } => {
				(1..=MAX_LENGTH).contains(&length) && !classes.alphabet().is_empty()
			}
			Self::Passphrase { words } => (1..=MAX_WORDS).contains(&words),
		}
	}
}

/// Entropy of a `Kind` as `generate` draws it, in bits; zero when the kind
/// would be refused.
pub fn bits(kind: &Kind) -> f64 {
	if !kind.is_valid() {
		return 0.0;
	}
	match *kind {
		Kind::Characters { length, classes } => {
			length as f64 * (classes.alphabet().len() as f64).log2()
		}
		Kind::Passphrase { words } => words as f64 * (WORDS.len() as f64).log2(),
	}
}

/// `bits` rounded down: the figure both heads show.
pub fn whole_bits(kind: &Kind) -> u32 {
	bits(kind).floor() as u32
}

/// Generate a secret of the given kind, or `None` when the kind has no
/// class on or its count is zero or over the bound.
pub fn generate(kind: &Kind) -> Option<Zeroizing<String>> {
	if !kind.is_valid() {
		return None;
	}
	Some(match *kind {
		Kind::Characters { length, classes } => characters(length, &classes.alphabet()),
		Kind::Passphrase { words } => passphrase(words),
	})
}

/// The default kind at the given length.
pub fn password(length: usize) -> Zeroizing<String> {
	characters(length, &Classes::ALL.alphabet())
}

fn characters(length: usize, alphabet: &[u8]) -> Zeroizing<String> {
	let mut out = Zeroizing::new(String::with_capacity(length));
	// The largest multiple of the alphabet size below 256 keeps the draw
	// uniform; a byte at or above it is discarded.
	let limit = 256 - (256 % alphabet.len());
	let mut draw = Zeroizing::new([0u8; 64]);
	while out.len() < length {
		getrandom::fill(&mut *draw).expect("Password generation failed");
		for byte in draw.iter() {
			if (*byte as usize) < limit && out.len() < length {
				out.push(alphabet[*byte as usize % alphabet.len()] as char);
			}
		}
	}
	out
}

fn passphrase(words: usize) -> Zeroizing<String> {
	let mut out = Zeroizing::new(String::with_capacity(words * 10));
	// Two bytes give 65536 outcomes; the largest multiple of 7776 below that
	// keeps every word equally likely, and a value at or above it is discarded.
	let limit = 65536 - (65536 % WORDS.len());
	let mut draw = Zeroizing::new([0u8; 64]);
	let mut chosen = 0;
	while chosen < words {
		getrandom::fill(&mut *draw).expect("Passphrase generation failed");
		for pair in draw.as_chunks::<2>().0 {
			let value = u16::from_le_bytes(*pair) as usize;
			if value < limit && chosen < words {
				if chosen > 0 {
					out.push(SEPARATOR);
				}
				out.push_str(WORDS[value % WORDS.len()]);
				chosen += 1;
			}
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	/// BLAKE3 of the 7776 words joined by newlines, pinned so the table
	/// cannot change silently.
	const WORDLIST_HASH: &str = "7b1b2e0721b74a93fe3f313cd62dd53b2049f9f18068e96eaeacd8ce6faad66d";

	#[test]
	fn passwords_have_the_requested_length_and_use_the_alphabet() {
		let alphabet = Classes::ALL.alphabet();
		let first = password(LENGTH);
		let second = password(LENGTH);
		assert_eq!(first.len(), LENGTH);
		assert_ne!(*first, *second);
		assert!(first.bytes().all(|b| alphabet.contains(&b)));
		assert!(password(0).is_empty());
		assert_eq!(password(300).len(), 300);
		assert_eq!(alphabet.len(), 82);
	}

	#[test]
	fn every_kind_draws_from_exactly_its_alphabet() {
		let digits = Kind::Characters {
			length: 12,
			classes: Classes::from_bits(4),
		};
		let made = generate(&digits).unwrap();
		assert_eq!(made.len(), 12);
		assert!(made.bytes().all(|b| b.is_ascii_digit()));

		let letters = Kind::Characters {
			length: 200,
			classes: Classes::from_bits(1 | 2),
		};
		let made = generate(&letters).unwrap();
		assert_eq!(made.len(), 200);
		assert!(made.bytes().all(|b| b.is_ascii_alphabetic()));

		for _ in 0..50 {
			let phrase = generate(&Kind::Passphrase { words: 6 }).unwrap();
			assert!(is_words(&phrase, 6), "{}", *phrase);
		}
		assert!(is_words(
			&generate(&Kind::Passphrase { words: 1 }).unwrap(),
			1
		));
		assert_eq!(generate(&Kind::DEFAULT).unwrap().len(), LENGTH);
	}

	/// Whether `phrase` is exactly `n` table words joined by the separator.
	/// Four table words contain a hyphen themselves, so this walks the
	/// table rather than splitting.
	fn is_words(phrase: &str, n: usize) -> bool {
		if n == 0 {
			return phrase.is_empty();
		}
		WORDS.iter().any(|w| match phrase.strip_prefix(w) {
			Some("") => n == 1,
			Some(rest) => {
				n > 1
					&& rest
						.strip_prefix(SEPARATOR)
						.is_some_and(|rest| is_words(rest, n - 1))
			}
			None => false,
		})
	}

	#[test]
	fn the_word_matcher_handles_hyphenated_words() {
		assert!(is_words("yo-yo", 1));
		assert!(is_words("yo-yo-t-shirt-abacus", 3));
		assert!(!is_words("yo-yo-t-shirt-abacus", 4));
		assert!(!is_words("abacus-", 1));
		assert!(!is_words("abacus-xyzzy", 2));
		assert!(!is_words("", 1));
	}

	#[test]
	fn impossible_kinds_are_refused() {
		let none = Classes::from_bits(0);
		assert_eq!(
			none,
			Classes {
				upper: false,
				lower: false,
				digits: false,
				symbols: false
			}
		);
		for kind in [
			Kind::Characters {
				length: 10,
				classes: none,
			},
			Kind::Characters {
				length: 0,
				classes: Classes::ALL,
			},
			Kind::Characters {
				length: MAX_LENGTH + 1,
				classes: Classes::ALL,
			},
			Kind::Passphrase { words: 0 },
			Kind::Passphrase {
				words: MAX_WORDS + 1,
			},
		] {
			assert!(generate(&kind).is_none(), "{kind:?}");
			assert_eq!(bits(&kind), 0.0, "{kind:?}");
		}
		assert!(
			generate(&Kind::Characters {
				length: MAX_LENGTH,
				classes: Classes::ALL
			})
			.is_some()
		);
		assert!(generate(&Kind::Passphrase { words: MAX_WORDS }).is_some());
	}

	#[test]
	fn bits_follow_the_draw() {
		assert!((bits(&Kind::DEFAULT) - 24.0 * 82f64.log2()).abs() < 1e-9);
		let digits = Kind::Characters {
			length: 6,
			classes: Classes::from_bits(4),
		};
		assert!((bits(&digits) - 6.0 * 10f64.log2()).abs() < 1e-9);
		assert!((bits(&Kind::Passphrase { words: 6 }) - 6.0 * 7776f64.log2()).abs() < 1e-9);
		assert_eq!(whole_bits(&Kind::Passphrase { words: WORD_COUNT }), 77);
		assert_eq!(whole_bits(&Kind::DEFAULT), 152);
		assert_eq!(whole_bits(&digits), 19);
		assert_eq!(whole_bits(&Kind::Passphrase { words: 0 }), 0);
	}

	#[test]
	fn the_wordlist_is_the_eff_large_list() {
		assert_eq!(WORDS.len(), 7776);
		assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
		assert!(WORDS.iter().all(|w| !w.is_empty()
			&& w.len() <= 9
			&& w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
		let joined = WORDS.join("\n");
		assert_eq!(
			blake3::hash(joined.as_bytes()).to_hex().as_str(),
			WORDLIST_HASH
		);
		// The rejection bound never indexes past the table.
		let limit = 65536 - (65536 % WORDS.len());
		assert_eq!(limit, 62208);
		assert_eq!((limit - 1) % WORDS.len(), WORDS.len() - 1);
	}
}
