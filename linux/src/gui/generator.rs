//! Random passwords. Each character is drawn uniformly from the alphabet by
//! rejection sampling, so no position is biased, and the result is kept in
//! a wiping buffer like every other secret.

use zeroize::Zeroizing;

const ALPHABET: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+[]{}:,.?";
/// 24 characters from an 84-symbol alphabet is about 153 bits, far beyond
/// what the 4 GiB derivation protects on the master password.
pub const LENGTH: usize = 24;

pub fn password(length: usize) -> Zeroizing<String> {
	let mut out = Zeroizing::new(String::with_capacity(length));
	// The largest multiple of the alphabet size below 256 keeps the draw
	// uniform; a byte at or above it is discarded.
	let limit = 256 - (256 % ALPHABET.len());
	let mut draw = Zeroizing::new([0u8; 64]);
	while out.len() < length {
		getrandom::fill(&mut *draw).expect("Password generation failed");
		for byte in draw.iter() {
			if (*byte as usize) < limit && out.len() < length {
				out.push(ALPHABET[*byte as usize % ALPHABET.len()] as char);
			}
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn passwords_have_the_requested_length_and_use_the_alphabet() {
		let first = password(LENGTH);
		let second = password(LENGTH);
		assert_eq!(first.len(), LENGTH);
		assert_ne!(*first, *second);
		assert!(first.bytes().all(|b| ALPHABET.contains(&b)));
		assert!(password(0).is_empty());
		assert_eq!(password(300).len(), 300);
	}
}
