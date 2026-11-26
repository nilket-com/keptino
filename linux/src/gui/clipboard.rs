//! Clipboard copies with a lifetime. A secret placed on the clipboard is
//! wiped when its timeout elapses or the vault locks, but only while the
//! clipboard still holds it: whatever the user copied since is left alone,
//! and the Primary selection, which Keptino never writes, is never touched.
//! The wipe runs on its own thread, so neither the idle lock nor the state
//! change to the unlock screen can cancel it.

use arboard::{
	ClearExtLinux, Clipboard, Error, GetExtLinux, LinuxClipboardKind as Kind, SetExtLinux,
};
use std::{
	sync::{Mutex, MutexGuard},
	thread,
	time::Duration,
};
use zeroize::Zeroizing;

type Hash = blake3::Hash;

/// Hash of the text Keptino last placed on the clipboard while a wipe of it
/// is still owed. Shared by the copy threads and the lock path, so a wipe
/// never clobbers a newer copy and a lock can finish an early one.
static PENDING: Mutex<Option<Hash>> = Mutex::new(None);

fn pending() -> MutexGuard<'static, Option<Hash>> {
	PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Records that a wipe of `hash` is owed, superseding any earlier copy.
fn claim(hash: Hash) {
	*pending() = Some(hash);
}

/// Whether `hash` is still the copy whose wipe is owed.
fn is_owed(hash: Hash) -> bool {
	*pending() == Some(hash)
}

/// Marks the wipe of `hash` done, unless a newer copy has taken over.
fn settle(hash: Hash) {
	let mut guard = pending();
	if *guard == Some(hash) {
		*guard = None;
	}
}

/// Places `value` on the clipboard and wipes it after `timeout` if it is
/// still there.
pub fn copy(value: Zeroizing<String>, timeout: Duration) {
	let hash = blake3::hash(value.as_bytes());
	claim(hash);
	thread::spawn(move || {
		let Ok(mut clipboard) = Clipboard::new() else {
			settle(hash);
			return;
		};
		let _ = clipboard
			.set()
			.clipboard(Kind::Clipboard)
			.exclude_from_history()
			.text(value.as_str());
		drop(value);
		thread::sleep(timeout);
		wipe_if_owed(&mut clipboard, hash);
	});
}

/// Wipes an owed copy now instead of at its timeout. Called on lock.
pub fn clear_pending() {
	let Some(hash) = *pending() else {
		return;
	};
	thread::spawn(move || {
		if let Ok(mut clipboard) = Clipboard::new() {
			wipe_if_owed(&mut clipboard, hash);
		}
	});
}

fn wipe_if_owed(clipboard: &mut Clipboard, hash: Hash) {
	if !is_owed(hash) {
		return;
	}
	if holds(clipboard, hash) {
		wipe(clipboard);
	}
	settle(hash);
}

/// Whether the clipboard still holds our text. An unreadable clipboard is
/// treated as still ours, so a read failure wipes rather than leaks.
fn holds(clipboard: &mut Clipboard, hash: Hash) -> bool {
	match clipboard.get().clipboard(Kind::Clipboard).text() {
		Ok(text) => blake3::hash(Zeroizing::new(text).as_bytes()) == hash,
		Err(Error::ContentNotAvailable) => false,
		Err(_) => true,
	}
}

/// Overwrites the clipboard with random text many times before clearing it,
/// so a manager that ignores the exclusion hint keeps noise, not the secret.
fn wipe(clipboard: &mut Clipboard) {
	for idx in 0..60 {
		let mut noise = [0u8; 16];
		getrandom::fill(&mut noise).expect("Clipboard noise generation failed");
		let munge = format!(
			"KEPTINO_CLIPBOARD_MUNGE_{:03}_{:040}",
			idx,
			u128::from_le_bytes(noise)
		);
		let _ = clipboard
			.set()
			.clipboard(Kind::Clipboard)
			.exclude_from_history()
			.text(munge);
		thread::sleep(Duration::from_millis(4));
	}
	let _ = clipboard.clear_with().clipboard(Kind::Clipboard);
	thread::sleep(Duration::from_millis(200));
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_newer_copy_supersedes_the_wipe_owed_for_an_older_one() {
		let first = blake3::hash(b"first");
		let second = blake3::hash(b"second");
		claim(first);
		assert!(is_owed(first));
		claim(second);
		assert!(!is_owed(first));
		assert!(is_owed(second));
		// The first copy's timer must not settle the second's debt.
		settle(first);
		assert!(is_owed(second));
		settle(second);
		assert!(pending().is_none());
		assert!(!is_owed(second));
	}
}
