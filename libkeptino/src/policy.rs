//! Which copy of a vault to trust. Pure functions over values the head reads
//! from its files and its storage; the head decides what to tell the user.

use crate::format::Envelope;
use std::fmt;

/// Which of two copies to try first: the higher revision when both carry
/// one, else the later modification time, local winning a tie. Both fields
/// are plaintext, so the loser is tried when the winner fails to open.
pub fn prefer_local(local: &Envelope, remote: &Envelope) -> bool {
	match (local.revision, remote.revision) {
		(Some(ours), Some(theirs)) if ours != theirs => ours > theirs,
		_ => local.modified >= remote.modified,
	}
}

/// A copy older than one already opened on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rollback {
	/// The revision of the copy offered; a legacy copy counts as zero.
	pub opened: u64,
	/// The highest revision previously trusted here.
	pub seen: u64,
}

impl fmt::Display for Rollback {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"This copy is revision {}, but revision {} was already opened here.",
			self.opened, self.seen
		)
	}
}

/// Refuses a copy older than one already opened here. A legacy copy carries
/// no revision and counts as zero: once a revision has been trusted, a file
/// from before the revision field is a rollback too.
pub fn check_revision(opened: Option<u64>, last_seen: Option<u64>) -> Result<(), Rollback> {
	match (opened.unwrap_or(0), last_seen) {
		(opened, Some(seen)) if opened < seen => Err(Rollback { opened, seen }),
		_ => Ok(()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::format::KdfParams;

	fn envelope(modified: u64, revision: Option<u64>) -> Envelope {
		Envelope {
			modified,
			revision,
			kdf: KdfParams::DEBUG,
			nonce: [0; 24],
			salt: [0; 32],
			ciphertext: Vec::new(),
			mirror: Vec::new(),
			aad: Vec::new(),
			slots: Vec::new(),
		}
	}

	#[test]
	fn the_newer_revision_is_tried_first_and_older_copies_are_refused() {
		assert!(
			!prefer_local(&envelope(10, None), &envelope(20, None)),
			"later timestamp wins without revisions"
		);
		assert!(
			prefer_local(&envelope(20, None), &envelope(20, None)),
			"local wins a tie"
		);
		assert!(
			prefer_local(&envelope(10, Some(3)), &envelope(20, Some(2))),
			"revision outranks timestamp"
		);
		assert!(
			!prefer_local(&envelope(10, Some(3)), &envelope(20, Some(3))),
			"equal revisions fall back to timestamp"
		);
		assert!(
			!prefer_local(&envelope(10, None), &envelope(20, Some(3))),
			"a legacy copy is compared by timestamp"
		);
		assert_eq!(
			check_revision(Some(2), Some(5)),
			Err(Rollback { opened: 2, seen: 5 })
		);
		assert!(check_revision(Some(5), Some(5)).is_ok());
		assert!(check_revision(Some(6), Some(5)).is_ok());
		assert_eq!(
			check_revision(None, Some(5)),
			Err(Rollback { opened: 0, seen: 5 }),
			"a legacy copy after a trusted revision is a rollback"
		);
		assert!(check_revision(Some(1), None).is_ok());
		assert!(check_revision(None, None).is_ok());
		assert_eq!(
			Rollback { opened: 2, seen: 5 }.to_string(),
			"This copy is revision 2, but revision 5 was already opened here."
		);
	}
}
