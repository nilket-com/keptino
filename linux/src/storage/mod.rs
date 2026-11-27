pub mod keys;
pub mod persistence;
mod remote;
mod secret;

pub use keptino_core::vault::MetaEntry;
pub use secret::SecretMemory;

/// The core's vault model over `memfd_secret` key storage.
pub type Database = keptino_core::vault::Database<SecretMemory>;
pub type PasswordEntry = keptino_core::vault::PasswordEntry<SecretMemory>;

/// Absolute, so a PATH entry under the session's control cannot stand in for
/// the tool that releases the TPM-sealed credentials. The interop harness is
/// the one build that wants exactly that substitution.
pub(crate) const SYSTEMD_CREDS: &str = if cfg!(feature = "harness") {
	"systemd-creds"
} else {
	"/usr/bin/systemd-creds"
};

/// A database under a fixed key, for tests of the screens and the save path.
#[cfg(test)]
pub(crate) fn test_database() -> Database {
	use keptino_core::vault::KeyStore;
	let key = SecretMemory::from_bytes(&[42; 32]).unwrap();
	Database::new(key, "example", &[42; 32])
}
