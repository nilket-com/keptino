use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// The vault file is damaged beyond what erasure coding can repair,
	/// or is not a Keptino vault.
	Corrupt(&'static str),
	/// Authentication failed: wrong password or pepper, or altered data.
	Decryption,
	/// None of the candidate's security-key slots could be opened.
	SecurityKeyUnavailable,
	DifferentVault,
	SecurityKey(libkeptino::fido::ceremony::Failure),
	/// A caller-supplied argument is unusable.
	Invalid(&'static str),
	/// Key derivation could not run, typically for lack of memory.
	Kdf(String),
	/// Locked key memory could not be set up.
	Memory(&'static str),
	/// The process is traced, instrumented or loaded through an injector.
	/// The application refuses to run, as the Linux application exits.
	Security(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Error::Corrupt(what) => write!(f, "Corrupt vault: {what}."),
			Error::Decryption => write!(f, "Decryption failure."),
			Error::SecurityKeyUnavailable => write!(f, "Security key unavailable."),
			Error::DifferentVault => write!(
				f,
				"The local and bucket copies have different salts. To keep the local copy as a generation and open the bucket copy, choose Adopt bucket copy."
			),
			Error::SecurityKey(failure) => write!(f, "{failure}"),
			Error::Invalid(what) => write!(f, "Invalid argument: {what}."),
			Error::Kdf(what) => write!(f, "Key derivation failure: {what}."),
			Error::Memory(what) => write!(f, "Memory failure: {what}."),
			Error::Security(what) => write!(f, "SECURITY VIOLATION: {what}."),
		}
	}
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl From<libkeptino::format::FormatError> for Error {
	fn from(error: libkeptino::format::FormatError) -> Self {
		use libkeptino::format::FormatError;
		match error {
			FormatError::Damaged => Error::Corrupt("damaged vault"),
			FormatError::TooLarge => Error::Invalid("vault exceeds the size budget"),
			FormatError::NewerFormat(_) => {
				Error::Invalid("unsupported vault format; update Keptino")
			}
		}
	}
}

impl From<libkeptino::crypto::KdfError> for Error {
	fn from(error: libkeptino::crypto::KdfError) -> Self {
		match error {
			libkeptino::crypto::KdfError::EmptySeed => Error::Invalid("empty pepper seed"),
			other => Error::Kdf(other.to_string()),
		}
	}
}

impl From<libkeptino::fido::ceremony::Failure> for Error {
	fn from(failure: libkeptino::fido::ceremony::Failure) -> Self {
		Self::SecurityKey(failure)
	}
}
