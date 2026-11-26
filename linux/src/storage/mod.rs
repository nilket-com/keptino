mod atlas;
pub mod database;
pub mod entry;
pub mod persistence;
mod remote;
mod secret;

mod protected;

/// Absolute, so a PATH entry under the session's control cannot stand in for
/// the tool that releases the TPM-sealed credentials. The interop harness is
/// the one build that wants exactly that substitution.
pub(crate) const SYSTEMD_CREDS: &str = if cfg!(feature = "harness") {
	"systemd-creds"
} else {
	"/usr/bin/systemd-creds"
};
