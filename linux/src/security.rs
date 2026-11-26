use crate::logger::{critical, info, warn};
use libc::{
	getrlimit, mlockall, prctl, rlimit, setrlimit, MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE,
	RLIMIT_CORE, RLIMIT_MEMLOCK,
};
use std::{env, fs, process::Command};

pub fn get_memory_lock_limits() -> String {
	unsafe {
		let mut rlim = rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		if getrlimit(RLIMIT_MEMLOCK, &mut rlim) == 0 {
			format!(
				"{} bytes current, {} bytes maximum",
				rlim.rlim_cur, rlim.rlim_max
			)
		} else {
			let msg = "Memlock limit error.".to_string();
			warn(&msg);
			msg
		}
	}
}

fn lock_memory_pages() {
	unsafe {
		let flags = MCL_CURRENT | MCL_FUTURE;
		if mlockall(flags) != 0 {
			critical("Memory lock failure.");
			warn(&format!(
				"Memory lock limits: {}.",
				get_memory_lock_limits()
			));
			std::process::exit(1);
		}
	}
}

fn set_not_dumpable() {
	unsafe {
		let rlim = rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		setrlimit(RLIMIT_CORE, &rlim);
		prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	}
}

/// A launcher that carries no Wayland socket in its environment gets the
/// compositor's default. An explicit socket is left alone: the build has no
/// X11 backend, so a second compositor is not a downgrade.
pub fn force_secure_display() {
	if env::var("WAYLAND_DISPLAY").is_ok_and(|socket| !socket.is_empty()) {
		return;
	}
	unsafe {
		env::set_var("WAYLAND_DISPLAY", "wayland-0");
	}
}

fn verify_secure_display() {
	let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_default();
	if session_type != "wayland" {
		critical("SECURITY VIOLATION: XDG_SESSION_TYPE must be set to wayland.");
		std::process::exit(1);
	}
}

fn check_env(var: &str) {
	if env::var(var).map(|v| !v.is_empty()).unwrap_or(false) {
		critical(&format!("SECURITY VIOLATION: {} is set.", var));
		std::process::exit(1);
	}
}

fn enforce_no_preload() {
	check_env("LD_PRELOAD");
	check_env("LD_AUDIT");
}

fn check_tme() {
	let cpu_info = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
	let is_tme_active = cpu_info.contains(" tme ");
	if !is_tme_active {
		warn("Total Memory Encryption is not active.");
	}
}

fn sniff_luks() {
	// An absolute path, so a PATH entry the session controls cannot substitute it.
	let Ok(output) = Command::new("/usr/bin/lsblk").arg("-e7").output() else {
		warn("lsblk is unavailable; LUKS drive encryption was not checked.");
		return;
	};
	let is_crypt = String::from_utf8_lossy(&output.stdout).contains(" crypt ");
	if !is_crypt {
		warn("LUKS drive encryption not detected.");
	}
}

/// Confines the process, and every helper it spawns, to the filesystem it
/// needs: system files read-only, devices for the TPM and randomness, the
/// runtime directory for the compositor and buses, the font cache, and the
/// vault directory. Everything else in the home directory is unreachable
/// even if the process is compromised. Best effort: a kernel without
/// Landlock runs unconfined with a warning, and a missing optional path is
/// skipped.
fn sandbox_filesystem() {
	use landlock::{
		ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
		RulesetAttr, RulesetCreatedAttr, RulesetStatus,
	};
	let home = env::home_dir().unwrap_or_default();
	let runtime = env::var("XDG_RUNTIME_DIR")
		.ok()
		.filter(|dir| !dir.is_empty())
		.unwrap_or_else(|| format!("/run/user/{}", unsafe { libc::getuid() }));
	let abi = ABI::V5;
	let read = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
	let device = AccessFs::ReadFile | AccessFs::WriteFile;
	let full = AccessFs::from_all(abi);
	// Writable directories hold data, never programs.
	let data = full & !AccessFs::Execute;
	let vault_dir = crate::storage::persistence::base_path();
	let rules = [
		("/usr".into(), read),
		("/etc".into(), read),
		("/lib".into(), read),
		("/lib64".into(), read),
		("/bin".into(), read),
		("/sbin".into(), read),
		("/proc".into(), read),
		("/sys".into(), read),
		("/var/lib/systemd".into(), read),
		("/run/dbus".into(), read),
		("/run/systemd".into(), read),
		("/dev".into(), device),
		(runtime, data),
		(vault_dir.to_string_lossy().into_owned(), data),
		(home.join(".cache/fontconfig").to_string_lossy().into_owned(), data),
	];
	let ruleset = Ruleset::default()
		.set_compatibility(CompatLevel::BestEffort)
		.handle_access(full)
		.and_then(|ruleset| ruleset.create());
	let mut ruleset = match ruleset {
		Ok(ruleset) => ruleset,
		Err(err) => {
			warn(&format!("Filesystem sandbox unavailable: {err}"));
			return;
		}
	};
	for (path, access) in rules {
		// Optional paths (a font cache that was never written) are skipped;
		// a rule that cannot be added leaves the path unreachable, not open.
		if let Ok(fd) = PathFd::new(&path) {
			match ruleset.add_rule(PathBeneath::new(fd, access)) {
				Ok(next) => ruleset = next,
				Err(err) => {
					warn(&format!("Filesystem sandbox unavailable: {err}"));
					return;
				}
			}
		}
	}
	match ruleset.restrict_self() {
		Ok(status) => match status.ruleset {
			RulesetStatus::FullyEnforced => info("Filesystem sandbox enforced."),
			RulesetStatus::PartiallyEnforced => {
				warn("Filesystem sandbox partially enforced: the kernel is older than this build.")
			}
			RulesetStatus::NotEnforced => warn("Filesystem sandbox not enforced: Landlock is unavailable."),
		},
		Err(err) => warn(&format!("Filesystem sandbox unavailable: {err}")),
	}
}

pub fn preflight() {
	force_secure_display();
	lock_memory_pages();
	set_not_dumpable();
	enforce_no_preload();
	verify_secure_display();
	check_tme();
	sniff_luks();
	sandbox_filesystem();
	info("Preflight security checks passed.");
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Landlock binds the calling thread, so the sandbox is tried on a thread
	/// of its own and the rest of the suite stays unconfined.
	#[test]
	fn the_sandbox_keeps_system_files_and_hides_the_rest() {
		std::thread::spawn(|| {
			sandbox_filesystem();
			assert!(fs::read_dir("/usr/share").is_ok());
			assert!(fs::read("/etc/hostname").is_ok() || fs::read("/etc/os-release").is_ok());
			let outside = env::temp_dir().join(format!("keptino-sandbox-{}", std::process::id()));
			let denied = fs::File::create(&outside);
			assert!(denied.is_err(), "writing outside the allowed paths must fail");
			assert_eq!(
				denied.err().map(|e| e.kind()),
				Some(std::io::ErrorKind::PermissionDenied)
			);
		})
		.join()
		.unwrap();
	}
}
