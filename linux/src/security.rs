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

pub fn preflight() {
	force_secure_display();
	lock_memory_pages();
	set_not_dumpable();
	enforce_no_preload();
	verify_secure_display();
	check_tme();
	sniff_luks();
	info("Preflight security checks passed.");
}
