//! Process hardening and locked key memory: the counterpart of the Linux
//! application's `security` module, using what Android permits an app.
//!
//! Linux locks the whole process with `mlockall` and keeps keys in
//! `memfd_secret` pages. Neither works here: the app seccomp filter kills a
//! process on an unlisted system call such as `memfd_secret`, and the app
//! `RLIMIT_MEMLOCK` is far below the 4 GiB derivation arena. What remains:
//! the process is made undumpable, tracing and library injection are
//! refused, keys live in locked pages that never reach a dump or a fork,
//! and the derivation arena is excluded from dumps.

use crate::error::{Error, Result};
use keptino_core::{
	crypto::{self, Block, PEPPER_SIZE, SALT_SIZE},
	format::KdfParams,
};
use libc::{
	_SC_PAGESIZE, MADV_DONTDUMP, MADV_DONTFORK, MADV_WIPEONFORK, MAP_ANONYMOUS, MAP_FAILED,
	MAP_PRIVATE, PR_SET_DUMPABLE, PROT_READ, PROT_WRITE, RLIMIT_CORE, RLIMIT_MEMLOCK, c_void,
	getrlimit, madvise, mlock, mmap, munlock, munmap, prctl, rlimit, setrlimit, sysconf,
};
use std::{
	env,
	ffi::OsStr,
	fs,
	ops::{Deref, DerefMut},
	ptr, slice,
};
use zeroize::Zeroize;

/// Instrumentation frameworks that hook a running app. Any of these mapped
/// into the process means its memory is not private.
const INJECTED_LIBRARIES: &[&str] = &[
	"frida",
	"xposed",
	"substrate",
	"libriru",
	"zygisk",
	"lsposed",
	"edxposed",
];

fn violation(what: String) -> Error {
	Error::Security(what)
}

fn page_size() -> usize {
	let size = unsafe { sysconf(_SC_PAGESIZE) };
	if size > 0 { size as usize } else { 4096 }
}

/// Refuses a loader that injects code into every process. The value is a
/// parameter so the check is pure and testable without touching the
/// process environment under other tests.
fn check_env_value(var: &str, value: Option<&OsStr>) -> Result<()> {
	if value.is_some_and(|value| !value.is_empty()) {
		return Err(violation(format!("{var} is set")));
	}
	Ok(())
}

fn check_env(var: &str) -> Result<()> {
	check_env_value(var, env::var_os(var).as_deref())
}

/// Refuses to run under a debugger or tracer.
fn check_tracer() -> Result<()> {
	let status = fs::read_to_string("/proc/self/status")
		.map_err(|_| violation("process status is unreadable".into()))?;
	let tracer = status
		.lines()
		.find_map(|line| line.strip_prefix("TracerPid:"))
		.map(str::trim)
		.unwrap_or("0");
	if tracer != "0" {
		return Err(violation(format!("process is traced by pid {tracer}")));
	}
	Ok(())
}

/// Refuses to run with a hooking framework mapped into the process.
fn check_maps() -> Result<()> {
	let maps = fs::read_to_string("/proc/self/maps")
		.map_err(|_| violation("memory map is unreadable".into()))?;
	for line in maps.lines() {
		let lower = line.to_ascii_lowercase();
		if let Some(found) = INJECTED_LIBRARIES
			.iter()
			.find(|name| lower.contains(**name))
		{
			return Err(violation(format!("injected library {found}")));
		}
	}
	Ok(())
}

/// No core dumps and no ptrace attach by anything short of root. Android's
/// crash reporter loses this process's tombstones, the trade Linux makes.
/// Returns a warning when the kernel refused.
pub fn harden_process() -> Option<String> {
	unsafe {
		let none = rlimit {
			rlim_cur: 0,
			rlim_max: 0,
		};
		let core = setrlimit(RLIMIT_CORE, &none) == 0;
		let dumpable = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
		if core && dumpable {
			None
		} else {
			Some("Process could not be made undumpable.".to_owned())
		}
	}
}

fn memlock_limit() -> String {
	let mut limit = rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	if unsafe { getrlimit(RLIMIT_MEMLOCK, &mut limit) } == 0 {
		format!("{} bytes", limit.rlim_cur)
	} else {
		"unknown".to_owned()
	}
}

fn swap_active() -> bool {
	fs::read_to_string("/proc/swaps")
		.map(|swaps| swaps.lines().skip(1).any(|line| !line.trim().is_empty()))
		.unwrap_or(false)
}

/// Excludes whole pages of a buffer from core dumps. Partial pages at either
/// end are left alone, so neighbouring allocations are unaffected.
pub fn exclude_from_dumps(ptr: *const u8, len: usize) {
	let page = page_size();
	let start = (ptr as usize).div_ceil(page).saturating_mul(page);
	let end = (ptr as usize).saturating_add(len) / page * page;
	if end > start {
		unsafe {
			madvise(start as *mut c_void, end - start, MADV_DONTDUMP);
		}
	}
}

/// Startup checks, in the order the Linux application makes them. A hard
/// failure is an `Error::Security`; the warnings are conditions the device
/// cannot fix, for the user to see.
pub fn preflight() -> Result<Vec<String>> {
	check_env("LD_PRELOAD")?;
	check_env("LD_AUDIT")?;
	check_tracer()?;
	check_maps()?;
	let mut warnings = Vec::new();
	if let Some(warning) = harden_process() {
		warnings.push(warning);
	}
	match LockedPage::new() {
		Ok(page) if page.is_locked() => {}
		Ok(_) => warnings.push(format!(
			"Memory lock refused (limit {}): keys may be swapped.",
			memlock_limit()
		)),
		Err(error) => warnings.push(error.to_string()),
	}
	if swap_active() {
		warnings
			.push("Swap is active: the 4 GiB key derivation arena cannot be locked.".to_owned());
	}
	Ok(warnings)
}

/// One private anonymous page, locked in RAM when the limit allows, never
/// written to a core dump, and not inherited by a forked child. Wiped and
/// unmapped on drop.
pub struct LockedPage {
	ptr: *mut u8,
	len: usize,
	locked: bool,
}

// The page is owned exclusively; the raw pointer is only an address.
unsafe impl Send for LockedPage {}
unsafe impl Sync for LockedPage {}

impl LockedPage {
	pub fn new() -> Result<Self> {
		let len = page_size();
		let ptr = unsafe {
			mmap(
				ptr::null_mut(),
				len,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1,
				0,
			)
		};
		if ptr == MAP_FAILED {
			return Err(Error::Memory("cannot map key memory"));
		}
		// Advice is best effort: an older kernel without MADV_WIPEONFORK
		// still gets MADV_DONTFORK, which covers the same child.
		let locked = unsafe {
			madvise(ptr, len, MADV_DONTDUMP);
			madvise(ptr, len, MADV_DONTFORK);
			madvise(ptr, len, MADV_WIPEONFORK);
			mlock(ptr, len) == 0
		};
		Ok(Self {
			ptr: ptr.cast(),
			len,
			locked,
		})
	}

	pub fn is_locked(&self) -> bool {
		self.locked
	}
}

impl Deref for LockedPage {
	type Target = [u8];
	fn deref(&self) -> &[u8] {
		unsafe { slice::from_raw_parts(self.ptr, self.len) }
	}
}

impl DerefMut for LockedPage {
	fn deref_mut(&mut self) -> &mut [u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
	}
}

impl Drop for LockedPage {
	fn drop(&mut self) {
		self.deref_mut().zeroize();
		unsafe {
			if self.locked {
				munlock(self.ptr.cast(), self.len);
			}
			munmap(self.ptr.cast(), self.len);
		}
	}
}

/// A 32-byte key in its own locked page.
pub struct LockedKey(LockedPage);

pub const LOCKED_KEY_SIZE: usize = 32;

impl LockedKey {
	pub fn new() -> Result<Self> {
		LockedPage::new().map(Self)
	}

	pub fn copy_from(bytes: &[u8; LOCKED_KEY_SIZE]) -> Result<Self> {
		let mut key = Self::new()?;
		key.copy_from_slice(bytes);
		Ok(key)
	}

	pub fn is_locked(&self) -> bool {
		self.0.is_locked()
	}
}

impl Deref for LockedKey {
	type Target = [u8; LOCKED_KEY_SIZE];
	fn deref(&self) -> &[u8; LOCKED_KEY_SIZE] {
		self.0[..LOCKED_KEY_SIZE]
			.try_into()
			.expect("a page holds a key")
	}
}

impl DerefMut for LockedKey {
	fn deref_mut(&mut self) -> &mut [u8; LOCKED_KEY_SIZE] {
		(&mut self.0[..LOCKED_KEY_SIZE])
			.try_into()
			.expect("a page holds a key")
	}
}

/// Allocate the core's Argon2 arena and exclude its pages from process dumps.
fn derivation_arena(mem_kib: u32) -> Result<Vec<Block>> {
	#[cfg(target_os = "android")]
	if let Ok(info) = std::fs::read_to_string("/proc/meminfo")
		&& let Some(available) = info.lines().find_map(|line| {
			line.strip_prefix("MemAvailable:")?
				.split_whitespace()
				.next()?
				.parse::<u64>()
				.ok()
		})
		&& u64::from(mem_kib) > available
	{
		return Err(Error::Kdf(format!(
			"requires {} MiB of available memory",
			mem_kib / 1024
		)));
	}
	let blocks = crypto::arena(KdfParams::memory_only(mem_kib))?;
	exclude_from_dumps(
		blocks.as_ptr().cast(),
		std::mem::size_of_val(blocks.as_slice()),
	);
	Ok(blocks)
}

pub fn derive_pepper(seed: &[u8], mem_kib: u32) -> Result<LockedKey> {
	if seed.is_empty() {
		return Err(Error::Invalid("empty pepper seed"));
	}
	let mut key = LockedKey::new()?;
	let mut blocks = derivation_arena(mem_kib)?;
	crypto::derive_pepper_in(seed, mem_kib, &mut blocks, &mut key)?;
	Ok(key)
}

pub(crate) fn derive_master_key(
	password: &[u8],
	pepper: &[u8; PEPPER_SIZE],
	salt: &[u8; SALT_SIZE],
	cost: KdfParams,
) -> Result<LockedKey> {
	let mut key = LockedKey::new()?;
	let mut blocks = derivation_arena(cost.m_cost)?;
	crypto::derive_master_key_in(password, pepper, salt, cost, &mut blocks, &mut key)?;
	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn derives_the_fixture_pepper_in_a_key_page() {
		let pepper = derive_pepper(b"correct horse", KdfParams::DEBUG.m_cost).unwrap();
		assert_eq!(
			hex::encode(pepper.as_slice()),
			include_str!("../tests/fixtures/pepper_m12.hex").trim()
		);
		assert!(matches!(
			derive_pepper(b"", KdfParams::RELEASE.m_cost),
			Err(Error::Invalid("empty pepper seed"))
		));
	}

	#[test]
	fn preflight_passes_on_an_untraced_host_and_then_maps_stay_readable() {
		let warnings = preflight().unwrap();
		for warning in &warnings {
			assert!(warning.ends_with('.'), "{warning}");
		}
		// The process is undumpable now; it must still read its own map.
		check_maps().unwrap();
		check_tracer().unwrap();
		assert_eq!(preflight().unwrap(), warnings);
	}

	#[test]
	fn injected_loader_is_refused() {
		let error = check_env_value("LD_AUDIT", Some(OsStr::new("/tmp/evil.so"))).unwrap_err();
		assert_eq!(error.to_string(), "SECURITY VIOLATION: LD_AUDIT is set.");
		check_env_value("LD_AUDIT", Some(OsStr::new(""))).unwrap();
		check_env_value("LD_AUDIT", None).unwrap();
	}

	#[test]
	fn locked_key_holds_bytes_and_is_page_backed() {
		let key = LockedKey::copy_from(&[7u8; LOCKED_KEY_SIZE]).unwrap();
		assert_eq!(*key, [7u8; LOCKED_KEY_SIZE]);
		assert!(key.0.len() >= 4096);
		assert!(key.0[LOCKED_KEY_SIZE..].iter().all(|byte| *byte == 0));
		let mut other = LockedKey::new().unwrap();
		other.copy_from_slice(&*key);
		assert_eq!(*other, *key);
		drop(key);
		assert_eq!(other[0], 7);
	}

	#[test]
	fn dump_exclusion_tolerates_unaligned_and_tiny_buffers() {
		let small = [0u8; 16];
		exclude_from_dumps(small.as_ptr(), small.len());
		let large = vec![0u8; 3 * 4096 + 100].into_boxed_slice();
		exclude_from_dumps(large.as_ptr().wrapping_add(1), large.len() - 1);
		exclude_from_dumps(ptr::null(), 0);
	}
}
