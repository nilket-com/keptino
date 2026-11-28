//! The system call filter (ADR 0028). After preflight, the process and every
//! helper it starts lose the calls an attacker would use to reach other
//! processes, the kernel's rarer interfaces or a new namespace. Everything
//! the window, the network, the security keys and systemd-creds use stays
//! open: a refused call answers EPERM, so a library that probes one sees an
//! ordinary refusal. A call made in another architecture's numbering ends
//! the process.

use libc::{c_long, sock_filter, sock_fprog};

/// The calls no part of Keptino makes, each a step an attacker inside the
/// process would want: reading or steering another process, loading kernel
/// code, the io_uring, BPF and perf interfaces, mounts and namespaces, the
/// kernel keyrings, and host-wide settings.
const DENIED: &[c_long] = &[
	libc::SYS_ptrace,
	libc::SYS_process_vm_readv,
	libc::SYS_process_vm_writev,
	libc::SYS_process_madvise,
	libc::SYS_pidfd_getfd,
	libc::SYS_kcmp,
	libc::SYS_bpf,
	libc::SYS_perf_event_open,
	libc::SYS_userfaultfd,
	libc::SYS_io_uring_setup,
	libc::SYS_io_uring_enter,
	libc::SYS_io_uring_register,
	libc::SYS_kexec_load,
	libc::SYS_kexec_file_load,
	libc::SYS_init_module,
	libc::SYS_finit_module,
	libc::SYS_delete_module,
	libc::SYS_mount,
	libc::SYS_umount2,
	libc::SYS_pivot_root,
	libc::SYS_chroot,
	libc::SYS_move_mount,
	libc::SYS_open_tree,
	libc::SYS_fsopen,
	libc::SYS_fsconfig,
	libc::SYS_fsmount,
	libc::SYS_fspick,
	libc::SYS_mount_setattr,
	libc::SYS_unshare,
	libc::SYS_setns,
	libc::SYS_keyctl,
	libc::SYS_add_key,
	libc::SYS_request_key,
	libc::SYS_personality,
	libc::SYS_acct,
	libc::SYS_swapon,
	libc::SYS_swapoff,
	libc::SYS_reboot,
	libc::SYS_sethostname,
	libc::SYS_setdomainname,
	libc::SYS_settimeofday,
	libc::SYS_clock_settime,
	libc::SYS_clock_adjtime,
	libc::SYS_adjtimex,
	libc::SYS_quotactl,
	libc::SYS_syslog,
	libc::SYS_name_to_handle_at,
	libc::SYS_open_by_handle_at,
	libc::SYS_lookup_dcookie,
	libc::SYS_vhangup,
	#[cfg(target_arch = "x86_64")]
	libc::SYS_iopl,
	#[cfg(target_arch = "x86_64")]
	libc::SYS_ioperm,
	#[cfg(target_arch = "x86_64")]
	libc::SYS_uselib,
	#[cfg(target_arch = "x86_64")]
	libc::SYS_ustat,
	#[cfg(target_arch = "x86_64")]
	libc::SYS_sysfs,
	#[cfg(target_arch = "x86_64")]
	libc::SYS__sysctl,
];

/// The `clone` flags that make a namespace. Threads and helpers never ask
/// for one; an unprivileged user namespace is the usual first step of a
/// kernel exploit.
const NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
	| libc::CLONE_NEWCGROUP
	| libc::CLONE_NEWUTS
	| libc::CLONE_NEWIPC
	| libc::CLONE_NEWUSER
	| libc::CLONE_NEWPID
	| libc::CLONE_NEWNET) as u32;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_ALLOW: u32 = 0x7FFF_0000;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`.
const NR: u32 = 0;
const ARCH: u32 = 4;
/// The low half of the first argument on a little-endian machine.
const ARG0: u32 = 16;

fn statement(code: u16, k: u32) -> sock_filter {
	sock_filter {
		code,
		jt: 0,
		jf: 0,
		k,
	}
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
	sock_filter { code, jt, jf, k }
}

fn errno(errno: i32) -> u32 {
	RET_ERRNO | errno as u32
}

/// The filter program.
pub fn program() -> Vec<sock_filter> {
	let mut program = vec![
		statement(LD_W_ABS, ARCH),
		jump(JEQ_K, AUDIT_ARCH, 1, 0),
		statement(RET_K, RET_KILL_PROCESS),
		statement(LD_W_ABS, NR),
	];
	// x32 calls share the architecture with the bit set in the number.
	#[cfg(target_arch = "x86_64")]
	program.extend([
		jump(JSET_K, 0x4000_0000, 0, 1),
		statement(RET_K, RET_KILL_PROCESS),
	]);
	// clone3 passes its flags in memory the filter cannot read. ENOSYS
	// sends the C library back to clone, whose flags it can.
	program.extend([
		jump(JEQ_K, libc::SYS_clone3 as u32, 0, 1),
		statement(RET_K, errno(libc::ENOSYS)),
	]);
	for &call in DENIED {
		program.extend([
			jump(JEQ_K, call as u32, 0, 1),
			statement(RET_K, errno(libc::EPERM)),
		]);
	}
	// Last, because it replaces the number with the first argument.
	program.extend([
		jump(JEQ_K, libc::SYS_clone as u32, 0, 3),
		statement(LD_W_ABS, ARG0),
		jump(JSET_K, NAMESPACE_FLAGS, 0, 1),
		statement(RET_K, errno(libc::EPERM)),
		statement(RET_K, RET_ALLOW),
	]);
	program
}

/// Installs `program` on this thread, or with `all_threads` on every thread
/// of the process. Needs no privilege: it sets no_new_privs first.
pub fn install(program: &[sock_filter], all_threads: bool) -> Result<(), std::io::Error> {
	let prog = sock_fprog {
		len: u16::try_from(program.len()).expect("a short program"),
		filter: program.as_ptr().cast_mut(),
	};
	let flags = if all_threads {
		libc::SECCOMP_FILTER_FLAG_TSYNC
	} else {
		0
	};
	// SAFETY: prctl and seccomp read only the arguments given; `prog`
	// points at `program`, which outlives the call, and the kernel copies it.
	unsafe {
		if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
			return Err(std::io::Error::last_os_error());
		}
		match libc::syscall(
			libc::SYS_seccomp,
			libc::SECCOMP_SET_MODE_FILTER,
			flags,
			&raw const prog,
		) {
			0 => Ok(()),
			// With TSYNC, a positive answer names a thread that could not
			// take the filter.
			tid if tid > 0 => Err(std::io::Error::other(format!(
				"thread {tid} could not take the filter"
			))),
			_ => Err(std::io::Error::last_os_error()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn errno_of(result: c_long) -> Option<i32> {
		(result == -1).then(|| std::io::Error::last_os_error().raw_os_error().unwrap())
	}

	/// The filter binds the calling thread here, so the rest of the suite
	/// stays unfiltered.
	#[test]
	fn the_filter_refuses_the_denied_calls_and_keeps_threads_and_helpers() {
		std::thread::spawn(|| {
			install(&program(), false).unwrap();
			// SAFETY: each call is made with arguments that are refused or
			// harmless; none succeeds in changing the process.
			unsafe {
				let pid = libc::getpid();
				let refused = [
					libc::syscall(libc::SYS_ptrace, libc::PTRACE_PEEKUSER, pid, 0, 0),
					libc::syscall(libc::SYS_process_vm_readv, pid, 0, 0, 0, 0, 0),
					libc::syscall(libc::SYS_keyctl, 0, -3, 0),
					libc::syscall(libc::SYS_io_uring_setup, 0, 0),
					libc::syscall(libc::SYS_bpf, 0, 0, 0),
					// Without the filter both answer EINVAL: a user
					// namespace cannot share a filesystem context, and a
					// threaded process cannot unshare one.
					libc::syscall(
						libc::SYS_clone,
						libc::CLONE_NEWUSER | libc::CLONE_FS,
						0,
						0,
						0,
						0,
					),
					libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER),
				];
				for (index, result) in refused.into_iter().enumerate() {
					assert_eq!(errno_of(result), Some(libc::EPERM), "call {index}");
				}
				assert_eq!(
					errno_of(libc::syscall(libc::SYS_clone3, 0, 0)),
					Some(libc::ENOSYS)
				);
			}
			// Threads and helpers fall back from clone3 to clone.
			assert_eq!(std::thread::spawn(|| 7).join().unwrap(), 7);
			let status = std::process::Command::new("/bin/sh")
				.args(["-c", "exit 3"])
				.status()
				.unwrap();
			assert_eq!(status.code(), Some(3));
		})
		.join()
		.unwrap();
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn an_x32_call_ends_the_process() {
		let program = program();
		// SAFETY: the child makes only raw system calls before it exits.
		unsafe {
			let child = libc::fork();
			assert!(child >= 0);
			if child == 0 {
				if install(&program, false).is_err() {
					libc::_exit(2);
				}
				libc::syscall(libc::SYS_getpid | 0x4000_0000);
				libc::_exit(0);
			}
			let mut status = 0;
			assert_eq!(libc::waitpid(child, &mut status, 0), child);
			assert!(libc::WIFSIGNALED(status), "status {status}");
			assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
		}
	}
}
