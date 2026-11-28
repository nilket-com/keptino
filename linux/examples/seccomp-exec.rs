//! Runs a command under the system call filter (ADR 0028), which survives
//! exec: `cargo run --example seccomp-exec -- COMMAND [ARG ...]`. The RustFS
//! check and the interop driver run through it to show the storage paths
//! work filtered.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn main() {
	use std::os::unix::process::CommandExt;

	let mut args = std::env::args_os().skip(1);
	let Some(command) = args.next() else {
		eprintln!("Usage: seccomp-exec COMMAND [ARG ...]");
		std::process::exit(2);
	};
	if let Err(err) = keptino::seccomp::install(&keptino::seccomp::program(), true) {
		eprintln!("The filter could not be installed: {err}");
		std::process::exit(2);
	}
	let err = std::process::Command::new(command).args(args).exec();
	eprintln!("{err}");
	std::process::exit(127);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn main() {
	eprintln!("The system call filter is not built for this architecture.");
	std::process::exit(2);
}
