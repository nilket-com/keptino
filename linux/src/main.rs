mod cli;
mod fido;
mod gui;
mod logger;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod seccomp;
mod security;
mod storage;

pub fn main() -> gui::Result {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if let Some(status) = cli::run(&args) {
		std::process::exit(status);
	}
	logger::info("Keptino started.");
	security::preflight();
	gui::run()
}
