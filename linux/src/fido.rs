//! Security keys over USB HID on Linux. `/sys/class/hidraw` names the HID
//! devices; one whose report descriptor declares the FIDO usage page is a
//! key, and `/dev/hidrawN` carries its 64-byte packets. This module owns the
//! device and the clock; `keptino-fido` owns the protocol. A ceremony runs
//! here on the caller's thread, which is never the GUI thread.

use keptino_fido::ceremony::{Ceremony, Failure, Input, Outcome, Step, Transport};
use keptino_fido::hid::{self, PACKET_SIZE};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The FIDO Alliance usage page and the CTAPHID usage.
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const CTAPHID_USAGE: u16 = 0x01;
/// How long one read waits before the loop checks for a cancel.
pub const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the user has to touch the key once asked.
pub const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);
const SYSFS: &str = "/sys/class/hidraw";

/// A device that moves CTAPHID packets; the real one is a hidraw file and
/// the test one wraps the simulated key.
pub trait HidIo {
	fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()>;
	/// One packet, or `None` when none arrived within `timeout`.
	fn read_packet(&mut self, timeout: Duration) -> io::Result<Option<[u8; PACKET_SIZE]>>;
}

/// Whether a HID report descriptor declares the FIDO usage page with the
/// CTAPHID usage: the one pattern that marks a security key, whatever else
/// the device also is.
pub fn is_fido_descriptor(descriptor: &[u8]) -> bool {
	let mut page = None;
	let mut i = 0;
	while i < descriptor.len() {
		let prefix = descriptor[i];
		if prefix == 0xFE {
			// Long item: skip by its declared size.
			let size = *descriptor.get(i + 1).unwrap_or(&0) as usize;
			i += 3 + size;
			continue;
		}
		let size = match prefix & 0x03 {
			3 => 4,
			n => n as usize,
		};
		let data = &descriptor[(i + 1).min(descriptor.len())..(i + 1 + size).min(descriptor.len())];
		let value = data
			.iter()
			.rev()
			.fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
		match prefix & 0xFC {
			// Usage Page (global)
			0x04 => page = Some(value as u16),
			// Usage (local): with a four-byte value the page rides in the high half.
			0x08 => {
				let (usage_page, usage) = if size == 4 {
					((value >> 16) as u16, value as u16)
				} else {
					(page.unwrap_or(0), value as u16)
				};
				if usage_page == FIDO_USAGE_PAGE && usage == CTAPHID_USAGE {
					return true;
				}
			}
			_ => {}
		}
		i += 1 + size;
	}
	false
}

/// A security key found on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPath {
	pub device: PathBuf,
	pub name: String,
}

/// Every security key present, from `/sys/class/hidraw`.
pub fn enumerate() -> Vec<KeyPath> {
	enumerate_in(Path::new(SYSFS), Path::new("/dev"))
}

fn enumerate_in(sysfs: &Path, dev: &Path) -> Vec<KeyPath> {
	let Ok(entries) = fs::read_dir(sysfs) else {
		return Vec::new();
	};
	let mut keys: Vec<KeyPath> = entries
		.flatten()
		.filter_map(|entry| {
			let node = entry.file_name();
			let descriptor = fs::read(entry.path().join("device/report_descriptor")).ok()?;
			if !is_fido_descriptor(&descriptor) {
				return None;
			}
			let uevent = fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
			let name = uevent
				.lines()
				.find_map(|line| line.strip_prefix("HID_NAME="))
				.unwrap_or("Security key")
				.to_owned();
			Some(KeyPath {
				device: dev.join(node),
				name,
			})
		})
		.collect();
	keys.sort_by(|a, b| a.device.cmp(&b.device));
	keys
}

/// An open hidraw device.
pub struct HidrawDevice {
	file: File,
}

impl HidrawDevice {
	pub fn open(path: &Path) -> io::Result<Self> {
		let file = OpenOptions::new().read(true).write(true).open(path)?;
		Ok(Self { file })
	}
}

impl HidIo for HidrawDevice {
	fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
		// hidraw wants the report number first; CTAPHID uses none, so a zero
		// byte leads the 64 bytes.
		let mut report = [0u8; PACKET_SIZE + 1];
		report[1..].copy_from_slice(packet);
		self.file.write_all(&report)
	}

	fn read_packet(&mut self, timeout: Duration) -> io::Result<Option<[u8; PACKET_SIZE]>> {
		let mut poll = libc::pollfd {
			fd: self.file.as_raw_fd(),
			events: libc::POLLIN,
			revents: 0,
		};
		let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
		let ready = unsafe { libc::poll(&mut poll, 1, millis) };
		if ready < 0 {
			let err = io::Error::last_os_error();
			// A signal is not a device failure; the loop simply reads again.
			if err.kind() == io::ErrorKind::Interrupted {
				return Ok(None);
			}
			return Err(err);
		}
		if ready == 0 {
			return Ok(None);
		}
		let mut packet = [0u8; PACKET_SIZE];
		let read = self.file.read(&mut packet)?;
		if read != PACKET_SIZE {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"short CTAPHID packet",
			));
		}
		Ok(Some(packet))
	}
}

/// Allocates a channel on the key: `CTAPHID_INIT` on the broadcast channel
/// with a fresh nonce, the answer with the matching nonce names the channel.
pub fn init(device: &mut dyn HidIo) -> Result<Transport, Failure> {
	let mut nonce = [0u8; 8];
	getrandom::fill(&mut nonce).map_err(|_| Failure::Hid(hid::Error::BadLength))?;
	device
		.write_packet(&hid::init_request(nonce))
		.map_err(|_| Failure::Hid(hid::Error::BadLength))?;
	let deadline = Instant::now() + READ_TIMEOUT * 3;
	let mut reassembler = hid::Reassembler::new(hid::BROADCAST_CID);
	while Instant::now() < deadline {
		let Some(packet) = device
			.read_packet(READ_TIMEOUT)
			.map_err(|_| Failure::Hid(hid::Error::BadLength))?
		else {
			continue;
		};
		match reassembler.push(&packet) {
			Ok(hid::Event::Message {
				command: hid::Command::Init,
				payload,
			}) => {
				let response = hid::parse_init_response(&payload, nonce).map_err(Failure::Hid)?;
				return Ok(Transport::Hid { cid: response.cid });
			}
			// Another application's traffic on another channel is skipped.
			Ok(_) | Err(hid::Error::WrongChannel { .. }) => continue,
			Err(err) => return Err(Failure::Hid(err)),
		}
	}
	Err(Failure::Denied)
}

/// What the driver tells the GUI while a ceremony runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt {
	/// The key wants a touch.
	Touch,
}

/// Runs `ceremony` from `step` against `device` until it finishes. `pin`
/// answers one PIN request; without one the request cancels the ceremony.
/// `cancel` set from another thread aborts at the next read. `on_prompt`
/// hears when the key asks for a touch.
pub fn run(
	ceremony: &mut Ceremony,
	mut step: Step,
	device: &mut dyn HidIo,
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
	mut on_prompt: impl FnMut(Prompt),
) -> Step {
	let mut pin = pin;
	let mut waited_since = Instant::now();
	let mut prompted = false;
	loop {
		if cancel.load(Ordering::Relaxed) && !ceremony.is_finished() {
			if let Step::Write(packets) = ceremony.abort() {
				for packet in &packets {
					let _ = device.write_packet(packet);
				}
			}
			return Step::Failed(Failure::Canceled);
		}
		step = match step {
			Step::Write(packets) => {
				for packet in &packets {
					if device.write_packet(packet).is_err() {
						return ceremony_failed(
							ceremony,
							device,
							Failure::Hid(hid::Error::BadLength),
						);
					}
				}
				waited_since = Instant::now();
				Step::Read
			}
			Step::Read => match device.read_packet(READ_TIMEOUT) {
				Ok(Some(packet)) => {
					// A keepalive asking for a touch is the moment to tell the user.
					if packet[4] == 0x80 | hid::Command::KeepAlive.code()
						&& packet[7] == hid::KEEPALIVE_UPNEEDED
						&& !prompted
					{
						prompted = true;
						on_prompt(Prompt::Touch);
					}
					if packet[4] == 0x80 | hid::Command::KeepAlive.code() {
						// The key is alive and working; the touch clock runs
						// from the first keepalive, not the write.
						let fed = ceremony.feed(Input::Packet(packet));
						if waited_since.elapsed() > TOUCH_TIMEOUT {
							return ceremony_failed(ceremony, device, Failure::Denied);
						}
						fed
					} else {
						ceremony.feed(Input::Packet(packet))
					}
				}
				Ok(None) => {
					if waited_since.elapsed() > TOUCH_TIMEOUT {
						return ceremony_failed(ceremony, device, Failure::Denied);
					}
					Step::Read
				}
				Err(_) => {
					return ceremony_failed(ceremony, device, Failure::Hid(hid::Error::BadLength));
				}
			},
			Step::Transceive(_) => return ceremony_failed(ceremony, device, Failure::Mismatch),
			Step::NeedPin => match pin.take() {
				Some(pin) => ceremony.feed(Input::Pin(pin)),
				None => {
					let _ = ceremony.abort();
					return Step::Failed(Failure::Canceled);
				}
			},
			done @ (Step::Done(_) | Step::Failed(_)) => return done,
		};
	}
}

/// Ends the ceremony as failed, and tells the key so it stops waiting for
/// a touch: the abort's CANCEL packet goes out when one is due.
fn ceremony_failed(ceremony: &mut Ceremony, device: &mut dyn HidIo, failure: Failure) -> Step {
	if let Step::Write(packets) = ceremony.abort() {
		for packet in &packets {
			let _ = device.write_packet(packet);
		}
	}
	Step::Failed(failure)
}

/// Every key present, opened. Tests swap in simulated keys through
/// `test_support::with_keys`.
pub fn open_keys() -> Vec<Box<dyn HidIo>> {
	#[cfg(test)]
	if let Some(keys) = test_support::simulated_keys() {
		return keys;
	}
	enumerate()
		.into_iter()
		.filter_map(|key| HidrawDevice::open(&key.device).ok())
		.map(|device| Box::new(device) as Box<dyn HidIo>)
		.collect()
}

/// The result of asking every key present to open one of `slots`.
pub fn assert_with_any_key(
	slots: &[keptino_core::roaming::KeySlot],
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
	mut on_prompt: impl FnMut(Prompt),
) -> Result<Outcome, Failure> {
	let keys = open_keys();
	if keys.is_empty() {
		return Err(Failure::NoCredential);
	}
	let mut last = Failure::NoCredential;
	for mut device in keys {
		let transport = match init(device.as_mut()) {
			Ok(transport) => transport,
			Err(failure) => {
				last = failure;
				continue;
			}
		};
		let (mut ceremony, step) = Ceremony::assert(transport, slots.to_vec());
		match run(
			&mut ceremony,
			step,
			device.as_mut(),
			pin.clone(),
			cancel,
			&mut on_prompt,
		) {
			Step::Done(outcome) => return Ok(outcome),
			Step::Failed(Failure::NoCredential) => continue,
			Step::Failed(failure) => return Err(failure),
			_ => return Err(Failure::Mismatch),
		}
	}
	Err(last)
}

/// Enrolls the first key present into a slot wrapping `roaming`.
pub fn enroll_with_first_key(
	uv_mode: keptino_core::roaming::UvMode,
	roaming: &[u8; 32],
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
	mut on_prompt: impl FnMut(Prompt),
) -> Result<keptino_core::roaming::KeySlot, Failure> {
	let mut keys = open_keys();
	let Some(device) = keys.first_mut() else {
		return Err(Failure::NoCredential);
	};
	let transport = init(device.as_mut())?;
	let (mut ceremony, step) = Ceremony::enroll(transport, uv_mode, Zeroizing::new(*roaming));
	match run(
		&mut ceremony,
		step,
		device.as_mut(),
		pin,
		cancel,
		&mut on_prompt,
	) {
		Step::Done(Outcome::Enrolled(slot)) => Ok(slot),
		Step::Failed(failure) => Err(failure),
		_ => Err(Failure::Mismatch),
	}
}

/// Enrolls a key present that owns none of `existing`: the new key when a
/// backup is added while the daily key is still plugged in.
pub fn enroll_new_key(
	existing: &[keptino_core::roaming::KeySlot],
	uv_mode: keptino_core::roaming::UvMode,
	roaming: &[u8; 32],
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
	mut on_prompt: impl FnMut(Prompt),
) -> Result<keptino_core::roaming::KeySlot, Failure> {
	let keys = open_keys();
	if keys.is_empty() {
		return Err(Failure::NoCredential);
	}
	for mut device in keys {
		let transport = match init(device.as_mut()) {
			Ok(transport) => transport,
			Err(_) => continue,
		};
		if !existing.is_empty() {
			// A key that answers for an existing slot is already enrolled.
			let (mut ceremony, step) = Ceremony::assert(transport, existing.to_vec());
			match run(
				&mut ceremony,
				step,
				device.as_mut(),
				pin.clone(),
				cancel,
				&mut on_prompt,
			) {
				Step::Failed(Failure::NoCredential) => {}
				Step::Done(_) => continue,
				Step::Failed(failure) => return Err(failure),
				_ => return Err(Failure::Mismatch),
			}
		}
		let (mut ceremony, step) = Ceremony::enroll(transport, uv_mode, Zeroizing::new(*roaming));
		return match run(
			&mut ceremony,
			step,
			device.as_mut(),
			pin,
			cancel,
			&mut on_prompt,
		) {
			Step::Done(Outcome::Enrolled(slot)) => Ok(slot),
			Step::Failed(failure) => Err(failure),
			_ => Err(Failure::Mismatch),
		};
	}
	Err(Failure::NoCredential)
}

/// Finds the key that owns `slot` among those present, by asserting it,
/// and enrolls that same key into a new slot wrapping `roaming`: how a rekey
/// keeps a key enrolled without trusting whichever key happens to be first.
pub fn reenroll_owner(
	slot: &keptino_core::roaming::KeySlot,
	roaming: &[u8; 32],
	pin: Option<Zeroizing<String>>,
	cancel: &AtomicBool,
	mut on_prompt: impl FnMut(Prompt),
) -> Result<keptino_core::roaming::KeySlot, Failure> {
	let keys = open_keys();
	if keys.is_empty() {
		return Err(Failure::NoCredential);
	}
	for mut device in keys {
		let transport = match init(device.as_mut()) {
			Ok(transport) => transport,
			Err(_) => continue,
		};
		let (mut ceremony, step) = Ceremony::assert(transport, vec![slot.clone()]);
		match run(
			&mut ceremony,
			step,
			device.as_mut(),
			pin.clone(),
			cancel,
			&mut on_prompt,
		) {
			Step::Done(Outcome::Asserted { .. }) => {}
			Step::Failed(Failure::NoCredential) => continue,
			Step::Failed(failure) => return Err(failure),
			_ => return Err(Failure::Mismatch),
		}
		// This device owns the slot: it gets the new one.
		let (mut ceremony, step) =
			Ceremony::enroll(transport, slot.uv_mode, Zeroizing::new(*roaming));
		return match run(
			&mut ceremony,
			step,
			device.as_mut(),
			pin,
			cancel,
			&mut on_prompt,
		) {
			Step::Done(Outcome::Enrolled(new_slot)) => Ok(new_slot),
			Step::Failed(failure) => Err(failure),
			_ => Err(Failure::Mismatch),
		};
	}
	Err(Failure::NoCredential)
}

/// Simulated keys for tests of the layers above the transport.
#[cfg(test)]
pub mod test_support {
	use super::*;
	use keptino_fido::sim::{Authenticator, HidDevice};
	use std::cell::RefCell;

	/// A simulated key described by what makes it: a seed and a PIN.
	#[derive(Clone)]
	pub struct SimKey {
		pub seed: [u8; 32],
		pub pin: Option<&'static str>,
		/// Reads that return nothing before the key answers, as a key waiting
		/// for a finger.
		pub silent_reads: u32,
	}

	thread_local! {
		static KEYS: RefCell<Option<Vec<SimKey>>> = const { RefCell::new(None) };
	}

	/// The simulated key behind the `HidIo` trait.
	pub struct FakeDevice {
		pub inner: HidDevice,
		pub silent_reads: u32,
	}

	impl HidIo for FakeDevice {
		fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
			self.inner.write(packet);
			Ok(())
		}
		fn read_packet(&mut self, _timeout: Duration) -> io::Result<Option<[u8; PACKET_SIZE]>> {
			if self.silent_reads > 0 {
				self.silent_reads -= 1;
				return Ok(None);
			}
			Ok(self.inner.read())
		}
	}

	pub fn fake(key: Authenticator) -> FakeDevice {
		FakeDevice {
			inner: HidDevice::new(key),
			silent_reads: 0,
		}
	}

	/// Runs `f` with these simulated keys plugged in, on this thread.
	pub fn with_keys<T>(keys: Vec<SimKey>, f: impl FnOnce() -> T) -> T {
		KEYS.with(|slot| *slot.borrow_mut() = Some(keys));
		let out = f();
		KEYS.with(|slot| *slot.borrow_mut() = None);
		out
	}

	pub(super) fn simulated_keys() -> Option<Vec<Box<dyn HidIo>>> {
		KEYS.with(|slot| {
			slot.borrow().as_ref().map(|keys| {
				keys.iter()
					.map(|key| {
						let mut authenticator = Authenticator::new(key.seed);
						if let Some(pin) = key.pin {
							authenticator = authenticator.with_pin(pin);
						}
						let mut device = fake(authenticator);
						device.silent_reads = key.silent_reads;
						Box::new(device) as Box<dyn HidIo>
					})
					.collect()
			})
		})
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::{SimKey, fake, with_keys};
	use super::*;
	use keptino_core::roaming::UvMode;
	use keptino_fido::sim::Authenticator;

	#[test]
	fn the_descriptor_check_knows_a_security_key_from_a_mouse() {
		// A FIDO descriptor as the YubiKey 5 declares it.
		let fido = [
			0x06, 0xD0, 0xF1, // Usage Page (FIDO)
			0x09, 0x01, // Usage (CTAPHID)
			0xA1, 0x01, // Collection (Application)
			0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09,
			0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0,
		];
		assert!(is_fido_descriptor(&fido));
		// The same page and usage as one four-byte extended usage item.
		let extended = [0x0B, 0x01, 0x00, 0xD0, 0xF1, 0xA1, 0x01, 0xC0];
		assert!(is_fido_descriptor(&extended));
		// This host's touchpad descriptor, from /sys.
		let mouse = [
			0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09,
			0x19, 0x01, 0x29, 0x02, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02,
			0x95, 0x06, 0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81,
			0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0xC0, 0xC0,
		];
		assert!(!is_fido_descriptor(&mouse));
		// A FIDO page with another usage, and a truncated item, are not keys.
		assert!(!is_fido_descriptor(&[0x06, 0xD0, 0xF1, 0x09, 0x02]));
		assert!(!is_fido_descriptor(&[0x06, 0xD0]));
		assert!(!is_fido_descriptor(&[]));
	}

	#[test]
	fn enumeration_reads_sysfs_and_names_the_device_node() {
		let root = std::env::temp_dir().join(format!("keptino-hidraw-{}", std::process::id()));
		let _ = fs::remove_dir_all(&root);
		let sysfs = root.join("sys");
		for (node, descriptor, name) in [
			(
				"hidraw3",
				vec![0x06u8, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0xC0],
				"Yubico YubiKey OTP+FIDO+CCID",
			),
			(
				"hidraw1",
				vec![0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0xC0],
				"Keyboard",
			),
			(
				"hidraw2",
				vec![0x0B, 0x01, 0x00, 0xD0, 0xF1, 0xA1, 0x01, 0xC0],
				"SoloKeys Solo 2",
			),
		] {
			let dir = sysfs.join(node).join("device");
			fs::create_dir_all(&dir).unwrap();
			fs::write(dir.join("report_descriptor"), descriptor).unwrap();
			fs::write(
				dir.join("uevent"),
				format!("HID_ID=0003\nHID_NAME={name}\n"),
			)
			.unwrap();
		}
		let keys = enumerate_in(&sysfs, Path::new("/dev"));
		assert_eq!(
			keys,
			vec![
				KeyPath {
					device: PathBuf::from("/dev/hidraw2"),
					name: "SoloKeys Solo 2".into()
				},
				KeyPath {
					device: PathBuf::from("/dev/hidraw3"),
					name: "Yubico YubiKey OTP+FIDO+CCID".into()
				},
			]
		);
		assert!(enumerate_in(&root.join("missing"), Path::new("/dev")).is_empty());
		let _ = fs::remove_dir_all(&root);
	}

	#[test]
	fn the_driver_runs_a_ceremony_end_to_end_with_init_keepalives_and_a_pin() {
		let seed = [0x51u8; 32];
		let mut device = fake(Authenticator::new(seed).with_pin("2468"));
		device.inner.keepalives = 2;
		let transport = init(&mut device).unwrap();
		assert_eq!(
			transport,
			Transport::Hid {
				cid: device.inner.cid()
			}
		);
		let cancel = AtomicBool::new(false);
		let mut prompts = Vec::new();
		let (mut ceremony, step) =
			Ceremony::enroll(transport, UvMode::Verified, Zeroizing::new([0x33; 32]));
		let step = run(
			&mut ceremony,
			step,
			&mut device,
			Some(Zeroizing::new("2468".into())),
			&cancel,
			|p| prompts.push(p),
		);
		let Step::Done(Outcome::Enrolled(slot)) = step else {
			panic!("{step:?}");
		};
		assert_eq!(slot.uv_mode, UvMode::Verified);
		assert_eq!(prompts, vec![Prompt::Touch]);

		// Assert with a fresh life of the key, silent reads in between as a
		// key waiting for the finger.
		let mut device = fake(Authenticator::new(seed).with_pin("2468"));
		device.silent_reads = 3;
		let transport = init(&mut device).unwrap();
		let (mut ceremony, step) = Ceremony::assert(transport, vec![slot.clone()]);
		let step = run(
			&mut ceremony,
			step,
			&mut device,
			Some(Zeroizing::new("2468".into())),
			&cancel,
			|_| {},
		);
		assert!(
			matches!(step, Step::Done(Outcome::Asserted { slot: 0, .. })),
			"{step:?}"
		);

		// No PIN offered: the request cancels the ceremony and nothing is made.
		let mut device = fake(Authenticator::new(seed).with_pin("2468"));
		let transport = init(&mut device).unwrap();
		let (mut ceremony, step) =
			Ceremony::enroll(transport, UvMode::Verified, Zeroizing::new([0x33; 32]));
		assert_eq!(
			run(&mut ceremony, step, &mut device, None, &cancel, |_| {}),
			Step::Failed(Failure::Canceled)
		);
		assert_eq!(device.inner.key.credentials_made, 0);
	}

	#[test]
	fn any_key_present_is_tried_until_one_owns_a_slot() {
		let daily = SimKey {
			seed: [0x61; 32],
			pin: Some("1111"),
			silent_reads: 0,
		};
		let backup = SimKey {
			seed: [0x62; 32],
			pin: None,
			silent_reads: 2,
		};
		let cancel = AtomicBool::new(false);
		let roaming = [0x33u8; 32];
		// Enroll with the first key present: the backup, alone.
		let slot = with_keys(vec![backup.clone()], || {
			enroll_with_first_key(UvMode::TouchOnly, &roaming, None, &cancel, |_| {}).unwrap()
		});
		// Both plugged in, the daily key first: it owns no slot and says so;
		// the backup opens it.
		let outcome = with_keys(vec![daily.clone(), backup.clone()], || {
			assert_with_any_key(std::slice::from_ref(&slot), None, &cancel, |_| {}).unwrap()
		});
		match outcome {
			Outcome::Asserted {
				slot: 0,
				roaming: got,
			} => assert_eq!(*got, roaming),
			other => panic!("{other:?}"),
		}
		// Only the daily key: nothing opens, and that is NoCredential.
		assert_eq!(
			with_keys(vec![daily.clone()], || assert_with_any_key(
				std::slice::from_ref(&slot),
				None,
				&cancel,
				|_| {}
			)
			.err()),
			Some(Failure::NoCredential)
		);
		// No key at all.
		assert_eq!(
			with_keys(vec![], || assert_with_any_key(
				std::slice::from_ref(&slot),
				None,
				&cancel,
				|_| {}
			)
			.err()),
			Some(Failure::NoCredential)
		);
		// Re-enrolling the owner: with both present, the backup is found by
		// its slot and gets the new one; the daily key alone does not qualify.
		let fresh = [0x44u8; 32];
		let renewed = with_keys(vec![daily.clone(), backup.clone()], || {
			reenroll_owner(&slot, &fresh, None, &cancel, |_| {}).unwrap()
		});
		assert_ne!(renewed.cred_id, slot.cred_id);
		assert_eq!(renewed.uv_mode, UvMode::TouchOnly);
		let opened = with_keys(vec![backup], || {
			assert_with_any_key(std::slice::from_ref(&renewed), None, &cancel, |_| {}).unwrap()
		});
		assert!(matches!(opened, Outcome::Asserted { roaming: got, .. } if *got == fresh));
		assert_eq!(
			with_keys(vec![daily], || reenroll_owner(
				&slot,
				&fresh,
				None,
				&cancel,
				|_| {}
			)
			.err()),
			Some(Failure::NoCredential)
		);
	}

	#[test]
	fn a_cancel_from_another_thread_sends_the_cancel_packet() {
		let mut device = fake(Authenticator::new([0x52; 32]));
		let transport = init(&mut device).unwrap();
		let cancel = AtomicBool::new(true);
		let (mut ceremony, step) =
			Ceremony::enroll(transport, UvMode::TouchOnly, Zeroizing::new([0x33; 32]));
		// The first step is a write; the cancel is seen before it happens, and
		// nothing is pending, so only the failure comes back.
		assert_eq!(
			run(&mut ceremony, step, &mut device, None, &cancel, |_| {}),
			Step::Failed(Failure::Canceled)
		);
		assert!(ceremony.is_finished());
		// Cancel after the write went out: the CANCEL packet reaches the key.
		let mut device = fake(Authenticator::new([0x52; 32]));
		let transport = init(&mut device).unwrap();
		let cancel = AtomicBool::new(false);
		let (mut ceremony, step) =
			Ceremony::enroll(transport, UvMode::TouchOnly, Zeroizing::new([0x33; 32]));
		let Step::Write(packets) = step else { panic!() };
		for packet in &packets {
			device.write_packet(packet).unwrap();
		}
		cancel.store(true, Ordering::Relaxed);
		assert_eq!(
			run(
				&mut ceremony,
				Step::Read,
				&mut device,
				None,
				&cancel,
				|_| {}
			),
			Step::Failed(Failure::Canceled)
		);
		assert_eq!(device.inner.cancels, 1);
	}
}

/// Against a real key, for the operator: `cargo test -p keptino real_key_probe
/// -- --ignored --nocapture`. Logs every CTAP command and status byte of an
/// enrollment so a disagreement with a real authenticator can be seen.
#[cfg(test)]
mod probe {
	use super::*;
	use keptino_core::roaming::UvMode;

	struct Logging(Box<dyn HidIo>);

	impl HidIo for Logging {
		fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
			let cmd = packet[4];
			if cmd & 0x80 != 0 {
				let len = u16::from_be_bytes([packet[5], packet[6]]);
				eprintln!(
					"-> hid cmd 0x{:02x} len {len} ctap 0x{:02x} {}",
					cmd & 0x7f,
					packet[7],
					hex::encode(&packet[8..32])
				);
			}
			self.0.write_packet(packet)
		}
		fn read_packet(&mut self, timeout: Duration) -> io::Result<Option<[u8; PACKET_SIZE]>> {
			let got = self.0.read_packet(timeout)?;
			if let Some(packet) = &got {
				let cmd = packet[4];
				if cmd & 0x80 != 0 {
					let len = u16::from_be_bytes([packet[5], packet[6]]);
					eprintln!(
						"<- hid cmd 0x{:02x} len {len} status 0x{:02x} {}",
						cmd & 0x7f,
						packet[7],
						hex::encode(&packet[8..32])
					);
				}
			}
			Ok(got)
		}
	}

	fn read_pin() -> Option<Zeroizing<String>> {
		use std::io::{BufRead, BufReader};
		let mut tty = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.open("/dev/tty")
			.ok()?;
		write!(tty, "security key PIN (empty for none): ").ok()?;
		tty.flush().ok()?;
		let fd = tty.as_raw_fd();
		let mut term: libc::termios = unsafe { std::mem::zeroed() };
		unsafe { libc::tcgetattr(fd, &mut term) };
		let saved = term;
		term.c_lflag &= !libc::ECHO;
		unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
		let mut line = String::new();
		let _ = BufReader::new(&tty).read_line(&mut line);
		unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
		let _ = writeln!(tty);
		let pin = line.trim_end_matches(['\n', '\r']).to_owned();
		(!pin.is_empty()).then(|| Zeroizing::new(pin))
	}

	#[test]
	#[ignore = "needs a security key and a person to touch it"]
	fn real_key_probe() {
		let keys = enumerate();
		eprintln!("keys: {keys:?}");
		let key = keys.first().expect("a security key plugged in");
		let mut device = Logging(Box::new(
			HidrawDevice::open(&key.device).expect("open hidraw"),
		));
		let transport = init(&mut device).expect("init");
		eprintln!("transport: {transport:?}");
		let pin = read_pin();
		let cancel = AtomicBool::new(false);
		let roaming = Zeroizing::new([0x33u8; 32]);
		let (mut ceremony, step) = Ceremony::enroll(transport, UvMode::Verified, roaming);
		let result = run(
			&mut ceremony,
			step,
			&mut device,
			pin.clone(),
			&cancel,
			|p| eprintln!("prompt {p:?}"),
		);
		eprintln!("enroll (verified): {result:?}");
		if let Step::Done(Outcome::Enrolled(slot)) = result {
			let (mut ceremony, step) = Ceremony::assert(transport, vec![slot]);
			let result = run(&mut ceremony, step, &mut device, pin, &cancel, |p| {
				eprintln!("prompt {p:?}")
			});
			eprintln!("assert: {result:?}");
		}
	}
}
