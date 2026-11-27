//! Drive the shared ceremony on a foreground Android connection. Kotlin owns
//! the device and the prompts. Only the native caller receives its outcome.

use crate::error::Error;
use libkeptino::fido::{
	ceremony::{Ceremony, Failure, Input, Outcome, Step, Transport},
	hid, nfc,
};
use libkeptino::{
	roaming::{KeySlot, MAX_SLOTS, UvMode},
	vault::Derived,
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) type KeyResult<T> = Result<T, Failure>;
pub(crate) type Packet = [u8; hid::PACKET_SIZE];

pub(crate) enum Link {
	Usb,
	Nfc,
}

/// Blocking calls on the Android I/O worker. Each read or transceive has a
/// finite device timeout. Closing the foreground operation wakes pending I/O.
pub(crate) trait Device {
	fn purpose(&mut self, _prompt: &str) -> KeyResult<()> {
		Ok(())
	}
	fn begin(&mut self) -> KeyResult<Link>;
	fn write(&mut self, packet: &Packet) -> KeyResult<()>;
	fn read(&mut self) -> KeyResult<Packet>;
	fn apdu(&mut self, request: &[u8]) -> KeyResult<Vec<u8>>;
	fn pin(&mut self) -> KeyResult<Zeroizing<String>>;
}

fn connect(device: &mut impl Device) -> KeyResult<Transport> {
	match device.begin()? {
		Link::Nfc => {
			nfc::parse_select_response(&device.apdu(&nfc::select())?).map_err(Failure::Nfc)?;
			Ok(Transport::Nfc)
		}
		Link::Usb => {
			let mut nonce = [0u8; 8];
			getrandom::fill(&mut nonce).map_err(|_| Failure::Denied)?;
			device.write(&hid::init_request(nonce))?;
			let mut input = hid::Reassembler::new(hid::BROADCAST_CID);
			let start = Instant::now();
			while start.elapsed() < Duration::from_secs(5) {
				match input.push(&device.read()?) {
					Ok(hid::Event::Message {
						command: hid::Command::Init,
						payload,
					}) => {
						let init =
							hid::parse_init_response(&payload, nonce).map_err(Failure::Hid)?;
						if !init.supports_cbor() {
							return Err(Failure::NotFido2);
						}
						if matches!(init.cid, 0 | hid::BROADCAST_CID) {
							return Err(Failure::Mismatch);
						}
						return Ok(Transport::Hid { cid: init.cid });
					}
					Ok(_) | Err(hid::Error::WrongChannel { .. }) => continue,
					Err(error) => return Err(Failure::Hid(error)),
				}
			}
			Err(Failure::Denied)
		}
	}
}

fn run(device: &mut impl Device, mut ceremony: Ceremony, mut step: Step) -> KeyResult<Outcome> {
	let start = Instant::now();
	let result = (|| loop {
		if start.elapsed() >= Duration::from_secs(90) {
			return Err(Failure::Denied);
		}
		step = match step {
			Step::Write(ref packets) => {
				for packet in packets {
					device.write(packet)?;
				}
				Step::Read
			}
			Step::Read => ceremony.feed(Input::Packet(device.read()?)),
			Step::Transceive(ref apdu) => {
				let response = device.apdu(apdu)?;
				if response.ends_with(&[0x91, 0x00]) {
					std::thread::sleep(Duration::from_millis(50));
				}
				ceremony.feed(Input::Apdu(response))
			}
			Step::NeedPin => ceremony.feed(Input::Pin(device.pin()?)),
			Step::Done(outcome) => return Ok(outcome),
			Step::Failed(failure) => return Err(failure),
		};
	})();
	if result.is_err()
		&& let Step::Write(packets) = ceremony.abort()
	{
		for packet in packets {
			let _ = device.write(&packet);
		}
	}
	result
}

pub(crate) fn resolve(
	device: &mut impl Device,
	slots: &[KeySlot],
) -> Derived<Zeroizing<[u8; 32]>, Error> {
	let result = connect(device).and_then(|transport| {
		let (ceremony, step) = Ceremony::assert(transport, slots.to_vec());
		run(device, ceremony, step)
	});
	match result {
		Ok(Outcome::Asserted { roaming, .. }) => Derived::Key(roaming),
		Err(Failure::NoCredential) => Derived::Unavailable,
		Err(Failure::Canceled) => Derived::Canceled,
		Err(failure) => Derived::Failed(Error::SecurityKey(failure)),
		Ok(Outcome::Enrolled(_)) => Derived::Failed(Error::SecurityKey(Failure::Mismatch)),
	}
}

type SlotChange = (Vec<KeySlot>, Option<Zeroizing<[u8; 32]>>);

/// A zero mask adds a key. Otherwise each set bit names a slot explicitly
/// selected for removal. Proof and enrollment use the same device connection.
pub(crate) fn change_slots(
	device: &mut impl Device,
	slots: &[KeySlot],
	remove: u32,
	mode: UvMode,
) -> crate::Result<SlotChange> {
	if remove >> slots.len() != 0 || (remove == 0 && slots.len() >= MAX_SLOTS) {
		return Err(Error::Invalid(
			"invalid slot selection or vault already has four keys",
		));
	}
	let mut secret = Zeroizing::new([0; 32]);
	let mut result = Vec::new();
	if remove != 0 && remove.count_ones() as usize == slots.len() {
		return Ok((result, None));
	}
	if remove == 0 && !slots.is_empty() {
		device.purpose("Use an already enrolled security key.")?;
		let link = connect(device)?;
		let (ceremony, step) = Ceremony::assert(link, slots.to_vec());
		let Outcome::Asserted { roaming, .. } = run(device, ceremony, step)? else {
			return Err(Error::SecurityKey(Failure::Mismatch));
		};
		secret = roaming;
		result.extend_from_slice(slots);
	} else {
		getrandom::fill(secret.as_mut()).map_err(|_| Error::Memory("no system randomness"))?;
	}
	if remove == 0 {
		device.purpose("Use the new security key to enroll.")?;
		let link = connect(device)?;
		if !slots.is_empty() {
			let (ceremony, step) = Ceremony::assert(link, slots.to_vec());
			match run(device, ceremony, step) {
				Err(Failure::NoCredential) => (),
				Ok(_) => return Err(Error::Invalid("this security key is already enrolled")),
				Err(err) => return Err(err.into()),
			}
		}
		let slot = match enroll(device, link, mode, &secret) {
			Err(Failure::NoUserVerification) if mode == UvMode::Verified => {
				enroll(device, link, UvMode::TouchOnly, &secret)?
			}
			result => result?,
		};
		result.push(slot);
	} else {
		for (index, slot) in slots.iter().enumerate() {
			if remove & (1 << index) != 0 {
				continue;
			}
			device.purpose(&format!(
				"Use the security key in slot {} to keep it enrolled.",
				index + 1
			))?;
			let link = connect(device)?;
			let (ceremony, step) = Ceremony::assert(link, vec![slot.clone()]);
			let Outcome::Asserted { .. } = run(device, ceremony, step)? else {
				return Err(Error::SecurityKey(Failure::Mismatch));
			};
			result.push(enroll(device, link, slot.uv_mode, &secret)?);
		}
	}
	Ok((result, Some(secret)))
}

fn enroll(
	device: &mut impl Device,
	link: Transport,
	mode: UvMode,
	secret: &[u8; 32],
) -> KeyResult<KeySlot> {
	let (ceremony, step) = Ceremony::enroll(link, mode, Zeroizing::new(*secret));
	match run(device, ceremony, step)? {
		Outcome::Enrolled(slot) => Ok(slot),
		_ => Err(Failure::Mismatch),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Vault;
	use libkeptino::fido::sim::{Authenticator, Device as Sim, HidDevice, NfcDevice};
	use libkeptino::format::KdfParams;

	struct Fixture {
		key: Sim,
		pin: Option<&'static str>,
	}

	impl Device for Fixture {
		fn begin(&mut self) -> KeyResult<Link> {
			Ok(match self.key {
				Sim::Hid(_) => Link::Usb,
				Sim::Nfc(_) => Link::Nfc,
			})
		}
		fn write(&mut self, packet: &Packet) -> KeyResult<()> {
			let Sim::Hid(key) = &mut self.key else {
				panic!("unexpected HID write")
			};
			key.write(packet);
			Ok(())
		}
		fn read(&mut self) -> KeyResult<Packet> {
			let Sim::Hid(key) = &mut self.key else {
				panic!("unexpected HID read")
			};
			key.read().ok_or(Failure::Denied)
		}
		fn apdu(&mut self, request: &[u8]) -> KeyResult<Vec<u8>> {
			let Sim::Nfc(key) = &mut self.key else {
				panic!("unexpected APDU")
			};
			Ok(key.transceive(request))
		}
		fn pin(&mut self) -> KeyResult<Zeroizing<String>> {
			self.pin
				.take()
				.map(|p| Zeroizing::new(p.to_owned()))
				.ok_or(Failure::Canceled)
		}
	}

	fn open(key: Sim, pin: Option<&'static str>) -> crate::Result<Vault> {
		let mut device = Fixture { key, pin };
		let mut pepper = [0; 32];
		hex::decode_to_slice(
			"3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1",
			&mut pepper,
		)
		.unwrap();
		Vault::open_with_security_key(
			"vaultfido",
			b"correct horse battery staple",
			&pepper,
			Some(include_bytes!("../tests/fixtures/linux-debug-fido.keptino")),
			None,
			KdfParams::DEBUG,
			|candidate| resolve(&mut device, candidate.slots),
		)
	}

	#[test]
	fn production_driver_opens_the_linux_fixture_over_usb_and_nfc() {
		let daily = Authenticator::new(*b"keptino-fixture-security-key-001").with_pin("1234");
		let backup = Authenticator::new(*b"keptino-fixture-security-key-002");
		for (key, pin) in [
			(Sim::Hid(HidDevice::new(daily)), Some("1234")),
			(Sim::Nfc(NfcDevice::new(backup)), None),
		] {
			let vault = open(key, pin).unwrap();
			assert_eq!(vault.meta("db_name").as_deref(), Some("vaultfido"));
			assert_eq!(vault.revision(), 1);
		}
	}

	#[test]
	fn wrong_pin_is_terminal_and_does_not_try_again() {
		let daily = Authenticator::new(*b"keptino-fixture-security-key-001").with_pin("1234");
		assert!(matches!(
			open(Sim::Hid(HidDevice::new(daily)), Some("4321")),
			Err(Error::SecurityKey(Failure::WrongPin))
		));
	}
}
