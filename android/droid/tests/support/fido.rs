use libkeptino::fido::{
	ceremony::{Ceremony, Failure, Outcome, Step},
	sim::{Authenticator, Device},
};
use libkeptino::{roaming::KeySlot, vault::Derived};
use zeroize::Zeroizing;

pub const FILE: &[u8] = include_bytes!("../fixtures/linux-debug-fido.keptino");
pub const PIN: &str = "1234";

pub fn daily_key() -> Authenticator {
	Authenticator::new(*b"keptino-fixture-security-key-001").with_pin(PIN)
}

pub fn backup_key() -> Authenticator {
	Authenticator::new(*b"keptino-fixture-security-key-002")
}

pub fn assert_slots<E>(
	device: &mut Device,
	slots: &[KeySlot],
	pin: Option<&str>,
	expected_slot: usize,
) -> Derived<Zeroizing<[u8; 32]>, E> {
	let (mut ceremony, step) = Ceremony::assert(device.transport(), slots.to_vec());
	match device.drive(&mut ceremony, step, pin) {
		Step::Done(Outcome::Asserted { roaming, slot }) => {
			assert_eq!(slot, expected_slot);
			Derived::Key(roaming)
		}
		Step::Failed(Failure::Canceled) => Derived::Canceled,
		Step::Failed(_) => Derived::Unavailable,
		step => panic!("unexpected assertion step: {step:?}"),
	}
}
