//! CTAP2 over ISO 7816-4 APDUs (CTAP 2.1 section 11.3). A head transceives
//! each APDU and feeds the responses back. Two kinds of continuation exist:
//! the ISO status `61xx` means the key holds more response bytes and is
//! answered with the ISO GET RESPONSE; the CTAP status `9100` means the key
//! is still working and is answered with NFCCTAP_GETRESPONSE after a short
//! wait.

use std::fmt;

/// The FIDO applet identifier selected before any CTAP message.
pub const AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
/// The most data bytes a short APDU carries.
pub const MAX_CHUNK: usize = 255;
/// The longest response a ceremony accepts across continuations; a key
/// answering more than this is not speaking CTAP2 to us.
pub const MAX_RESPONSE_BYTES: usize = 16 << 10;

const CLA: u8 = 0x80;
const CLA_CHAINING: u8 = 0x10;
const INS_MSG: u8 = 0x10;
const INS_GET_RESPONSE: u8 = 0x11;
/// P1 of NFCCTAP_MSG: the client understands NFCCTAP_GETRESPONSE.
const P1_GETRESPONSE_SUPPORTED: u8 = 0x80;

const SW_OK: u16 = 0x9000;
const SW_MORE_DATA: u8 = 0x61;
const SW_PENDING: u16 = 0x9100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// A response of fewer than two bytes, so without a status word.
	Short,
	/// A status word other than success or one of the two continuations.
	Status(u16),
	/// A SELECT response naming a version this crate does not speak.
	UnknownVersion,
	/// A response grown past `MAX_RESPONSE_BYTES` across continuations.
	TooLong,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Short => f.write_str("the NFC response has no status word."),
			Self::TooLong => f.write_str("the NFC response is longer than a CTAP2 answer can be."),
			Self::Status(sw) => write!(f, "the security key answered status 0x{sw:04x}."),
			Self::UnknownVersion => {
				f.write_str("the security key named a FIDO version this crate does not speak.")
			}
		}
	}
}

impl std::error::Error for Error {}

/// The version string a SELECT response names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
	/// `U2F_V2`: a key that may still speak CTAP2 after getInfo.
	U2fV2,
	/// `FIDO_2_0`: a CTAP2-only key.
	Fido20,
}

/// The SELECT APDU for the FIDO applet.
pub fn select() -> Vec<u8> {
	let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, AID.len() as u8];
	apdu.extend_from_slice(&AID);
	apdu.push(0x00);
	apdu
}

/// Parse a SELECT response: a version string, then `90 00`.
pub fn parse_select_response(bytes: &[u8]) -> Result<Version, Error> {
	let (data, sw) = split_status(bytes)?;
	if sw != SW_OK {
		return Err(Error::Status(sw));
	}
	match data {
		b"U2F_V2" => Ok(Version::U2fV2),
		b"FIDO_2_0" => Ok(Version::Fido20),
		_ => Err(Error::UnknownVersion),
	}
}

/// Frame one CTAP message as NFCCTAP_MSG APDUs, chained when it exceeds a
/// short APDU. Every APDU but the last sets the chaining bit; the last
/// carries `Le` 0.
pub fn ctap_message(payload: &[u8]) -> Vec<Vec<u8>> {
	let chunks: Vec<&[u8]> = if payload.is_empty() {
		vec![&[]]
	} else {
		payload.chunks(MAX_CHUNK).collect()
	};
	let last = chunks.len() - 1;
	chunks
		.iter()
		.enumerate()
		.map(|(i, chunk)| {
			let cla = if i == last { CLA } else { CLA | CLA_CHAINING };
			let mut apdu = vec![cla, INS_MSG, P1_GETRESPONSE_SUPPORTED, 0x00];
			if !chunk.is_empty() {
				apdu.push(chunk.len() as u8);
				apdu.extend_from_slice(chunk);
			}
			if i == last {
				apdu.push(0x00);
			}
			apdu
		})
		.collect()
}

/// NFCCTAP_GETRESPONSE: ask for the result after status `91 00`.
pub fn get_response() -> Vec<u8> {
	vec![CLA, INS_GET_RESPONSE, 0x00, 0x00, 0x00]
}

/// ISO GET RESPONSE: fetch the next `le` bytes after status `61 le`.
pub fn iso_get_response(le: u8) -> Vec<u8> {
	vec![0x00, 0xC0, 0x00, 0x00, le]
}

/// What the driver does after one response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
	/// The whole response.
	Done(Vec<u8>),
	/// Status `61 le`: send `iso_get_response(le)`.
	MoreData { le: u8 },
	/// Status `91 00`: the key is still working; send `get_response()` after
	/// a short wait.
	Pending,
}

/// Joins the parts of one response across `61xx` and `9100` continuations.
#[derive(Clone, Debug, Default)]
pub struct ResponseAssembler {
	data: Vec<u8>,
}

impl ResponseAssembler {
	pub fn new() -> Self {
		Self::default()
	}

	/// Push one response as read from the key, status word included.
	pub fn push(&mut self, response: &[u8]) -> Result<Step, Error> {
		let (data, sw) = split_status(response)?;
		if self.data.len() + data.len() > MAX_RESPONSE_BYTES {
			self.data.clear();
			return Err(Error::TooLong);
		}
		self.data.extend_from_slice(data);
		match sw {
			SW_OK => Ok(Step::Done(std::mem::take(&mut self.data))),
			SW_PENDING => Ok(Step::Pending),
			_ if sw >> 8 == u16::from(SW_MORE_DATA) => Ok(Step::MoreData { le: sw as u8 }),
			_ => {
				self.data.clear();
				Err(Error::Status(sw))
			}
		}
	}
}

fn split_status(response: &[u8]) -> Result<(&[u8], u16), Error> {
	let Some((data, sw)) = response.split_last_chunk::<2>() else {
		return Err(Error::Short);
	};
	Ok((data, u16::from_be_bytes(*sw)))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn payload_of(len: usize) -> Vec<u8> {
		(0..len).map(|i| (i * 13 % 253) as u8).collect()
	}

	#[test]
	fn select_known_answer() {
		assert_eq!(
			select(),
			hex::decode("00a4040008a0000006472f000100").unwrap()
		);
	}

	#[test]
	fn select_response_names_a_version() {
		assert_eq!(parse_select_response(b"U2F_V2\x90\x00"), Ok(Version::U2fV2));
		assert_eq!(
			parse_select_response(b"FIDO_2_0\x90\x00"),
			Ok(Version::Fido20)
		);
		assert_eq!(
			parse_select_response(b"FIDO_3_0\x90\x00"),
			Err(Error::UnknownVersion)
		);
		assert_eq!(
			parse_select_response(&[0x6A, 0x82]),
			Err(Error::Status(0x6A82))
		);
		assert_eq!(parse_select_response(&[0x90]), Err(Error::Short));
	}

	#[test]
	fn short_message_is_one_apdu() {
		let payload = payload_of(100);
		let apdus = ctap_message(&payload);
		assert_eq!(apdus.len(), 1);
		assert_eq!(&apdus[0][..5], &[0x80, 0x10, 0x80, 0x00, 0x64]);
		assert_eq!(&apdus[0][5..105], &payload[..]);
		assert_eq!(apdus[0][105..], [0x00]);
		assert_eq!(apdus[0].len(), 106);
	}

	#[test]
	fn long_message_chains_short_apdus() {
		let payload = payload_of(600);
		let apdus = ctap_message(&payload);
		assert_eq!(apdus.len(), 3);
		assert_eq!(&apdus[0][..5], &[0x90, 0x10, 0x80, 0x00, 0xFF]);
		assert_eq!(&apdus[0][5..], &payload[..255]);
		assert_eq!(apdus[0].len(), 260);
		assert_eq!(&apdus[1][..5], &[0x90, 0x10, 0x80, 0x00, 0xFF]);
		assert_eq!(&apdus[1][5..], &payload[255..510]);
		assert_eq!(apdus[1].len(), 260);
		assert_eq!(&apdus[2][..5], &[0x80, 0x10, 0x80, 0x00, 0x5A]);
		assert_eq!(&apdus[2][5..95], &payload[510..]);
		assert_eq!(apdus[2][95], 0x00);
		assert_eq!(apdus[2].len(), 96);
	}

	#[test]
	fn full_chunk_message_ends_with_a_data_apdu() {
		let apdus = ctap_message(&payload_of(255));
		assert_eq!(apdus.len(), 1);
		assert_eq!(apdus[0][0], 0x80);
		assert_eq!(apdus[0].len(), 261);
	}

	#[test]
	fn get_response_apdus() {
		assert_eq!(get_response(), vec![0x80, 0x11, 0x00, 0x00, 0x00]);
		assert_eq!(iso_get_response(0x10), vec![0x00, 0xC0, 0x00, 0x00, 0x10]);
	}

	#[test]
	fn success_is_done_with_the_data() {
		let mut assembler = ResponseAssembler::new();
		assert_eq!(
			assembler.push(&[0x00, 0xAA, 0xBB, 0x90, 0x00]),
			Ok(Step::Done(vec![0x00, 0xAA, 0xBB]))
		);
		assert_eq!(assembler.push(&[0x90, 0x00]), Ok(Step::Done(Vec::new())));
	}

	#[test]
	fn more_data_then_the_rest_concatenates() {
		let mut assembler = ResponseAssembler::new();
		assert_eq!(
			assembler.push(&[0x01, 0x02, 0x61, 0x10]),
			Ok(Step::MoreData { le: 0x10 })
		);
		assert_eq!(
			assembler.push(&[0x03, 0x04, 0x90, 0x00]),
			Ok(Step::Done(vec![0x01, 0x02, 0x03, 0x04]))
		);
	}

	#[test]
	fn pending_keeps_the_data_so_far() {
		let mut assembler = ResponseAssembler::new();
		assert_eq!(
			assembler.push(&[0x01, 0x02, 0x61, 0x00]),
			Ok(Step::MoreData { le: 0x00 })
		);
		assert_eq!(assembler.push(&[0x91, 0x00]), Ok(Step::Pending));
		assert_eq!(assembler.push(&[0x91, 0x00]), Ok(Step::Pending));
		assert_eq!(
			assembler.push(&[0x03, 0x90, 0x00]),
			Ok(Step::Done(vec![0x01, 0x02, 0x03]))
		);
	}

	#[test]
	fn other_status_is_an_error() {
		let mut assembler = ResponseAssembler::new();
		assert_eq!(
			assembler.push(&[0x01, 0x61, 0x05]),
			Ok(Step::MoreData { le: 0x05 })
		);
		assert_eq!(assembler.push(&[0x6A, 0x82]), Err(Error::Status(0x6A82)));
		assert_eq!(
			assembler.push(&[0x02, 0x90, 0x00]),
			Ok(Step::Done(vec![0x02]))
		);
		assert_eq!(assembler.push(&[0x90]), Err(Error::Short));
		assert_eq!(assembler.push(&[]), Err(Error::Short));
	}

	#[test]
	fn errors_display_plainly() {
		assert_eq!(
			Error::Status(0x6A82).to_string(),
			"the security key answered status 0x6a82."
		);
	}

	#[test]
	fn a_response_past_the_bound_is_refused_before_it_grows() {
		let mut assembler = ResponseAssembler::new();
		let chunk = [vec![0xAB; 256], vec![0x61, 0x00]].concat();
		for _ in 0..(MAX_RESPONSE_BYTES / 256) {
			assert_eq!(assembler.push(&chunk), Ok(Step::MoreData { le: 0 }));
		}
		assert_eq!(assembler.push(&chunk), Err(Error::TooLong));
		// The assembler is reusable afterwards.
		assert_eq!(
			assembler.push(&[0x01, 0x90, 0x00]),
			Ok(Step::Done(vec![0x01]))
		);
	}
}
