//! CTAPHID framing (CTAP 2.1 section 11.2). A message travels in 64-byte
//! packets: one initialization packet with the command and the payload
//! length, then continuation packets numbered from zero. This module frames
//! and reassembles; a head moves the packets.

use std::fmt;

/// Every CTAPHID packet is this long.
pub const PACKET_SIZE: usize = 64;
/// The channel every INIT request is sent on before a channel is allocated.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
/// The longest payload one message can carry: one initialization packet and
/// 128 continuation packets.
pub const MAX_PAYLOAD: usize = INIT_DATA + 128 * CONT_DATA;

/// Data bytes in an initialization packet after CID, CMD and BCNT.
const INIT_DATA: usize = PACKET_SIZE - 7;
/// Data bytes in a continuation packet after CID and SEQ.
const CONT_DATA: usize = PACKET_SIZE - 5;
/// The INIT response: nonce, CID, protocol version, three device version
/// bytes and the capability flags.
const INIT_RESPONSE_LEN: usize = 17;

/// KEEPALIVE status: the key is processing the command.
pub const KEEPALIVE_PROCESSING: u8 = 1;
/// KEEPALIVE status: the key waits for the user to touch it.
pub const KEEPALIVE_UPNEEDED: u8 = 2;

/// INIT response capability flag: the key answers WINK.
pub const CAPABILITY_WINK: u8 = 0x01;
/// INIT response capability flag: the key speaks CTAP2 over CBOR.
pub const CAPABILITY_CBOR: u8 = 0x04;
/// INIT response capability flag: the key does not accept MSG (U2F).
pub const CAPABILITY_NMSG: u8 = 0x08;

/// A CTAPHID command. On the wire the command byte carries bit 7 set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
	Ping,
	Msg,
	Init,
	Wink,
	Cbor,
	Cancel,
	KeepAlive,
	Error,
}

impl Command {
	/// The seven-bit command code, without the wire bit 7.
	pub fn code(self) -> u8 {
		match self {
			Self::Ping => 0x01,
			Self::Msg => 0x03,
			Self::Init => 0x06,
			Self::Wink => 0x08,
			Self::Cbor => 0x10,
			Self::Cancel => 0x11,
			Self::KeepAlive => 0x3B,
			Self::Error => 0x3F,
		}
	}

	/// The command for a code; bit 7 is ignored so a wire byte works too.
	pub fn from_code(code: u8) -> Option<Self> {
		match code & 0x7F {
			0x01 => Some(Self::Ping),
			0x03 => Some(Self::Msg),
			0x06 => Some(Self::Init),
			0x08 => Some(Self::Wink),
			0x10 => Some(Self::Cbor),
			0x11 => Some(Self::Cancel),
			0x3B => Some(Self::KeepAlive),
			0x3F => Some(Self::Error),
			_ => None,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// A payload longer than one message can carry.
	PayloadTooLarge(usize),
	/// An initialization packet with a command code this crate does not know.
	UnknownCommand(u8),
	/// A packet for a channel other than the one being read.
	WrongChannel { expected: u32, got: u32 },
	/// A continuation packet with no message in progress.
	UnexpectedContinuation,
	/// An initialization packet while a message was still in progress.
	UnexpectedInit,
	/// A continuation packet out of order.
	BadSequence { expected: u8, got: u8 },
	/// A payload length that does not fit the command.
	BadLength,
	/// An INIT response that echoes a nonce other than the one sent.
	NonceMismatch,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PayloadTooLarge(len) => {
				write!(f, "a CTAPHID payload of {len} bytes exceeds {MAX_PAYLOAD}.")
			}
			Self::UnknownCommand(code) => {
				write!(f, "unknown CTAPHID command 0x{code:02x}.")
			}
			Self::WrongChannel { expected, got } => write!(
				f,
				"CTAPHID packet for channel 0x{got:08x} while reading channel 0x{expected:08x}."
			),
			Self::UnexpectedContinuation => {
				f.write_str("CTAPHID continuation packet with no message in progress.")
			}
			Self::UnexpectedInit => {
				f.write_str("CTAPHID initialization packet while a message was in progress.")
			}
			Self::BadSequence { expected, got } => write!(
				f,
				"CTAPHID continuation packet {got} arrived; {expected} was expected."
			),
			Self::BadLength => f.write_str("CTAPHID payload length does not fit the command."),
			Self::NonceMismatch => {
				f.write_str("the CTAPHID INIT response echoed a different nonce.")
			}
		}
	}
}

impl std::error::Error for Error {}

/// Frame one message into packets, ready to write in order.
pub fn frame(cid: u32, command: Command, payload: &[u8]) -> Result<Vec<[u8; PACKET_SIZE]>, Error> {
	if payload.len() > MAX_PAYLOAD {
		return Err(Error::PayloadTooLarge(payload.len()));
	}
	let len = payload.len() as u16;
	let (head, rest) = payload.split_at(payload.len().min(INIT_DATA));
	let mut packets = Vec::with_capacity(1 + rest.len().div_ceil(CONT_DATA));
	let mut init = [0u8; PACKET_SIZE];
	init[..4].copy_from_slice(&cid.to_be_bytes());
	init[4] = command.code() | 0x80;
	init[5..7].copy_from_slice(&len.to_be_bytes());
	init[7..7 + head.len()].copy_from_slice(head);
	packets.push(init);
	for (seq, chunk) in rest.chunks(CONT_DATA).enumerate() {
		let mut cont = [0u8; PACKET_SIZE];
		cont[..4].copy_from_slice(&cid.to_be_bytes());
		cont[4] = seq as u8;
		cont[5..5 + chunk.len()].copy_from_slice(chunk);
		packets.push(cont);
	}
	Ok(packets)
}

/// The INIT request on the broadcast channel.
pub fn init_request(nonce: [u8; 8]) -> [u8; PACKET_SIZE] {
	frame(BROADCAST_CID, Command::Init, &nonce).expect("eight bytes fit one packet")[0]
}

/// The CANCEL packet for a channel; it carries no payload.
pub fn cancel(cid: u32) -> [u8; PACKET_SIZE] {
	frame(cid, Command::Cancel, &[]).expect("an empty payload fits one packet")[0]
}

/// What an INIT response says about the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitResponse {
	/// The channel allocated to this client.
	pub cid: u32,
	/// The CTAPHID protocol version, 2 for CTAP2.
	pub protocol_version: u8,
	/// Major, minor and build version of the device.
	pub device_version: [u8; 3],
	/// The `CAPABILITY_*` flags.
	pub capabilities: u8,
}

impl InitResponse {
	/// Whether the key speaks CTAP2 over CBOR.
	pub fn supports_cbor(&self) -> bool {
		self.capabilities & CAPABILITY_CBOR != 0
	}
}

/// Parse the payload of an INIT response and check it answers our nonce.
pub fn parse_init_response(payload: &[u8], nonce: [u8; 8]) -> Result<InitResponse, Error> {
	if payload.len() < INIT_RESPONSE_LEN {
		return Err(Error::BadLength);
	}
	if payload[..8] != nonce {
		return Err(Error::NonceMismatch);
	}
	let cid = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
	Ok(InitResponse {
		cid,
		protocol_version: payload[12],
		device_version: [payload[13], payload[14], payload[15]],
		capabilities: payload[16],
	})
}

/// What one pushed packet amounts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
	/// Part of a message; keep reading.
	Incomplete,
	/// A KEEPALIVE with its status byte; keep reading.
	KeepAlive(u8),
	/// A whole message.
	Message { command: Command, payload: Vec<u8> },
	/// A CTAPHID_ERROR with its error code.
	Error(u8),
}

/// Rebuilds messages from the packets read on one channel.
#[derive(Clone, Debug, Default)]
pub struct Reassembler {
	cid: u32,
	pending: Option<Pending>,
}

#[derive(Clone, Debug)]
struct Pending {
	command: Command,
	expected: usize,
	payload: Vec<u8>,
	seq: u8,
}

impl Reassembler {
	/// Read messages on one channel; `BROADCAST_CID` for the INIT response.
	pub fn new(cid: u32) -> Self {
		Self { cid, pending: None }
	}

	/// The channel this reassembler reads.
	pub fn cid(&self) -> u32 {
		self.cid
	}

	/// Push the next packet read from the device.
	pub fn push(&mut self, packet: &[u8; PACKET_SIZE]) -> Result<Event, Error> {
		let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
		if cid != self.cid {
			return Err(Error::WrongChannel {
				expected: self.cid,
				got: cid,
			});
		}
		if packet[4] & 0x80 != 0 {
			self.push_init(packet)
		} else {
			self.push_continuation(packet)
		}
	}

	fn push_init(&mut self, packet: &[u8; PACKET_SIZE]) -> Result<Event, Error> {
		let command = Command::from_code(packet[4]).ok_or(Error::UnknownCommand(packet[4]))?;
		let len = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
		if len > MAX_PAYLOAD {
			return Err(Error::PayloadTooLarge(len));
		}
		match command {
			Command::KeepAlive => {
				if len != 1 {
					return Err(Error::BadLength);
				}
				return Ok(Event::KeepAlive(packet[7]));
			}
			Command::Error => {
				self.pending = None;
				if len != 1 {
					return Err(Error::BadLength);
				}
				return Ok(Event::Error(packet[7]));
			}
			_ => {}
		}
		if self.pending.is_some() {
			self.pending = None;
			return Err(Error::UnexpectedInit);
		}
		let head = &packet[7..7 + len.min(INIT_DATA)];
		if len <= INIT_DATA {
			return Ok(Event::Message {
				command,
				payload: head.to_vec(),
			});
		}
		let mut payload = Vec::with_capacity(len);
		payload.extend_from_slice(head);
		self.pending = Some(Pending {
			command,
			expected: len,
			payload,
			seq: 0,
		});
		Ok(Event::Incomplete)
	}

	fn push_continuation(&mut self, packet: &[u8; PACKET_SIZE]) -> Result<Event, Error> {
		let Some(pending) = self.pending.as_mut() else {
			return Err(Error::UnexpectedContinuation);
		};
		if packet[4] != pending.seq {
			let expected = pending.seq;
			self.pending = None;
			return Err(Error::BadSequence {
				expected,
				got: packet[4],
			});
		}
		let remaining = pending.expected - pending.payload.len();
		pending
			.payload
			.extend_from_slice(&packet[5..5 + remaining.min(CONT_DATA)]);
		pending.seq += 1;
		if pending.payload.len() < pending.expected {
			return Ok(Event::Incomplete);
		}
		let done = self.pending.take().expect("a message was in progress");
		Ok(Event::Message {
			command: done.command,
			payload: done.payload,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const CID: u32 = 0x1234_5678;

	fn feed(reassembler: &mut Reassembler, packets: &[[u8; PACKET_SIZE]]) -> Event {
		let mut last = Event::Incomplete;
		for packet in packets {
			last = reassembler.push(packet).expect("packet accepted");
		}
		last
	}

	fn payload_of(len: usize) -> Vec<u8> {
		(0..len).map(|i| (i * 7 % 251) as u8).collect()
	}

	#[test]
	fn command_codes_round_trip() {
		for command in [
			Command::Ping,
			Command::Msg,
			Command::Init,
			Command::Wink,
			Command::Cbor,
			Command::Cancel,
			Command::KeepAlive,
			Command::Error,
		] {
			assert_eq!(Command::from_code(command.code()), Some(command));
			assert_eq!(Command::from_code(command.code() | 0x80), Some(command));
		}
		assert_eq!(Command::from_code(0x02), None);
	}

	#[test]
	fn single_packet_round_trip() {
		let payload = payload_of(20);
		let packets = frame(CID, Command::Cbor, &payload).unwrap();
		assert_eq!(packets.len(), 1);
		assert_eq!(&packets[0][..4], &CID.to_be_bytes());
		assert_eq!(packets[0][4], 0x90);
		assert_eq!(&packets[0][5..7], &[0x00, 0x14]);
		assert_eq!(&packets[0][7..27], &payload[..]);
		assert!(packets[0][27..].iter().all(|&b| b == 0));
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(
			feed(&mut reassembler, &packets),
			Event::Message {
				command: Command::Cbor,
				payload
			}
		);
	}

	#[test]
	fn full_initialization_packet_needs_no_continuation() {
		let payload = payload_of(57);
		let packets = frame(CID, Command::Msg, &payload).unwrap();
		assert_eq!(packets.len(), 1);
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(
			feed(&mut reassembler, &packets),
			Event::Message {
				command: Command::Msg,
				payload
			}
		);
	}

	#[test]
	fn multi_packet_command_frames_and_reassembles() {
		let payload = payload_of(300);
		let packets = frame(CID, Command::Cbor, &payload).unwrap();
		assert_eq!(packets.len(), 6);
		assert_eq!(packets[0][4], 0x90);
		assert_eq!(&packets[0][5..7], &[0x01, 0x2C]);
		for (i, packet) in packets[1..].iter().enumerate() {
			assert_eq!(&packet[..4], &CID.to_be_bytes());
			assert_eq!(packet[4], i as u8);
		}
		assert_eq!(&packets[5][5..12], &payload[293..300]);
		assert!(packets[5][12..].iter().all(|&b| b == 0));
		let mut reassembler = Reassembler::new(CID);
		for packet in &packets[..5] {
			assert_eq!(reassembler.push(packet), Ok(Event::Incomplete));
		}
		assert_eq!(
			reassembler.push(&packets[5]),
			Ok(Event::Message {
				command: Command::Cbor,
				payload
			})
		);
	}

	#[test]
	fn maximum_payload_frames_and_one_more_is_refused() {
		let payload = payload_of(MAX_PAYLOAD);
		assert_eq!(MAX_PAYLOAD, 7609);
		let packets = frame(CID, Command::Cbor, &payload).unwrap();
		assert_eq!(packets.len(), 129);
		assert_eq!(packets[128][4], 0x7F);
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(
			feed(&mut reassembler, &packets),
			Event::Message {
				command: Command::Cbor,
				payload
			}
		);
		assert_eq!(
			frame(CID, Command::Cbor, &payload_of(MAX_PAYLOAD + 1)),
			Err(Error::PayloadTooLarge(7610))
		);
	}

	#[test]
	fn keepalive_then_read_again() {
		let payload = payload_of(100);
		let packets = frame(CID, Command::Cbor, &payload).unwrap();
		assert_eq!(packets.len(), 2);
		let processing = frame(CID, Command::KeepAlive, &[KEEPALIVE_PROCESSING]).unwrap();
		let upneeded = frame(CID, Command::KeepAlive, &[KEEPALIVE_UPNEEDED]).unwrap();
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(
			reassembler.push(&processing[0]),
			Ok(Event::KeepAlive(KEEPALIVE_PROCESSING))
		);
		assert_eq!(
			reassembler.push(&upneeded[0]),
			Ok(Event::KeepAlive(KEEPALIVE_UPNEEDED))
		);
		assert_eq!(reassembler.push(&packets[0]), Ok(Event::Incomplete));
		assert_eq!(
			reassembler.push(&processing[0]),
			Ok(Event::KeepAlive(KEEPALIVE_PROCESSING))
		);
		assert_eq!(
			reassembler.push(&packets[1]),
			Ok(Event::Message {
				command: Command::Cbor,
				payload
			})
		);
	}

	#[test]
	fn cancel_packet_layout() {
		let packet = cancel(CID);
		assert_eq!(&packet[..4], &CID.to_be_bytes());
		assert_eq!(packet[4], 0x91);
		assert!(packet[5..].iter().all(|&b| b == 0));
	}

	#[test]
	fn error_packet_reports_the_code_and_drops_the_message() {
		let packets = frame(CID, Command::Cbor, &payload_of(100)).unwrap();
		let error = frame(CID, Command::Error, &[0x2D]).unwrap();
		assert_eq!(error[0][4], 0xBF);
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(reassembler.push(&packets[0]), Ok(Event::Incomplete));
		assert_eq!(reassembler.push(&error[0]), Ok(Event::Error(0x2D)));
		assert_eq!(
			reassembler.push(&packets[1]),
			Err(Error::UnexpectedContinuation)
		);
	}

	#[test]
	fn wrong_channel_is_refused_and_the_message_survives() {
		let payload = payload_of(100);
		let packets = frame(CID, Command::Cbor, &payload).unwrap();
		let other = frame(CID + 1, Command::Cbor, &payload).unwrap();
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(reassembler.push(&packets[0]), Ok(Event::Incomplete));
		assert_eq!(
			reassembler.push(&other[1]),
			Err(Error::WrongChannel {
				expected: CID,
				got: CID + 1
			})
		);
		assert_eq!(
			reassembler.push(&packets[1]),
			Ok(Event::Message {
				command: Command::Cbor,
				payload
			})
		);
	}

	#[test]
	fn bad_sequence_is_refused() {
		let packets = frame(CID, Command::Cbor, &payload_of(300)).unwrap();
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(reassembler.push(&packets[0]), Ok(Event::Incomplete));
		assert_eq!(reassembler.push(&packets[1]), Ok(Event::Incomplete));
		assert_eq!(
			reassembler.push(&packets[3]),
			Err(Error::BadSequence {
				expected: 1,
				got: 2
			})
		);
		assert_eq!(
			reassembler.push(&packets[2]),
			Err(Error::UnexpectedContinuation)
		);
	}

	#[test]
	fn continuation_without_a_message_is_refused() {
		let packets = frame(CID, Command::Cbor, &payload_of(300)).unwrap();
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(
			reassembler.push(&packets[1]),
			Err(Error::UnexpectedContinuation)
		);
	}

	#[test]
	fn initialization_packet_during_a_message_is_refused() {
		let packets = frame(CID, Command::Cbor, &payload_of(300)).unwrap();
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(reassembler.push(&packets[0]), Ok(Event::Incomplete));
		assert_eq!(reassembler.push(&packets[0]), Err(Error::UnexpectedInit));
	}

	#[test]
	fn unknown_command_and_oversized_length_are_refused() {
		let mut packet = [0u8; PACKET_SIZE];
		packet[..4].copy_from_slice(&CID.to_be_bytes());
		packet[4] = 0x82;
		let mut reassembler = Reassembler::new(CID);
		assert_eq!(reassembler.push(&packet), Err(Error::UnknownCommand(0x82)));
		packet[4] = 0x90;
		packet[5..7].copy_from_slice(&7610u16.to_be_bytes());
		assert_eq!(reassembler.push(&packet), Err(Error::PayloadTooLarge(7610)));
	}

	#[test]
	fn init_request_known_answer() {
		let packet = init_request([0, 1, 2, 3, 4, 5, 6, 7]);
		let expected = hex::decode("ffffffff860008000102030405060708").unwrap();
		assert_eq!(&packet[..15], &expected[..15]);
		assert!(packet[15..].iter().all(|&b| b == 0));
	}

	#[test]
	fn init_response_layout_parses() {
		let nonce = [0, 1, 2, 3, 4, 5, 6, 7];
		let payload = hex::decode("00010203040506071234567802050403050000").unwrap();
		let parsed = parse_init_response(&payload[..17], nonce).unwrap();
		assert_eq!(
			parsed,
			InitResponse {
				cid: CID,
				protocol_version: 2,
				device_version: [5, 4, 3],
				capabilities: CAPABILITY_WINK | CAPABILITY_CBOR,
			}
		);
		assert!(parsed.supports_cbor());
		assert_eq!(
			parse_init_response(&payload[..16], nonce),
			Err(Error::BadLength)
		);
		assert_eq!(
			parse_init_response(&payload[..17], [7, 6, 5, 4, 3, 2, 1, 0]),
			Err(Error::NonceMismatch)
		);
	}

	#[test]
	fn init_response_is_read_on_the_broadcast_channel() {
		let nonce = [9u8; 8];
		let mut payload = nonce.to_vec();
		payload.extend_from_slice(&CID.to_be_bytes());
		payload.extend_from_slice(&[2, 1, 0, 0, CAPABILITY_CBOR]);
		let packets = frame(BROADCAST_CID, Command::Init, &payload).unwrap();
		let mut reassembler = Reassembler::new(BROADCAST_CID);
		let Event::Message { command, payload } = reassembler.push(&packets[0]).unwrap() else {
			panic!("one packet carries the INIT response");
		};
		assert_eq!(command, Command::Init);
		assert_eq!(parse_init_response(&payload, nonce).unwrap().cid, CID);
	}

	#[test]
	fn errors_display_plainly() {
		assert_eq!(
			Error::BadSequence {
				expected: 1,
				got: 2
			}
			.to_string(),
			"CTAPHID continuation packet 2 arrived; 1 was expected."
		);
		assert_eq!(
			Error::PayloadTooLarge(7610).to_string(),
			"a CTAPHID payload of 7610 bytes exceeds 7609."
		);
	}
}
