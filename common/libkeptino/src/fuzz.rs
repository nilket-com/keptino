//! Fuzz target bodies (ADR 0026): one function per untrusted input, each
//! taking arbitrary bytes. A target must not panic, and where a parser has
//! an encoder it checks that what it accepts survives a round trip. The
//! libFuzzer crate in `fuzz/` calls these, and the smoke test below runs
//! them over seeds and deterministic mutations in every `cargo test`.

use crate::crypto;
use crate::format::{self, Envelope, FieldAtlas, KdfParams};
use crate::roaming::KeySlot;

/// What a stored vault file can carry before any key: shard repair and the
/// envelope reader.
pub fn shards(data: &[u8]) {
	if let Ok(recovered) = format::decode_shards(data) {
		assert!(recovered.len() <= data.len(), "repair never grows the file");
		let again = format::decode_shards(&format::encode_shards(&recovered));
		assert_eq!(again.as_deref(), Ok(recovered.as_slice()));
	}
	let _ = Envelope::parse(data, KdfParams::DEBUG);
}

/// The envelope reader on a payload already recovered from its shards: the
/// plaintext meta entries, cost, revision, nonce, salt and key slots.
pub fn envelope(data: &[u8]) {
	let Ok(envelope) = Envelope::read(data, KdfParams::DEBUG) else {
		return;
	};
	assert!(KdfParams::M_COST.contains(&envelope.kdf.m_cost));
	assert!(KdfParams::T_COST.contains(&envelope.kdf.t_cost));
	assert!(KdfParams::P_COST.contains(&envelope.kdf.p_cost));
	assert!(envelope.mirror.iter().all(|(name, _)| name != "db"));
	// Writing the same entries back reads as the same envelope.
	let file = format::encode_envelope(&envelope.mirror, &envelope.ciphertext);
	let again = Envelope::parse(&file, KdfParams::DEBUG).expect("rewritten envelope");
	assert_eq!(again.mirror, envelope.mirror);
	assert_eq!(again.ciphertext, envelope.ciphertext);
	assert_eq!(again.kdf, envelope.kdf);
	assert_eq!(again.aad, envelope.aad);
}

/// What only a holder of the vault key can write: the compressed database
/// after decryption, its meta entries and its entry records.
pub fn payload(data: &[u8]) {
	if let Ok(database) = crypto::decompress(data, 1 << 20) {
		assert!(database.len() <= 1 << 20, "the budget holds");
		records(&database);
	}
	records(data);
}

fn records(data: &[u8]) {
	let _ = format::meta_pairs(data);
	let Ok(entries) = format::deserialize_entries(data) else {
		return;
	};
	// Fields are kept by id; a record whose ids are already in order and
	// distinct serializes back to its own bytes.
	for (_, atlas) in &entries {
		let bytes = atlas.serialize();
		let again = FieldAtlas::deserialize(&bytes).expect("reserialized fields");
		assert_eq!(*again.serialize(), *bytes);
	}
}

/// A key slot as a meta entry value.
pub fn slot(data: &[u8]) {
	let Ok(text) = std::str::from_utf8(data) else {
		return;
	};
	if let Ok(slot) = KeySlot::decode(text) {
		let encoded = slot.encode();
		let again = KeySlot::decode(&encoded).expect("reencoded slot");
		assert_eq!(again.encode(), encoded);
	}
}

/// What an S3 store answers, and the endpoint and bucket a user types.
#[cfg(feature = "s3")]
pub fn s3(data: &[u8]) {
	let _ = crate::s3::is_missing_key(data);
	let text = String::from_utf8_lossy(data);
	if let Ok(endpoint) = crate::s3::validate_endpoint(&text) {
		assert!(!endpoint.host().is_empty());
		assert!(crate::s3::validate_endpoint(endpoint.url()).is_ok());
	}
	let _ = crate::s3::validate_bucket(&text);
	let _ = crate::s3::encode_segment(&text);
}

/// CBOR from a security key: decoding, and canonical re-encoding of what
/// decodes.
#[cfg(feature = "fido")]
pub fn cbor(data: &[u8]) {
	use crate::fido::cbor;
	if let Ok(value) = cbor::decode(data) {
		assert_eq!(cbor::decode(&cbor::encode(&value)), Ok(value));
	}
}

/// CTAP2 responses from a security key, read as every reply the ceremonies
/// expect.
#[cfg(feature = "fido")]
pub fn ctap(data: &[u8]) {
	use crate::fido::ctap;
	let _ = ctap::AuthData::parse(data);
	if let Ok(Some(body)) = ctap::response(data) {
		let _ = ctap::Info::parse(&body);
		let _ = ctap::key_agreement_from(&body);
		let _ = ctap::pin_token_from(&body);
		let _ = ctap::make_credential_from(&body);
		let _ = ctap::assertion_from(&body);
	}
}

/// USB HID packets from a security key: the first four bytes choose the
/// channel and the rest is read as 64-byte packets. Framing a message and
/// reading it back gives the message.
#[cfg(feature = "fido")]
pub fn hid(data: &[u8]) {
	use crate::fido::hid::{self, Command, Event, PACKET_SIZE, Reassembler};
	let _ = hid::parse_init_response(data, [7; 8]);
	let Some((cid, packets)) = data.split_first_chunk::<4>() else {
		return;
	};
	let cid = u32::from_be_bytes(*cid);
	let mut reader = Reassembler::new(cid);
	for chunk in packets.chunks(PACKET_SIZE) {
		let mut packet = [0u8; PACKET_SIZE];
		packet[..chunk.len()].copy_from_slice(chunk);
		if let Ok(Event::Message { payload, .. }) = reader.push(&packet) {
			assert!(payload.len() <= hid::MAX_PAYLOAD);
		}
	}
	if let Ok(frames) = hid::frame(cid, Command::Cbor, packets) {
		let mut reader = Reassembler::new(cid);
		let mut read = None;
		for packet in &frames {
			if let Event::Message { command, payload } = reader.push(packet).expect("own framing") {
				assert_eq!(command, Command::Cbor);
				read = Some(payload);
			}
		}
		assert_eq!(read.as_deref(), Some(packets));
	}
}

/// NFC responses from a security key: the select answer, and responses
/// chained by status words, each part prefixed by a length byte.
#[cfg(feature = "fido")]
pub fn nfc(data: &[u8]) {
	use crate::fido::nfc::{self, ResponseAssembler, Step};
	let _ = nfc::parse_select_response(data);
	let mut assembler = ResponseAssembler::new();
	let mut rest = data;
	while let Some((&len, tail)) = rest.split_first() {
		let (part, tail) = tail.split_at(usize::from(len).min(tail.len()));
		rest = tail;
		if let Ok(Step::Done(response)) = assembler.push(part) {
			assert!(response.len() <= data.len());
		}
	}
}

/// One fuzz target body.
pub type Target = fn(&[u8]);

/// Every target with its name, for the smoke test and the fuzz crate.
pub const TARGETS: &[(&str, Target)] = &[
	("shards", shards),
	("envelope", envelope),
	("payload", payload),
	("slot", slot),
	#[cfg(feature = "s3")]
	("s3", s3),
	#[cfg(feature = "fido")]
	("cbor", cbor),
	#[cfg(feature = "fido")]
	("ctap", ctap),
	#[cfg(feature = "fido")]
	("hid", hid),
	#[cfg(feature = "fido")]
	("nfc", nfc),
];

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::{KEY_SIZE, NONCE_SIZE, ROAMING_SIZE, SALT_SIZE};
	use crate::roaming::{SLOT_SALT_SIZE, SLOT_VERSION};
	use crate::vault::tests::HeapKey;
	use crate::vault::{Database, KeyStore, PasswordEntry};
	use base64ct::{Base64, Encoding};

	/// Deterministic, so a failure reproduces from the test name alone.
	struct Mutator(u64);

	impl Mutator {
		fn next(&mut self) -> u64 {
			// xorshift64*
			self.0 ^= self.0 >> 12;
			self.0 ^= self.0 << 25;
			self.0 ^= self.0 >> 27;
			self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
		}

		fn below(&mut self, n: usize) -> usize {
			(self.next() % n.max(1) as u64) as usize
		}

		/// One to four edits: flip a bit, set a byte to an edge value,
		/// insert, delete a run, truncate, duplicate a run.
		fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
			let mut data = seed.to_vec();
			for _ in 0..=self.below(4) {
				let at = self.below(data.len() + 1);
				match self.below(6) {
					0 if at < data.len() => data[at] ^= 1 << self.below(8),
					1 if at < data.len() => {
						data[at] = [0x00, 0x01, 0x7f, 0x80, 0xff][self.below(5)];
					}
					2 => data.insert(at, self.next() as u8),
					3 => {
						let end = (at + self.below(16)).min(data.len());
						data.drain(at..end);
					}
					4 => data.truncate(at),
					_ => {
						let end = (at + self.below(32)).min(data.len());
						let run = data[at..end].to_vec();
						let to = self.below(data.len() + 1);
						data.splice(to..to, run);
					}
				}
			}
			data
		}
	}

	fn vault_file() -> Vec<u8> {
		let key = HeapKey::from_bytes(&[42; KEY_SIZE]).unwrap();
		let db = Database::new(key, "seed", &[7; SALT_SIZE]);
		let mut entry = PasswordEntry::<HeapKey>::new();
		entry.set_name("bank");
		entry.set_password("hunter2");
		db.set_password_entry(entry);
		db.encode(true, KdfParams::DEBUG).unwrap()
	}

	fn seeds(name: &str) -> Vec<Vec<u8>> {
		let file = vault_file();
		let recovered = format::decode_shards(&file).unwrap();
		let mut atlas = FieldAtlas::default();
		atlas.set(1, b"bank");
		atlas.set(3, b"hunter2");
		let entries = format::serialize_entries([(2u8, atlas.serialize().as_slice())].into_iter());
		match name {
			"shards" => vec![file],
			"envelope" => vec![recovered],
			"payload" => vec![
				crypto::compress(&entries).to_vec(),
				entries.to_vec(),
				recovered,
			],
			"slot" => vec![
				b"AQAAEA==".to_vec(),
				Base64::encode_string(
					&[
						&[SLOT_VERSION, 1, 0, 16][..],
						&[3; 16],
						&[5; SLOT_SALT_SIZE],
						&[6; NONCE_SIZE],
						&[8; ROAMING_SIZE + 16],
					]
					.concat(),
				)
				.into_bytes(),
			],
			"s3" => vec![
				b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>".to_vec(),
				b"https://s3.example.com:9000".to_vec(),
				b"my-bucket".to_vec(),
			],
			#[cfg(feature = "fido")]
			"cbor" | "ctap" => fido_seeds(name == "ctap"),
			#[cfg(feature = "fido")]
			"hid" => {
				let mut data = 0x0102_0304u32.to_be_bytes().to_vec();
				for packet in crate::fido::hid::frame(
					0x0102_0304,
					crate::fido::hid::Command::Cbor,
					&[0xa1, 0x01, 0x02].repeat(40),
				)
				.unwrap()
				{
					data.extend_from_slice(&packet);
				}
				vec![data]
			}
			#[cfg(feature = "fido")]
			"nfc" => vec![
				b"FIDO_2_0\x90\x00".to_vec(),
				[&[4u8][..], b"ab\x61\x02", &[4], b"cd\x90\x00"].concat(),
			],
			_ => vec![Vec::new()],
		}
	}

	#[cfg(feature = "fido")]
	fn fido_seeds(status: bool) -> Vec<Vec<u8>> {
		use crate::fido::cbor::{Value, encode};
		let info = Value::map([
			(
				Value::Unsigned(1),
				Value::Array(vec![Value::Text("FIDO_2_0".into())]),
			),
			(
				Value::Unsigned(2),
				Value::Array(vec![Value::Text("hmac-secret".into())]),
			),
			(Value::Unsigned(3), Value::Bytes(vec![0; 16])),
			(
				Value::Unsigned(6),
				Value::Array(vec![Value::Unsigned(2), Value::Unsigned(1)]),
			),
		])
		.unwrap();
		let auth_data = [vec![9; 32], vec![0x01], vec![0, 0, 0, 5]].concat();
		let assertion = Value::map([
			(Value::Unsigned(2), Value::Bytes(auth_data.clone())),
			(Value::Unsigned(3), Value::Bytes(vec![1; 70])),
		])
		.unwrap();
		let prefix: &[u8] = if status { &[0] } else { &[] };
		let mut seeds: Vec<Vec<u8>> = [info, assertion]
			.iter()
			.map(|value| [prefix, &encode(value)].concat())
			.collect();
		if status {
			seeds.push(auth_data);
		}
		seeds
	}

	#[test]
	fn every_target_survives_its_seeds_and_their_mutations() {
		// KEPTINO_FUZZ_ROUNDS runs longer, still deterministic.
		let rounds = std::env::var("KEPTINO_FUZZ_ROUNDS")
			.ok()
			.and_then(|rounds| rounds.parse().ok())
			.unwrap_or(400);
		for (index, (name, target)) in TARGETS.iter().enumerate() {
			let seeds = seeds(name);
			assert!(!seeds.is_empty(), "{name} has seeds");
			let mut mutator = Mutator(0x9E37_79B9_7F4A_7C15 ^ index as u64);
			for seed in &seeds {
				target(seed);
				target(&[]);
				for _ in 0..rounds {
					target(&mutator.mutate(seed));
				}
			}
		}
	}

	#[test]
	fn the_seeds_reach_past_the_first_refusal() {
		// A seed every parser refuses would make the mutations above test
		// little but the first length check.
		assert!(Envelope::parse(&seeds("shards")[0], KdfParams::DEBUG).is_ok());
		assert!(Envelope::read(&seeds("envelope")[0], KdfParams::DEBUG).is_ok());
		assert!(crypto::decompress(&seeds("payload")[0], 1 << 20).is_ok());
		assert!(KeySlot::decode(std::str::from_utf8(&seeds("slot")[1]).unwrap()).is_ok());
	}
}
