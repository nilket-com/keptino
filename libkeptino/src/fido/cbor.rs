//! Canonical CBOR, the form CTAP2 requires (RFC 8949 with the CTAP2
//! canonical rules): every integer and length in its shortest encoding,
//! definite lengths only, no tags, no floats, and map keys sorted by major
//! type, then encoded length, then bytewise, with no two equal. The encoder
//! writes nothing else and the decoder accepts nothing else, so a message
//! round trips byte for byte or is refused.

use std::{cmp::Ordering, fmt};

/// The deepest nesting of arrays and maps the decoder follows.
pub const MAX_DEPTH: usize = 16;
/// The longest message the decoder reads. CTAP2 messages fit in 7609 bytes.
pub const MAX_BYTES: usize = 64 << 10;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 0xf4;
const SIMPLE_TRUE: u8 = 0xf5;
const SIMPLE_NULL: u8 = 0xf6;

/// One CBOR data item. A map is a vector of pairs in canonical key order;
/// build one with [`Value::map`] to have it sorted and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
	Unsigned(u64),
	/// A negative integer from -1 down to -2^63. A non-negative value here
	/// is the same integer and encodes as `Unsigned`.
	Negative(i64),
	Bytes(Vec<u8>),
	Text(String),
	Array(Vec<Value>),
	Map(Vec<(Value, Value)>),
	Bool(bool),
	Null,
}

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// The message is longer than `MAX_BYTES`.
	TooLong,
	/// The message ends inside an item.
	Truncated,
	/// Bytes follow the single top-level item.
	TrailingBytes,
	/// Arrays or maps nest deeper than `MAX_DEPTH`.
	TooDeep,
	/// An integer or length is not in its shortest encoding.
	NotShortest,
	/// An indefinite-length item or a break code.
	Indefinite,
	/// Additional information 28 to 30, reserved by RFC 8949.
	Reserved,
	/// A tagged item.
	Tag,
	/// A simple value or float other than false, true and null.
	UnsupportedSimple,
	/// A negative integer below -2^63.
	NegativeOutOfRange,
	/// A text string that is not UTF-8.
	InvalidUtf8,
	/// Map keys out of canonical order.
	UnsortedKeys,
	/// Two equal keys in one map.
	DuplicateKey,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TooLong => write!(f, "the message is longer than {} KiB.", MAX_BYTES >> 10),
			Self::Truncated => f.write_str("the message ends inside an item."),
			Self::TrailingBytes => f.write_str("bytes follow the end of the message."),
			Self::TooDeep => write!(f, "arrays or maps nest deeper than {MAX_DEPTH} levels."),
			Self::NotShortest => {
				f.write_str("an integer or length is not in its shortest encoding.")
			}
			Self::Indefinite => f.write_str("an indefinite-length item or a break code."),
			Self::Reserved => f.write_str("a reserved additional information value."),
			Self::Tag => f.write_str("a tagged item; CTAP2 forbids tags."),
			Self::UnsupportedSimple => {
				f.write_str("a simple value or float other than false, true and null.")
			}
			Self::NegativeOutOfRange => f.write_str("a negative integer below -2^63."),
			Self::InvalidUtf8 => f.write_str("a text string that is not UTF-8."),
			Self::UnsortedKeys => f.write_str("map keys out of canonical order."),
			Self::DuplicateKey => f.write_str("two equal keys in one map."),
		}
	}
}

impl std::error::Error for Error {}

impl Value {
	/// Build a map in canonical key order. Refuses two equal keys.
	pub fn map(pairs: impl IntoIterator<Item = (Value, Value)>) -> Result<Value, Error> {
		let mut keyed: Vec<(Vec<u8>, (Value, Value))> = pairs
			.into_iter()
			.map(|pair| (encode(&pair.0), pair))
			.collect();
		keyed.sort_by(|a, b| compare_keys(&a.0, &b.0));
		if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
			return Err(Error::DuplicateKey);
		}
		Ok(Value::Map(
			keyed.into_iter().map(|(_, pair)| pair).collect(),
		))
	}

	pub fn as_u64(&self) -> Option<u64> {
		match self {
			Value::Unsigned(n) => Some(*n),
			_ => None,
		}
	}

	pub fn as_bytes(&self) -> Option<&[u8]> {
		match self {
			Value::Bytes(b) => Some(b),
			_ => None,
		}
	}

	pub fn as_text(&self) -> Option<&str> {
		match self {
			Value::Text(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_array(&self) -> Option<&[Value]> {
		match self {
			Value::Array(items) => Some(items),
			_ => None,
		}
	}

	pub fn as_map(&self) -> Option<&[(Value, Value)]> {
		match self {
			Value::Map(pairs) => Some(pairs),
			_ => None,
		}
	}

	pub fn as_bool(&self) -> Option<bool> {
		match self {
			Value::Bool(b) => Some(*b),
			_ => None,
		}
	}

	/// The value under `key` in a map; `None` for a missing key or a non-map.
	pub fn get(&self, key: &Value) -> Option<&Value> {
		self.as_map()?
			.iter()
			.find(|(k, _)| k == key)
			.map(|(_, v)| v)
	}
}

impl From<u64> for Value {
	fn from(n: u64) -> Self {
		Value::Unsigned(n)
	}
}

impl From<&str> for Value {
	fn from(s: &str) -> Self {
		Value::Text(s.to_owned())
	}
}

impl From<Vec<u8>> for Value {
	fn from(bytes: Vec<u8>) -> Self {
		Value::Bytes(bytes)
	}
}

impl From<bool> for Value {
	fn from(b: bool) -> Self {
		Value::Bool(b)
	}
}

/// The CTAP2 key order over two encoded keys: major type, then encoded
/// length, then bytewise.
fn compare_keys(a: &[u8], b: &[u8]) -> Ordering {
	(a[0] >> 5, a.len(), a).cmp(&(b[0] >> 5, b.len(), b))
}

/// Encode a value in canonical form. A map built by other means than
/// [`Value::map`] is written in the order it holds.
pub fn encode(value: &Value) -> Vec<u8> {
	let mut out = Vec::new();
	write(value, &mut out);
	out
}

fn write(value: &Value, out: &mut Vec<u8>) {
	match value {
		Value::Unsigned(n) => head(MAJOR_UNSIGNED, *n, out),
		Value::Negative(n) if *n < 0 => head(MAJOR_NEGATIVE, (-1 - *n) as u64, out),
		Value::Negative(n) => head(MAJOR_UNSIGNED, *n as u64, out),
		Value::Bytes(bytes) => {
			head(MAJOR_BYTES, bytes.len() as u64, out);
			out.extend_from_slice(bytes);
		}
		Value::Text(text) => {
			head(MAJOR_TEXT, text.len() as u64, out);
			out.extend_from_slice(text.as_bytes());
		}
		Value::Array(items) => {
			head(MAJOR_ARRAY, items.len() as u64, out);
			for item in items {
				write(item, out);
			}
		}
		Value::Map(pairs) => {
			head(MAJOR_MAP, pairs.len() as u64, out);
			for (key, value) in pairs {
				write(key, out);
				write(value, out);
			}
		}
		Value::Bool(false) => out.push(SIMPLE_FALSE),
		Value::Bool(true) => out.push(SIMPLE_TRUE),
		Value::Null => out.push(SIMPLE_NULL),
	}
}

/// Write the initial byte and the shortest argument that holds the value.
fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
	let major = major << 5;
	if argument < 24 {
		out.push(major | argument as u8);
	} else if argument <= 0xff {
		out.push(major | 24);
		out.push(argument as u8);
	} else if argument <= 0xffff {
		out.push(major | 25);
		out.extend_from_slice(&(argument as u16).to_be_bytes());
	} else if argument <= 0xffff_ffff {
		out.push(major | 26);
		out.extend_from_slice(&(argument as u32).to_be_bytes());
	} else {
		out.push(major | 27);
		out.extend_from_slice(&argument.to_be_bytes());
	}
}

/// Decode one canonical message. Anything that `encode` would not have
/// written is refused with the first reason met.
pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
	if bytes.len() > MAX_BYTES {
		return Err(Error::TooLong);
	}
	let mut decoder = Decoder {
		input: bytes,
		pos: 0,
	};
	let value = decoder.item(0)?;
	if decoder.pos != bytes.len() {
		return Err(Error::TrailingBytes);
	}
	Ok(value)
}

struct Decoder<'a> {
	input: &'a [u8],
	pos: usize,
}

impl<'a> Decoder<'a> {
	fn byte(&mut self) -> Result<u8, Error> {
		let b = *self.input.get(self.pos).ok_or(Error::Truncated)?;
		self.pos += 1;
		Ok(b)
	}

	fn take(&mut self, len: u64) -> Result<&'a [u8], Error> {
		let remaining = self.input.len() - self.pos;
		if len > remaining as u64 {
			return Err(Error::Truncated);
		}
		let start = self.pos;
		self.pos += len as usize;
		Ok(&self.input[start..self.pos])
	}

	/// Read the argument that follows an initial byte and check that it
	/// is in its shortest form.
	fn argument(&mut self, additional: u8) -> Result<u64, Error> {
		match additional {
			0..=23 => Ok(u64::from(additional)),
			24 => {
				let n = u64::from(self.byte()?);
				if n < 24 {
					return Err(Error::NotShortest);
				}
				Ok(n)
			}
			25 => {
				let n = u64::from(u16::from_be_bytes(self.fixed()?));
				if n <= 0xff {
					return Err(Error::NotShortest);
				}
				Ok(n)
			}
			26 => {
				let n = u64::from(u32::from_be_bytes(self.fixed()?));
				if n <= 0xffff {
					return Err(Error::NotShortest);
				}
				Ok(n)
			}
			27 => {
				let n = u64::from_be_bytes(self.fixed()?);
				if n <= 0xffff_ffff {
					return Err(Error::NotShortest);
				}
				Ok(n)
			}
			28..=30 => Err(Error::Reserved),
			_ => Err(Error::Indefinite),
		}
	}

	fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
		let slice = self.take(N as u64)?;
		let mut out = [0; N];
		out.copy_from_slice(slice);
		Ok(out)
	}

	fn item(&mut self, depth: usize) -> Result<Value, Error> {
		let initial = self.byte()?;
		let major = initial >> 5;
		let additional = initial & 0x1f;
		if major == MAJOR_SIMPLE {
			return match initial {
				SIMPLE_FALSE => Ok(Value::Bool(false)),
				SIMPLE_TRUE => Ok(Value::Bool(true)),
				SIMPLE_NULL => Ok(Value::Null),
				0xff => Err(Error::Indefinite),
				_ => Err(Error::UnsupportedSimple),
			};
		}
		let argument = self.argument(additional)?;
		match major {
			MAJOR_UNSIGNED => Ok(Value::Unsigned(argument)),
			MAJOR_NEGATIVE => {
				let n = i64::try_from(argument).map_err(|_| Error::NegativeOutOfRange)?;
				Ok(Value::Negative(-1 - n))
			}
			MAJOR_BYTES => Ok(Value::Bytes(self.take(argument)?.to_vec())),
			MAJOR_TEXT => {
				let bytes = self.take(argument)?;
				let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
				Ok(Value::Text(text.to_owned()))
			}
			MAJOR_ARRAY => {
				if depth >= MAX_DEPTH {
					return Err(Error::TooDeep);
				}
				let mut items = Vec::new();
				for _ in 0..argument {
					items.push(self.item(depth + 1)?);
				}
				Ok(Value::Array(items))
			}
			MAJOR_MAP => {
				if depth >= MAX_DEPTH {
					return Err(Error::TooDeep);
				}
				let mut pairs = Vec::new();
				let mut previous: Option<&[u8]> = None;
				for _ in 0..argument {
					let start = self.pos;
					let key = self.item(depth + 1)?;
					let encoded = &self.input[start..self.pos];
					if let Some(previous) = previous {
						match compare_keys(previous, encoded) {
							Ordering::Less => {}
							Ordering::Equal => return Err(Error::DuplicateKey),
							Ordering::Greater => return Err(Error::UnsortedKeys),
						}
					}
					previous = Some(encoded);
					let value = self.item(depth + 1)?;
					pairs.push((key, value));
				}
				Ok(Value::Map(pairs))
			}
			MAJOR_TAG => Err(Error::Tag),
			_ => unreachable!("major type 7 is handled above"),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn h(hex: &str) -> Vec<u8> {
		hex::decode(hex).expect("test vector is hex")
	}

	fn text(s: &str) -> Value {
		Value::from(s)
	}

	fn map(pairs: Vec<(Value, Value)>) -> Value {
		Value::map(pairs).expect("test map has distinct keys")
	}

	/// Encode, compare with the expected bytes, decode, compare with the
	/// value.
	fn check(hex: &str, value: &Value) {
		let bytes = h(hex);
		assert_eq!(encode(value), bytes, "encoding of {value:?}");
		assert_eq!(decode(&bytes).as_ref(), Ok(value), "decoding of {hex}");
	}

	#[test]
	fn every_variant_round_trips() {
		let values = [
			Value::Unsigned(0),
			Value::Unsigned(u64::MAX),
			Value::Negative(-1),
			Value::Negative(i64::MIN),
			Value::Bytes(Vec::new()),
			Value::Bytes(vec![0; 300]),
			text(""),
			text("keptino.local"),
			Value::Array(Vec::new()),
			Value::Array(vec![Value::Null, Value::Bool(true), Value::Unsigned(7)]),
			Value::Map(Vec::new()),
			map(vec![
				(Value::Unsigned(1), Value::Bytes(vec![1, 2, 3])),
				(Value::Unsigned(2), text("x")),
				(text("k"), Value::Array(vec![Value::Negative(-2)])),
			]),
			Value::Bool(false),
			Value::Bool(true),
			Value::Null,
		];
		for value in &values {
			assert_eq!(decode(&encode(value)).as_ref(), Ok(value));
		}
	}

	#[test]
	fn rfc_8949_integers_hold() {
		check("00", &Value::Unsigned(0));
		check("01", &Value::Unsigned(1));
		check("0a", &Value::Unsigned(10));
		check("17", &Value::Unsigned(23));
		check("1818", &Value::Unsigned(24));
		check("1819", &Value::Unsigned(25));
		check("1864", &Value::Unsigned(100));
		check("1903e8", &Value::Unsigned(1000));
		check("1a000f4240", &Value::Unsigned(1_000_000));
		check("1b000000e8d4a51000", &Value::Unsigned(1_000_000_000_000));
		check(
			"1bffffffffffffffff",
			&Value::Unsigned(18_446_744_073_709_551_615),
		);
		check("20", &Value::Negative(-1));
		check("29", &Value::Negative(-10));
		check("3863", &Value::Negative(-100));
		check("3903e7", &Value::Negative(-1000));
	}

	#[test]
	fn rfc_8949_simple_values_hold() {
		check("f4", &Value::Bool(false));
		check("f5", &Value::Bool(true));
		check("f6", &Value::Null);
	}

	#[test]
	fn rfc_8949_strings_hold() {
		check("40", &Value::Bytes(Vec::new()));
		check("4401020304", &Value::Bytes(vec![1, 2, 3, 4]));
		check("60", &text(""));
		check("6161", &text("a"));
		check("6449455446", &text("IETF"));
		check("62225c", &text("\"\\"));
		check("62c3bc", &text("ü"));
		check("63e6b0b4", &text("水"));
		check("64f0908591", &text("𐅑"));
	}

	#[test]
	fn rfc_8949_arrays_hold() {
		check("80", &Value::Array(Vec::new()));
		check(
			"83010203",
			&Value::Array(vec![
				Value::Unsigned(1),
				Value::Unsigned(2),
				Value::Unsigned(3),
			]),
		);
		check(
			"8301820203820405",
			&Value::Array(vec![
				Value::Unsigned(1),
				Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
				Value::Array(vec![Value::Unsigned(4), Value::Unsigned(5)]),
			]),
		);
		check(
			"98190102030405060708090a0b0c0d0e0f101112131415161718181819",
			&Value::Array((1..=25).map(Value::Unsigned).collect()),
		);
	}

	#[test]
	fn rfc_8949_maps_hold() {
		check("a0", &Value::Map(Vec::new()));
		check(
			"a201020304",
			&map(vec![
				(Value::Unsigned(1), Value::Unsigned(2)),
				(Value::Unsigned(3), Value::Unsigned(4)),
			]),
		);
		check(
			"a26161016162820203",
			&map(vec![
				(text("a"), Value::Unsigned(1)),
				(
					text("b"),
					Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
				),
			]),
		);
		check(
			"826161a161626163",
			&Value::Array(vec![text("a"), map(vec![(text("b"), text("c"))])]),
		);
		check(
			"a56161614161626142616361436164614461656145",
			&map(vec![
				(text("a"), text("A")),
				(text("b"), text("B")),
				(text("c"), text("C")),
				(text("d"), text("D")),
				(text("e"), text("E")),
			]),
		);
	}

	#[test]
	fn negative_range_ends_at_i64_min() {
		check("3b7fffffffffffffff", &Value::Negative(i64::MIN));
		assert_eq!(
			decode(&h("3bffffffffffffffff")),
			Err(Error::NegativeOutOfRange)
		);
	}

	#[test]
	fn non_negative_in_negative_variant_encodes_unsigned() {
		assert_eq!(encode(&Value::Negative(0)), h("00"));
		assert_eq!(encode(&Value::Negative(24)), h("1818"));
	}

	#[test]
	fn longer_than_shortest_integers_are_refused() {
		assert_eq!(decode(&h("1800")), Err(Error::NotShortest));
		assert_eq!(decode(&h("1817")), Err(Error::NotShortest));
		assert_eq!(decode(&h("1900ff")), Err(Error::NotShortest));
		assert_eq!(decode(&h("1a0000ffff")), Err(Error::NotShortest));
		assert_eq!(decode(&h("1b00000000ffffffff")), Err(Error::NotShortest));
		assert_eq!(decode(&h("3800")), Err(Error::NotShortest));
		assert_eq!(decode(&h("580100")), Err(Error::NotShortest));
		assert!(decode(&h("8100")).is_ok());
		assert_eq!(decode(&h("980100")), Err(Error::NotShortest));
	}

	#[test]
	fn indefinite_lengths_and_breaks_are_refused() {
		assert_eq!(decode(&h("9f")), Err(Error::Indefinite));
		assert_eq!(decode(&h("9f0102ff")), Err(Error::Indefinite));
		assert_eq!(decode(&h("5f42010243030405ff")), Err(Error::Indefinite));
		assert_eq!(
			decode(&h("7f657374726561646d696e67ff")),
			Err(Error::Indefinite)
		);
		assert_eq!(decode(&h("bf61610161629f0203ffff")), Err(Error::Indefinite));
		assert_eq!(decode(&h("ff")), Err(Error::Indefinite));
		assert_eq!(decode(&h("8101ff")), Err(Error::TrailingBytes));
	}

	#[test]
	fn tags_floats_and_other_simple_values_are_refused() {
		assert_eq!(
			decode(&h("c074323031332d30332d32315432303a30343a30305a")),
			Err(Error::Tag)
		);
		assert_eq!(decode(&h("c249010000000000000000")), Err(Error::Tag));
		assert_eq!(decode(&h("f90000")), Err(Error::UnsupportedSimple));
		assert_eq!(decode(&h("fa47c35000")), Err(Error::UnsupportedSimple));
		assert_eq!(
			decode(&h("fb3ff199999999999a")),
			Err(Error::UnsupportedSimple)
		);
		assert_eq!(decode(&h("f7")), Err(Error::UnsupportedSimple));
		assert_eq!(decode(&h("f0")), Err(Error::UnsupportedSimple));
		assert_eq!(decode(&h("f818")), Err(Error::UnsupportedSimple));
		assert_eq!(decode(&h("1c")), Err(Error::Reserved));
		assert_eq!(decode(&h("5e")), Err(Error::Reserved));
	}

	#[test]
	fn unsorted_and_duplicate_keys_are_refused() {
		assert_eq!(decode(&h("a203040102")), Err(Error::UnsortedKeys));
		assert_eq!(decode(&h("a2616201616102")), Err(Error::UnsortedKeys));
		assert_eq!(decode(&h("a2616101020300")), Err(Error::UnsortedKeys));
		assert_eq!(decode(&h("a201020103")), Err(Error::DuplicateKey));
		assert_eq!(decode(&h("a2616101616102")), Err(Error::DuplicateKey));
	}

	#[test]
	fn ctap2_key_order_is_major_type_then_length_then_bytes() {
		// Integer keys sort before text keys whatever their length, a
		// shorter text key before a longer one, and equal lengths bytewise.
		let value = map(vec![
			(text("aa"), Value::Unsigned(3)),
			(text("b"), Value::Unsigned(2)),
			(text(""), Value::Unsigned(1)),
			(Value::Unsigned(24), Value::Unsigned(0)),
			(Value::Negative(-1), Value::Unsigned(4)),
		]);
		check("a51818002004600161620262616103", &value);
	}

	#[test]
	fn map_constructor_sorts_and_refuses_duplicates() {
		let sorted = map(vec![
			(Value::Unsigned(3), Value::Null),
			(Value::Unsigned(1), Value::Null),
			(Value::Unsigned(2), Value::Null),
		]);
		assert_eq!(
			sorted
				.as_map()
				.map(|pairs| pairs.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()),
			Some(vec![
				Value::Unsigned(1),
				Value::Unsigned(2),
				Value::Unsigned(3)
			])
		);
		assert_eq!(
			Value::map(vec![
				(Value::Unsigned(1), Value::Null),
				(Value::Unsigned(1), Value::Bool(true)),
			]),
			Err(Error::DuplicateKey)
		);
	}

	#[test]
	fn trailing_and_missing_bytes_are_refused() {
		assert_eq!(decode(&h("0100")), Err(Error::TrailingBytes));
		assert_eq!(decode(&h("")), Err(Error::Truncated));
		assert_eq!(decode(&h("18")), Err(Error::Truncated));
		assert_eq!(decode(&h("1b00")), Err(Error::Truncated));
		assert_eq!(decode(&h("440102")), Err(Error::Truncated));
		assert_eq!(decode(&h("8201")), Err(Error::Truncated));
		assert_eq!(decode(&h("a101")), Err(Error::Truncated));
		assert_eq!(decode(&h("5a0fffffff")), Err(Error::Truncated));
	}

	#[test]
	fn invalid_utf8_is_refused() {
		assert_eq!(decode(&h("61ff")), Err(Error::InvalidUtf8));
		assert_eq!(decode(&h("62c328")), Err(Error::InvalidUtf8));
	}

	#[test]
	fn depth_stops_at_sixteen() {
		let mut sixteen = vec![0x81; 15];
		sixteen.push(0x80);
		assert!(decode(&sixteen).is_ok());
		let mut seventeen = vec![0x81; 16];
		seventeen.push(0x80);
		assert_eq!(decode(&seventeen), Err(Error::TooDeep));
		let mut maps = [0xa1, 0x00].repeat(16);
		maps.push(0xa0);
		assert_eq!(decode(&maps), Err(Error::TooDeep));
		let mut bomb = vec![0x81; 10_000];
		bomb.push(0x80);
		assert_eq!(decode(&bomb), Err(Error::TooDeep));
	}

	#[test]
	fn length_stops_at_sixty_four_kib() {
		let mut exact = h("59fffd");
		exact.resize(MAX_BYTES, 0);
		assert_eq!(decode(&exact), Ok(Value::Bytes(vec![0; MAX_BYTES - 3])));
		let mut over = h("59fffe");
		over.resize(MAX_BYTES + 1, 0);
		assert_eq!(decode(&over), Err(Error::TooLong));
	}

	#[test]
	fn accessors_and_conversions_read_back() {
		let pairs = map(vec![
			(Value::from(2u64), Value::from("rp")),
			(Value::from(1u64), Value::from(vec![9u8, 8])),
			(Value::from(3u64), Value::from(true)),
			(Value::from(4u64), Value::Array(vec![Value::Null])),
		]);
		assert_eq!(
			pairs.get(&Value::Unsigned(1)).and_then(Value::as_bytes),
			Some(&[9u8, 8][..])
		);
		assert_eq!(
			pairs.get(&Value::Unsigned(2)).and_then(Value::as_text),
			Some("rp")
		);
		assert_eq!(
			pairs.get(&Value::Unsigned(3)).and_then(Value::as_bool),
			Some(true)
		);
		assert_eq!(
			pairs.get(&Value::Unsigned(4)).and_then(Value::as_array),
			Some(&[Value::Null][..])
		);
		assert_eq!(pairs.get(&Value::Unsigned(5)), None);
		assert_eq!(Value::Unsigned(7).as_u64(), Some(7));
		assert_eq!(Value::Unsigned(7).get(&Value::Unsigned(7)), None);
		assert_eq!(Value::Negative(-7).as_u64(), None);
		assert_eq!(pairs.as_map().map(<[_]>::len), Some(4));
	}

	#[test]
	fn make_credential_request_encodes_keys_in_order() {
		let client_data_hash = vec![0xaa; 32];
		let request = map(vec![
			(
				Value::from(4u64),
				Value::Array(vec![map(vec![
					(text("type"), text("public-key")),
					(text("alg"), Value::Negative(-7)),
				])]),
			),
			(
				Value::from(3u64),
				map(vec![
					(text("name"), text("keptino")),
					(text("id"), Value::from(vec![1u8, 2, 3, 4])),
				]),
			),
			(
				Value::from(2u64),
				map(vec![
					(text("name"), text("Keptino")),
					(text("id"), text("keptino.local")),
				]),
			),
			(Value::from(1u64), Value::from(client_data_hash.clone())),
		]);
		let bytes = encode(&request);
		let mut expected = h("a4015820");
		expected.extend_from_slice(&client_data_hash);
		expected.extend(h(
			"02a26269646d6b657074696e6f2e6c6f63616c646e616d65674b657074696e6f",
		));
		expected.extend(h("03a26269644401020304646e616d65676b657074696e6f"));
		expected.extend(h("0481a263616c672664747970656a7075626c69632d6b6579"));
		assert_eq!(bytes, expected);
		let keys: Vec<u64> = request
			.as_map()
			.unwrap()
			.iter()
			.map(|(k, _)| k.as_u64().unwrap())
			.collect();
		assert_eq!(keys, vec![1, 2, 3, 4]);
		assert_eq!(decode(&bytes), Ok(request));
	}

	#[test]
	fn errors_display_as_sentences() {
		for error in [
			Error::TooLong,
			Error::Truncated,
			Error::TrailingBytes,
			Error::TooDeep,
			Error::NotShortest,
			Error::Indefinite,
			Error::Reserved,
			Error::Tag,
			Error::UnsupportedSimple,
			Error::NegativeOutOfRange,
			Error::InvalidUtf8,
			Error::UnsortedKeys,
			Error::DuplicateKey,
		] {
			let text = error.to_string();
			assert!(text.ends_with('.'), "{text}");
		}
	}
}
