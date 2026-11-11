//! The TLV containers of the Linux vault format: `id u8 | len u32 LE | value`.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Splits one `tag | len | value` record off the front of `data`.
fn split_record(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
	let (header, rest) = data
		.split_at_checked(5)
		.ok_or(Error::Corrupt("truncated record header"))?;
	let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
	let (value, rest) = rest
		.split_at_checked(len)
		.ok_or(Error::Corrupt("truncated record value"))?;
	Ok((header[0], value, rest))
}

fn push_record(buffer: &mut Vec<u8>, tag: u8, value: &[u8]) {
	buffer.push(tag);
	buffer.extend_from_slice(&(value.len() as u32).to_le_bytes());
	buffer.extend_from_slice(value);
}

/// The fields of one entry, keyed by field id. Unknown ids are preserved.
#[derive(Clone, Default)]
pub struct FieldAtlas {
	fields: BTreeMap<u8, Zeroizing<Vec<u8>>>,
}

impl FieldAtlas {
	pub fn deserialize(mut data: &[u8]) -> Result<Self> {
		let mut fields = BTreeMap::new();
		while !data.is_empty() {
			let (id, value, rest) = split_record(data)?;
			fields.insert(id, Zeroizing::new(value.to_vec()));
			data = rest;
		}
		Ok(Self { fields })
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		let size = self.fields.values().map(|v| 5 + v.len()).sum();
		let mut buffer = Zeroizing::new(Vec::with_capacity(size));
		for (&id, value) in &self.fields {
			push_record(&mut buffer, id, value);
		}
		buffer
	}

	pub fn get(&self, id: u8) -> Option<&[u8]> {
		self.fields.get(&id).map(|v| v.as_slice())
	}

	pub fn get_str(&self, id: u8) -> Option<&str> {
		self.get(id).and_then(|bytes| std::str::from_utf8(bytes).ok())
	}

	pub fn set(&mut self, id: u8, value: &[u8]) {
		self.fields.insert(id, Zeroizing::new(value.to_vec()));
	}
}

/// The ordered entry records of a database: `(tag, serialized FieldAtlas)`.
pub fn deserialize_entries(mut data: &[u8]) -> Result<Vec<(u8, FieldAtlas)>> {
	let mut entries = Vec::new();
	while !data.is_empty() {
		let (tag, value, rest) = split_record(data)?;
		entries.push((tag, FieldAtlas::deserialize(value)?));
		data = rest;
	}
	Ok(entries)
}

pub fn serialize_entries<'a>(
	entries: impl Iterator<Item = (u8, &'a [u8])> + Clone,
) -> Zeroizing<Vec<u8>> {
	let size = entries.clone().map(|(_, value)| 5 + value.len()).sum();
	let mut buffer = Zeroizing::new(Vec::with_capacity(size));
	for (tag, value) in entries {
		push_record(&mut buffer, tag, value);
	}
	buffer
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fields_roundtrip_sorted_and_keep_unknown_ids() {
		let mut raw = Vec::new();
		push_record(&mut raw, 200, b"future");
		push_record(&mut raw, 1, b"name");
		push_record(&mut raw, 1, b"last wins");
		let atlas = FieldAtlas::deserialize(&raw).unwrap();
		assert_eq!(atlas.get_str(1), Some("last wins"));
		let mut expected = Vec::new();
		push_record(&mut expected, 1, b"last wins");
		push_record(&mut expected, 200, b"future");
		assert_eq!(&*atlas.serialize(), &expected);
	}

	#[test]
	fn truncation_is_an_error_not_a_panic() {
		let mut raw = Vec::new();
		push_record(&mut raw, 1, b"name");
		for cut in 1..raw.len() {
			assert!(FieldAtlas::deserialize(&raw[..cut]).is_err());
		}
		assert!(deserialize_entries(&[1, 255, 255, 255, 255]).is_err());
	}
}
