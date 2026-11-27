//! Entry records sealed in memory. Each record is encrypted under a key that
//! lives in secret memory, with its id and tag as authenticated context, so
//! an idle vault holds no entry plaintext at all. The TLV field layer comes
//! from `keptino_core::format`.

use super::{
	protected::{ProtectedBytes, fresh_key},
	secret::SecretMemory,
};
use keptino_core::format::deserialize_records;
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct EntryAtlas {
	pub entries: BTreeMap<u32, (u8, ProtectedBytes)>,
	key: Arc<SecretMemory>,
}

impl Default for EntryAtlas {
	fn default() -> Self {
		Self {
			entries: BTreeMap::new(),
			key: fresh_key(),
		}
	}
}

impl EntryAtlas {
	fn context(id: u32, tag: u8) -> [u8; 5] {
		let mut context = [0; 5];
		context[..4].copy_from_slice(&id.to_le_bytes());
		context[4] = tag;
		context
	}

	/// Seals every record of an authenticated database; ids are positions.
	pub fn deserialize(data: &[u8]) -> Self {
		let mut atlas = Self::default();
		let records = deserialize_records(data).expect("Invalid entry record");
		for (id, (tag, value)) in records.into_iter().enumerate() {
			atlas.set(id as u32, tag, value);
		}
		atlas
	}

	pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
		// Size from ciphertext lengths to avoid reallocating plaintext buffers.
		let size = self
			.entries
			.values()
			.map(|(_, value)| 5 + value.plaintext_len())
			.sum();
		let mut buffer = Zeroizing::new(Vec::with_capacity(size));
		for id in self.entries.keys() {
			let (tag, value) = self.get(*id).unwrap();
			buffer.push(tag);
			buffer.extend_from_slice(&(value.len() as u32).to_le_bytes());
			buffer.extend_from_slice(&value);
		}
		buffer
	}

	pub fn set(&mut self, id: u32, tag: u8, value: &[u8]) {
		let sealed = ProtectedBytes::seal(&self.key, value, &Self::context(id, tag));
		self.entries.insert(id, (tag, sealed));
	}

	pub fn get(&self, id: u32) -> Option<(u8, Zeroizing<Vec<u8>>)> {
		let (tag, sealed) = self.entries.get(&id)?;
		Some((*tag, sealed.open(&Self::context(id, *tag))))
	}

	/// Drops a record; its ciphertext goes with it and its key is per-atlas,
	/// so nothing of the plaintext remains recoverable from this object.
	pub fn remove(&mut self, id: u32) -> bool {
		self.entries.remove(&id).is_some()
	}

	pub fn clear(&mut self) {
		self.entries.clear();
		self.key.zeroize().expect("Failed to erase memory key");
	}
}
