//! The DigiSafe vault for Android: reads and writes the files of the Linux
//! application. Kotlin reaches it through the `bridge` module.

pub mod atlas;
pub mod crypto;
pub mod erasure;
pub mod error;
mod bridge;
pub mod security;
pub mod vault;

pub use error::{Error, Result};
pub use vault::{Commit, Source, Vault, field};
