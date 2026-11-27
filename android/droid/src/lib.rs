//! The Keptino vault for Android: reads and writes the files of the Linux
//! application. Kotlin reaches it through the `bridge` module.

mod bridge;
pub mod error;
pub mod security;
pub mod vault;

pub use error::{Error, Result};
pub use keptino_core::format::field;
pub use vault::{Commit, Source, Vault};
