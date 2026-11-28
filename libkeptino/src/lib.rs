//! What a Keptino vault is, independent of the machine that holds it: the
//! file format, the cryptography, the erasure code and the rules for
//! choosing between copies. Everything here is a function of bytes and values
//! the caller passes in. There is no I/O, no system call and no network; the
//! Linux and Android heads supply those and consume this. Security keys live
//! behind the `fido` feature and S3 signing behind `s3`, so a head links only
//! what it uses.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod erasure;
#[cfg(feature = "fido")]
pub mod fido;
pub mod format;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz;
pub mod generator;
pub mod health;
pub mod lz4frame;
pub mod policy;
pub mod roaming;
#[cfg(feature = "s3")]
pub mod s3;
pub mod vault;
mod wordlist;
