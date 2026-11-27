//! What a Keptino vault is, independent of the machine that holds it: the
//! file format, the cryptography and the rules for choosing between copies.
//! Everything here is a function of bytes and values the caller passes in.
//! There is no I/O, no system call and no network; the Linux and Android
//! heads supply those and consume this.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod format;
pub mod generator;
pub mod health;
pub mod policy;
pub mod vault;
mod wordlist;
