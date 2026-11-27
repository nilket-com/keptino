//! CTAP2 for Keptino security keys. This crate speaks the protocol and runs
//! the ceremonies; it never touches a device. A head drives it: each step
//! says what to send or read next, and the head owns the transport.

pub mod cbor;
pub mod ceremony;
pub mod ctap;
#[cfg(test)]
mod fixture;
pub mod hid;
pub mod nfc;
pub mod pin;
#[cfg(any(test, feature = "test-support"))]
pub mod sim;
