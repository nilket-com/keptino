//! Loopback peer for the Android instrumentation tests. All keys are public
//! fixtures. The simulator is a dev dependency and is absent from the APK.
use keptino_fido::sim::{Authenticator, Device, HidDevice, NfcDevice};
use std::{
	error::Error,
	io::{BufRead, BufReader, Read, Write},
	net::{TcpListener, TcpStream},
	time::Duration,
};

fn serve(stream: TcpStream) -> Result<(), Box<dyn Error>> {
	stream.set_read_timeout(Some(Duration::from_secs(60)))?;
	let mut reader = BufReader::new(&stream);
	let mut writer = &stream;
	let mut device = None;
	let mut line = String::new();
	loop {
		line.clear();
		if reader.by_ref().take(4096).read_line(&mut line)? == 0 {
			return Ok(());
		}
		if !line.ends_with('\n') {
			return Err("incomplete test frame".into());
		}
		let (cmd, arg) = line
			.trim_end()
			.split_once(' ')
			.unwrap_or((line.trim_end(), ""));
		let reply = match (cmd, device.as_mut()) {
			("usb" | "nfc", _) => {
				let index: u8 = arg.parse()?;
				let auth = match index {
					1 => Authenticator::new(*b"keptino-fixture-security-key-001").with_pin("1234"),
					2 => Authenticator::new(*b"keptino-fixture-security-key-002"),
					3..=5 => Authenticator::new([index; 32]),
					_ => return Err("unknown fixture key".into()),
				};
				device = Some(if cmd == "usb" {
					Device::Hid(HidDevice::new(auth))
				} else {
					Device::Nfc(NfcDevice::new(auth))
				});
				String::new()
			}
			("write", Some(Device::Hid(key))) => {
				let mut packet = [0u8; 64];
				hex::decode_to_slice(arg, &mut packet)?;
				key.write(&packet);
				String::new()
			}
			("read", Some(Device::Hid(key))) => hex::encode(key.read().ok_or("no HID response")?),
			("apdu", Some(Device::Nfc(key))) => hex::encode(key.transceive(&hex::decode(arg)?)),
			_ => return Err("unexpected test command".into()),
		};
		writeln!(writer, "{reply}")?;
	}
}

fn main() -> Result<(), Box<dyn Error>> {
	let listener = TcpListener::bind(("127.0.0.1", 0))?;
	println!("{}", listener.local_addr()?.port());
	for connection in listener.incoming() {
		serve(connection?)?;
	}
	Ok(())
}
