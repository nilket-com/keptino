//! JNI entry points of `com.keptino.app.Core`. Every failure, including a
//! panic, becomes a `java.lang.RuntimeException`; a database is reached
//! through a handle, so a stale one is an error and not a dangling pointer.

use crate::{
	error::{Error, Result},
	security,
	vault::Vault,
};
use jni::{
	JNIEnv,
	objects::{JByteArray, JObject, JString, JValue},
	sys::{JNI_VERSION_1_6, jboolean, jbyteArray, jint, jlong, jobjectArray},
};
use libkeptino::crypto::PEPPER_SIZE;
use libkeptino::format::KdfParams;
use libkeptino::generator::{Classes, Kind};
use libkeptino::health::{Report, WEAK_BITS};
use libkeptino::vault::KeyStore;
use std::{
	collections::HashMap,
	ffi::c_void,
	panic::{AssertUnwindSafe, catch_unwind},
	sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use zeroize::Zeroizing;

type Shared = Arc<Mutex<Vault>>;

#[derive(Default)]
struct Registry {
	last: jlong,
	vaults: HashMap<jlong, Shared>,
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
	mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register(vault: Vault) -> jlong {
	let mut guard = lock(&REGISTRY);
	let registry = guard.get_or_insert_with(Registry::default);
	registry.last += 1;
	registry
		.vaults
		.insert(registry.last, Arc::new(Mutex::new(vault)));
	registry.last
}

fn vault(handle: jlong) -> Result<Shared> {
	lock(&REGISTRY)
		.as_ref()
		.and_then(|registry| registry.vaults.get(&handle).cloned())
		.ok_or(Error::Invalid("database is closed"))
}

fn with<T>(handle: jlong, body: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
	let shared = vault(handle)?;
	let mut guard = lock(&*shared);
	body(&mut guard)
}

fn unregister(handle: jlong) {
	let removed = lock(&REGISTRY)
		.as_mut()
		.and_then(|registry| registry.vaults.remove(&handle));
	// Wiped here unless another thread is mid-call, then when that returns.
	drop(removed);
}

fn jni_error(_: jni::errors::Error) -> Error {
	Error::Invalid("unreadable argument")
}

fn bytes(env: &JNIEnv, array: &JByteArray) -> Result<Zeroizing<Vec<u8>>> {
	if array.is_null() {
		return Err(Error::Invalid("missing argument"));
	}
	env.convert_byte_array(array)
		.map(Zeroizing::new)
		.map_err(jni_error)
}

fn optional_bytes(env: &JNIEnv, array: &JByteArray) -> Result<Option<Zeroizing<Vec<u8>>>> {
	if array.is_null() {
		return Ok(None);
	}
	bytes(env, array).map(Some)
}

fn string(env: &mut JNIEnv, value: &JString) -> Result<Zeroizing<String>> {
	if value.is_null() {
		return Err(Error::Invalid("missing argument"));
	}
	let value: String = env.get_string(value).map_err(jni_error)?.into();
	Ok(Zeroizing::new(value))
}

fn byte_array(env: &JNIEnv, value: &[u8]) -> Result<jbyteArray> {
	env.byte_array_from_slice(value)
		.map(JByteArray::into_raw)
		.map_err(|_| Error::Invalid("result does not fit in memory"))
}

fn string_array(env: &mut JNIEnv, rows: Vec<String>) -> Result<jobjectArray> {
	let count = jint::try_from(rows.len()).map_err(|_| Error::Invalid("too many rows"))?;
	let array = env
		.new_object_array(count, "java/lang/String", JObject::null())
		.map_err(jni_error)?;
	for (index, row) in rows.into_iter().enumerate() {
		let text = env.auto_local(env.new_string(row).map_err(jni_error)?);
		env.set_object_array_element(&array, index as jint, &*text)
			.map_err(jni_error)?;
	}
	Ok(array.into_raw())
}

fn mem_kib(value: jint) -> Result<u32> {
	u32::try_from(value).map_err(|_| Error::Invalid("memory size"))
}

fn field_id(value: jint) -> Result<u8> {
	u8::try_from(value).map_err(|_| Error::Invalid("unknown field"))
}

/// Runs `body`, converting an error or a panic into a pending Java
/// exception and returning `fallback` to the JVM, which ignores it.
fn guard<'local, T>(
	env: &mut JNIEnv<'local>,
	fallback: T,
	body: impl FnOnce(&mut JNIEnv<'local>) -> Result<T>,
) -> T {
	let (class, message) = match catch_unwind(AssertUnwindSafe(|| body(env))) {
		Ok(Ok(value)) => return value,
		Ok(Err(Error::DifferentVault)) => (
			"com/keptino/app/DifferentVault",
			Error::DifferentVault.to_string(),
		),
		Ok(Err(error)) => ("java/lang/RuntimeException", error.to_string()),
		Err(_) => ("java/lang/RuntimeException", "Internal error.".to_owned()),
	};
	if !env.exception_check().unwrap_or(true) {
		let _ = env.throw_new(class, message);
	}
	fallback
}

/// Hardens the process as soon as the library loads, before Kotlin asks
/// for anything; `preflight` repeats it and adds the checks that can fail.
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
	security::harden_process();
	JNI_VERSION_1_6
}

/// Startup checks: throws `SECURITY VIOLATION: ...` when the process is
/// traced or instrumented, else returns warnings for the user, possibly none.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_preflight<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
) -> jobjectArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		string_array(env, security::preflight()?)
	})
}

fn local_date(seconds: libc::time_t) -> String {
	let mut date = std::mem::MaybeUninit::uninit();
	// localtime_r writes a complete tm into our buffer on success.
	let Some(date) = (unsafe { libc::localtime_r(&seconds, date.as_mut_ptr()).as_ref() }) else {
		return "unknown".into();
	};
	format!(
		"{:04}-{:02}-{:02} {:02}:{:02}",
		date.tm_year + 1900,
		date.tm_mon + 1,
		date.tm_mday,
		date.tm_hour,
		date.tm_min
	)
}

fn health_rows(report: Report) -> Vec<String> {
	let entries = report.entries;
	if report.is_clean() {
		return vec![format!(
			"{entries} entries. No reused, weak, stale or empty passwords."
		)];
	}
	let mut rows = vec![format!("{entries} entries")];
	for (index, group) in report.reused.into_iter().enumerate() {
		rows.push(format!("Reused password {}", index + 1));
		rows.extend(group);
	}
	if !report.weak.is_empty() {
		rows.push(format!("Weak passwords, estimated under {WEAK_BITS} bits"));
		rows.extend(
			report
				.weak
				.into_iter()
				.map(|entry| format!("{}: {} bits", entry.name, entry.bits)),
		);
	}
	if !report.stale.is_empty() {
		rows.push("Not edited in a year".into());
		rows.extend(report.stale.into_iter().map(|entry| {
			format!(
				"{}: last edited {}",
				entry.name,
				local_date(entry.last_edited)
			)
		}));
	}
	if !report.empty.is_empty() {
		rows.push("No password".into());
		rows.extend(report.empty);
	}
	rows
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_healthReport<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jobjectArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let report = with(handle, |vault| Ok(vault.health_report()))?;
		string_array(env, health_rows(report))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_derivePepper<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	seed: JByteArray<'local>,
	mem: jint,
) -> jbyteArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let seed = bytes(env, &seed)?;
		let pepper = security::derive_pepper(&seed, mem_kib(mem)?)?;
		pepper.with_key(|bytes| byte_array(env, bytes))
	})
}

struct AndroidKey<'a, 'local> {
	env: &'a mut JNIEnv<'local>,
	io: &'a JObject<'local>,
}

impl crate::fido::Device for AndroidKey<'_, '_> {
	fn purpose(&mut self, prompt: &str) -> crate::fido::KeyResult<()> {
		use libkeptino::fido::ceremony::Failure;
		let text = self.env.new_string(prompt).map_err(|_| Failure::Canceled)?;
		let text = self.env.auto_local(text);
		self.env
			.call_method(
				self.io,
				"purpose",
				"(Ljava/lang/String;)V",
				&[JValue::Object(&text)],
			)
			.map(|_| ())
			.map_err(|_| Failure::Canceled)
	}
	fn begin(&mut self) -> crate::fido::KeyResult<crate::fido::Link> {
		use libkeptino::fido::ceremony::Failure;
		match self
			.env
			.call_method(self.io, "begin", "()I", &[])
			.and_then(|v| v.i())
		{
			Ok(1) => Ok(crate::fido::Link::Usb),
			Ok(2) => Ok(crate::fido::Link::Nfc),
			Ok(_) | Err(_) => Err(Failure::Canceled),
		}
	}

	fn write(&mut self, packet: &crate::fido::Packet) -> crate::fido::KeyResult<()> {
		use libkeptino::fido::ceremony::Failure;
		// A failed Java callback already carries its device error. Avoid another
		// JNI call with that exception pending during best-effort HID abort.
		if self.env.exception_check().unwrap_or(true) {
			return Err(Failure::Canceled);
		}
		let array = self
			.env
			.byte_array_from_slice(packet)
			.map_err(|_| Failure::Canceled)?;
		let array = self.env.auto_local(array);
		self.env
			.call_method(self.io, "write", "([B)V", &[JValue::Object(&array)])
			.map(|_| ())
			.map_err(|_| Failure::Canceled)
	}

	fn read(&mut self) -> crate::fido::KeyResult<crate::fido::Packet> {
		use libkeptino::fido::ceremony::Failure;
		let array = self.result_bytes("read", "()[B", &[], 64)?;
		array.try_into().map_err(|_| Failure::Mismatch)
	}

	fn apdu(&mut self, request: &[u8]) -> crate::fido::KeyResult<Vec<u8>> {
		use libkeptino::fido::{ceremony::Failure, nfc};
		let input = self
			.env
			.byte_array_from_slice(request)
			.map_err(|_| Failure::Canceled)?;
		let input = self.env.auto_local(input);
		self.result_bytes(
			"apdu",
			"([B)[B",
			&[JValue::Object(&input)],
			nfc::MAX_RESPONSE_BYTES + 2,
		)
	}

	fn pin(&mut self) -> crate::fido::KeyResult<Zeroizing<String>> {
		use libkeptino::fido::ceremony::Failure;
		let value = self
			.env
			.call_method(self.io, "pin", "()[B", &[])
			.and_then(|v| v.l())
			.map_err(|_| Failure::Canceled)?;
		if value.is_null() {
			return Err(Failure::Canceled);
		}
		let array = self.env.auto_local(JByteArray::from(value));
		let length = self
			.env
			.get_array_length(&*array)
			.map_err(|_| Failure::Canceled)?;
		let copied = if (1..=63).contains(&length) {
			bytes(self.env, &array).ok()
		} else {
			None
		};
		for start in (0..length).step_by(64) {
			let count = (length - start).min(64) as usize;
			self.env
				.set_byte_array_region(&array, start, &[0; 64][..count])
				.map_err(|_| Failure::Canceled)?;
		}
		let copied = copied.ok_or(Failure::WrongPin)?;
		let text = std::str::from_utf8(&copied).map_err(|_| Failure::WrongPin)?;
		Ok(Zeroizing::new(text.to_owned()))
	}
}

impl AndroidKey<'_, '_> {
	fn result_bytes(
		&mut self,
		name: &str,
		sig: &str,
		args: &[JValue],
		max: usize,
	) -> crate::fido::KeyResult<Vec<u8>> {
		use libkeptino::fido::ceremony::Failure;
		let value = self
			.env
			.call_method(self.io, name, sig, args)
			.and_then(|v| v.l())
			.map_err(|_| Failure::Canceled)?;
		if value.is_null() {
			return Err(Failure::Canceled);
		}
		let array = self.env.auto_local(JByteArray::from(value));
		if self
			.env
			.get_array_length(&*array)
			.map_err(|_| Failure::Canceled)? as usize
			> max
		{
			return Err(Failure::Mismatch);
		}
		self.env
			.convert_byte_array(&array)
			.map_err(|_| Failure::Canceled)
	}
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_openWithKey<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	db_name: JString<'local>,
	password: JByteArray<'local>,
	pepper: JByteArray<'local>,
	local: JByteArray<'local>,
	remote: JByteArray<'local>,
	mem: jint,
	io: JObject<'local>,
) -> jlong {
	guard(&mut env, 0, |env| {
		let db_name = string(env, &db_name)?;
		let password = bytes(env, &password)?;
		let pepper = bytes(env, &pepper)?;
		let pepper: &[u8; PEPPER_SIZE] = pepper
			.as_slice()
			.try_into()
			.map_err(|_| Error::Invalid("pepper must be 32 bytes"))?;
		let local = optional_bytes(env, &local)?;
		let remote = optional_bytes(env, &remote)?;
		let vault = Vault::open_with_security_key(
			&db_name,
			&password,
			pepper,
			local.as_ref().map(|bytes| bytes.as_slice()),
			remote.as_ref().map(|bytes| bytes.as_slice()),
			KdfParams::memory_only(mem_kib(mem)?),
			|candidate| {
				if io.is_null() {
					return libkeptino::vault::Derived::Unavailable;
				}
				crate::fido::resolve(&mut AndroidKey { env, io: &io }, candidate.slots)
			},
		)?;
		Ok(register(vault))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_source<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jint {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.source() as jint))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_revision<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jlong {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.revision() as jlong))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_uploadsPaused<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jboolean {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.uploads_paused as jboolean))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_modifiedTs<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jlong {
	guard(&mut env, 0, |_| {
		with(handle, |vault| {
			Ok(vault.modified_ts().min(jlong::MAX as u64) as jlong)
		})
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_query<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	query: JString<'local>,
) -> jboolean {
	guard(&mut env, 0, |env| {
		let query = string(env, &query)?;
		with(handle, |vault| Ok(vault.query(&query) as jboolean))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_next<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jboolean {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.next() as jboolean))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_previous<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jboolean {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.previous() as jboolean))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_clear<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) {
	guard(&mut env, (), |_| {
		with(handle, |vault| {
			vault.clear();
			Ok(())
		})
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_generatePassword<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	kind: jint,
	count: jint,
	classes: jint,
) -> jint {
	guard(&mut env, 0, |_| {
		let count =
			usize::try_from(count).map_err(|_| Error::Invalid("invalid generator count"))?;
		let kind = match kind {
			0 if (0..=15).contains(&classes) => Kind::Characters {
				length: count,
				classes: Classes::from_bits(classes as u8),
			},
			1 => Kind::Passphrase { words: count },
			_ => return Err(Error::Invalid("invalid generator options")),
		};
		with(handle, |vault| Ok(vault.generate_password(kind)? as jint))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_deleteSelected<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	confirmed_name: JString<'local>,
) -> jboolean {
	guard(&mut env, 0, |env| {
		let name = string(env, &confirmed_name)?;
		with(
			handle,
			|vault| Ok(vault.delete_selected(&name)? as jboolean),
		)
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_getField<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	field: jint,
) -> jbyteArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let value = with(handle, |vault| vault.get_field(field_id(field)?))?;
		byte_array(env, &value)
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_setField<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	field: jint,
	value: JByteArray<'local>,
) {
	guard(&mut env, (), |env| {
		let value = bytes(env, &value)?;
		with(handle, |vault| vault.set_field(field_id(field)?, &value))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_commit<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jint {
	guard(&mut env, 0, |_| {
		with(handle, |vault| Ok(vault.commit() as jint))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_save<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jbyteArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let file = with(handle, Vault::save)?;
		byte_array(env, &file)
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_close<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) {
	guard(&mut env, (), |_| {
		unregister(handle);
		Ok(())
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_keySlots<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
) -> jobjectArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let slots = with(handle, |vault| vault.slots())?;
		let rows = slots
			.iter()
			.enumerate()
			.map(|(index, slot)| {
				let mode = match slot.uv_mode {
					libkeptino::roaming::UvMode::TouchOnly => "touch only",
					libkeptino::roaming::UvMode::Verified => "verified",
				};
				let id: String = slot
					.cred_id
					.iter()
					.take(4)
					.map(|byte| format!("{byte:02x}"))
					.collect();
				format!("Slot {} · {mode} · {id}", index + 1)
			})
			.collect();
		string_array(env, rows)
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_fileStamp<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	file: JByteArray<'local>,
) -> jbyteArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let file = bytes(env, &file)?;
		let envelope = libkeptino::format::Envelope::parse(&file, KdfParams::BUILD_DEFAULT)?;
		let mut stamp = envelope.salt.to_vec();
		stamp.extend_from_slice(&envelope.revision.unwrap_or(0).to_be_bytes());
		byte_array(env, &stamp)
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_prepareKeys<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	handle: jlong,
	file: JByteArray<'local>,
	password: JByteArray<'local>,
	pepper: JByteArray<'local>,
	remove: jint,
	touch_only: jboolean,
	io: JObject<'local>,
) -> jlong {
	guard(&mut env, 0, |env| {
		let context = with(handle, |vault| vault.key_context())?;
		let file = bytes(env, &file)?;
		let password = bytes(env, &password)?;
		let pepper = bytes(env, &pepper)?;
		let mode = if touch_only != 0 {
			libkeptino::roaming::UvMode::TouchOnly
		} else {
			libkeptino::roaming::UvMode::Verified
		};
		let next = context.prepare(
			&file,
			&password,
			pepper
				.as_slice()
				.try_into()
				.map_err(|_| Error::Invalid("pepper must be 32 bytes"))?,
			u32::try_from(remove).map_err(|_| Error::Invalid("invalid key selection"))?,
			mode,
			&mut AndroidKey { env, io: &io },
		)?;
		Ok(register(next))
	})
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_signR2<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	put: jboolean,
	account: JString<'local>,
	bucket: JString<'local>,
	name: JString<'local>,
	id: JString<'local>,
	secret: JString<'local>,
	body: JByteArray<'local>,
	seconds: jlong,
) -> jobjectArray {
	guard(&mut env, std::ptr::null_mut(), |env| {
		let account = string(env, &account)?;
		if account.len() != 32 || !account.bytes().all(|b| b.is_ascii_hexdigit()) {
			return Err(Error::Invalid("invalid R2 account ID"));
		}
		let endpoint = libkeptino::s3::validate_endpoint(&format!(
			"https://{}.r2.cloudflarestorage.com",
			account.to_ascii_lowercase()
		))
		.map_err(|_| Error::Invalid("invalid R2 endpoint"))?;
		let signed = libkeptino::s3::sign(
			if put != 0 {
				libkeptino::s3::Method::Put
			} else {
				libkeptino::s3::Method::Get
			},
			&endpoint,
			&string(env, &bucket)?,
			&format!("{}.keptino", string(env, &name)?.as_str()),
			"auto",
			&string(env, &id)?,
			&string(env, &secret)?,
			&bytes(env, &body)?,
			u64::try_from(seconds).map_err(|_| Error::Invalid("invalid system time"))?,
		)
		.map_err(|_| Error::Invalid("invalid R2 request"))?;
		string_array(
			env,
			vec![
				signed.url,
				signed.amz_date,
				signed.content_sha256,
				signed.authorization,
			],
		)
	})
}
