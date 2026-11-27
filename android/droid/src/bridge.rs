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
	objects::{JByteArray, JObject, JString},
	sys::{JNI_VERSION_1_6, jboolean, jbyteArray, jint, jlong, jobjectArray},
};
use keptino_core::crypto::PEPPER_SIZE;
use keptino_core::vault::KeyStore;
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
	let message = match catch_unwind(AssertUnwindSafe(|| body(env))) {
		Ok(Ok(value)) => return value,
		Ok(Err(error)) => error.to_string(),
		Err(_) => "Internal error.".to_owned(),
	};
	if !env.exception_check().unwrap_or(true) {
		let _ = env.throw_new("java/lang/RuntimeException", message);
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
		let warnings = security::preflight()?;
		let count =
			jint::try_from(warnings.len()).map_err(|_| Error::Invalid("too many warnings"))?;
		let array = env
			.new_object_array(count, "java/lang/String", JObject::null())
			.map_err(jni_error)?;
		for (index, warning) in warnings.iter().enumerate() {
			let text = env.new_string(warning).map_err(jni_error)?;
			env.set_object_array_element(&array, index as jint, text)
				.map_err(jni_error)?;
		}
		Ok(array.into_raw())
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keptino_app_Core_open<'local>(
	mut env: JNIEnv<'local>,
	_this: JObject<'local>,
	db_name: JString<'local>,
	password: JByteArray<'local>,
	pepper: JByteArray<'local>,
	local: JByteArray<'local>,
	remote: JByteArray<'local>,
	mem: jint,
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
		let vault = Vault::open(
			&db_name,
			&password,
			pepper,
			local.as_ref().map(|bytes| bytes.as_slice()),
			remote.as_ref().map(|bytes| bytes.as_slice()),
			mem_kib(mem)?,
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
