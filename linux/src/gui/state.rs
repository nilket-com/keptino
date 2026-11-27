use crate::gui::{clipboard, components, messages::Message, session_lock};
use crate::storage::{
	PasswordEntry,
	persistence::{self, OpenedVault},
};
use iced::{
	Element, Event, Size, Subscription, Task, application, keyboard,
	widget::{
		Id,
		operation::{focus_next, focus_previous},
		text_editor,
	},
	window,
};
use libkeptino::generator::{self, Classes, Kind};
use libkeptino::health;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct LockedState {
	db_name: String,
	db_password: Zeroizing<String>,
	/// The security key's PIN, asked for when the local copy has slots.
	db_pin: Zeroizing<String>,
	has_slots: bool,
	/// The last unlock saw two salts; the adopt action is on screen.
	offer_adopt: bool,
	is_processing: bool,
	status: String,
}

/// The keys screen: the vault's slots and the inputs its ceremonies need.
pub struct KeysScreen {
	pub slots: Vec<libkeptino::roaming::KeySlot>,
	/// The master password, needed to derive the new key for a rekey.
	pub password: Zeroizing<String>,
	pub pin: Zeroizing<String>,
	pub touch_only: bool,
	/// Remove was pressed on this slot; the next press rekeys without it.
	pub confirm_remove: Option<usize>,
	/// Slots the user chose to drop after their key did not answer.
	pub dropped: Vec<usize>,
	pub busy: bool,
}

impl KeysScreen {
	fn new(db: &crate::storage::Database) -> Self {
		Self {
			slots: crate::storage::keys::slots_of(db),
			password: Zeroizing::new(String::new()),
			pin: Zeroizing::new(String::new()),
			touch_only: false,
			confirm_remove: None,
			dropped: Vec::new(),
			busy: false,
		}
	}

	fn pin(&self) -> Option<Zeroizing<String>> {
		(!self.pin.is_empty()).then(|| self.pin.clone())
	}
}

/// What the die makes: characters from the chosen classes, or EFF words.
/// A session choice; nothing of it is stored in the vault.
pub struct GeneratorChoice {
	pub words: bool,
	/// The length or word count as typed; empty or out of range refuses.
	pub count: String,
	pub classes: Classes,
}

impl GeneratorChoice {
	fn new() -> Self {
		Self {
			words: false,
			count: generator::LENGTH.to_string(),
			classes: Classes::ALL,
		}
	}

	pub fn kind(&self) -> Kind {
		let count = self.count.parse().unwrap_or(0);
		if self.words {
			Kind::Passphrase { words: count }
		} else {
			Kind::Characters {
				length: count,
				classes: self.classes,
			}
		}
	}
}

struct UnlockedState {
	query: String,
	password_entry: PasswordEntry,
	generator: GeneratorChoice,
	is_password_visible: bool,
	is_pin_visible: bool,
	is_note_visible: bool,
	last_copy_time: Option<Instant>,
	last_interaction_time: Option<Instant>,
	note: text_editor::Content,
	status: String,
	vault: OpenedVault,
	saving: bool,
	/// Delete was pressed once; the next press removes the entry.
	confirm_delete: bool,
	/// The health report on screen in place of the editor, if any.
	health: Option<Box<health::Report>>,
	/// The keys screen in place of the editor, if any.
	keys: Option<Box<KeysScreen>>,
}

enum AppState {
	Locked(LockedState),
	Unlocked(UnlockedState),
}

pub const APP_NAME: &str = "Keptino";
const COPY_TIMEOUT: Duration = Duration::from_secs(if cfg!(debug_assertions) { 10 } else { 20 });
const IDLE_TIMEOUT: Duration = Duration::from_secs(if cfg!(debug_assertions) { 60 } else { 240 });

pub type Result = iced::Result;

pub fn run() -> Result {
	application(new, update, view)
		.subscription(|app_state| {
			Subscription::batch(vec![
				keyboard_subscription(app_state),
				tick_subscription(app_state),
			])
		})
		.theme(components::theme())
		.title(APP_NAME)
		.window(window::Settings {
			size: Size::new(1000.0, 800.0),
			position: window::Position::Centered,
			decorations: false,
			transparent: false,
			platform_specific: window::settings::PlatformSpecific {
				application_id: "keptino".into(),
				..Default::default()
			},
			..Default::default()
		})
		.run()
}

fn new() -> AppState {
	AppState::Locked(LockedState {
		db_name: "".into(),
		db_password: Zeroizing::new(String::new()),
		db_pin: Zeroizing::new(String::new()),
		has_slots: false,
		offer_adopt: false,
		is_processing: false,
		status: String::new(),
	})
}

fn update(app_state: &mut AppState, message: Message) -> Task<Message> {
	match app_state {
		AppState::Locked(_) => update_locked(message, app_state),
		AppState::Unlocked(_) => update_unlocked(message, app_state),
	}
}

fn tick_subscription(app_state: &AppState) -> Subscription<Message> {
	if let AppState::Unlocked(_) = &app_state {
		Subscription::batch(vec![
			iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick),
			session_lock::subscription(),
		])
	} else {
		Subscription::none()
	}
}

fn keyboard_subscription(_app_state: &AppState) -> Subscription<Message> {
	iced::event::listen().map(|event| match event {
		Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
			// Ctrl+L locks at once, as in KeePassXC; the locked screen ignores it.
			if let keyboard::Key::Character(character) = key.as_ref()
				&& character.eq_ignore_ascii_case("l")
				&& modifiers.control()
			{
				Message::Lock
			} else if key == keyboard::Key::Named(keyboard::key::Named::Tab) {
				if modifiers.shift() {
					Message::FocusPrevious
				} else {
					Message::FocusNext
				}
			} else if key == keyboard::Key::Named(keyboard::key::Named::ArrowLeft) {
				if modifiers.control() {
					Message::NavigatePrevious
				} else {
					Message::None
				}
			} else if key == keyboard::Key::Named(keyboard::key::Named::ArrowRight) {
				if modifiers.control() {
					Message::NavigateNext
				} else {
					Message::None
				}
			} else {
				Message::None
			}
		}
		_ => Message::None,
	})
}

fn view(app_state: &AppState) -> Element<'_, Message> {
	match app_state {
		AppState::Locked(LockedState {
			db_name,
			db_password,
			db_pin,
			has_slots,
			offer_adopt,
			is_processing,
			status,
		}) => components::unlock_screen(
			db_name,
			db_password,
			db_pin,
			components::UnlockExtras {
				has_slots: *has_slots,
				offer_adopt: *offer_adopt,
			},
			is_processing,
			status,
		),
		AppState::Unlocked(UnlockedState {
			query,
			password_entry,
			generator,
			is_password_visible,
			is_pin_visible,
			is_note_visible,
			last_copy_time: _,
			last_interaction_time: _,
			note,
			status,
			health,
			keys,
			..
		}) => match (health, keys) {
			(Some(report), _) => components::health_screen(report, status),
			(None, Some(keys)) => components::keys_screen(keys, status),
			(None, None) => components::password_screen(
				query,
				password_entry,
				generator,
				components::Revealed {
					password: *is_password_visible,
					pin: *is_pin_visible,
					note: *is_note_visible,
				},
				note,
				status,
			),
		},
	}
}

fn update_locked(message: Message, app_state: &mut AppState) -> Task<Message> {
	let AppState::Locked(LockedState {
		db_name,
		db_password,
		db_pin,
		has_slots,
		offer_adopt,
		is_processing,
		status,
	}) = app_state
	else {
		unreachable!("update_locked called with non-Locked state")
	};
	match message {
		Message::AttemptUnlock | Message::AdoptRemote => {
			if *is_processing {
				return Task::none();
			}
			*is_processing = true;
			*status = if *has_slots {
				"Touch your security key when it blinks.".to_string()
			} else {
				String::new()
			};
			let adopt = matches!(message, Message::AdoptRemote);
			*offer_adopt = false;
			let db_name_clone = db_name.clone();
			let input = persistence::UnlockInput {
				password: std::mem::replace(db_password, Zeroizing::new(String::new())),
				pin: (!db_pin.is_empty())
					.then(|| std::mem::replace(db_pin, Zeroizing::new(String::new()))),
			};
			return Task::perform(
				async move {
					if adopt {
						persistence::adopt_remote(&db_name_clone, input).await
					} else {
						persistence::load(&db_name_clone, input).await
					}
				},
				Message::UnlockResult,
			);
		}
		Message::UnlockResult(Err(err)) => {
			*is_processing = false;
			*offer_adopt = err == persistence::DIFFERENT_VAULT_HELP;
			*status = err;
		}
		Message::UnlockResult(Ok(vault)) => {
			*app_state = AppState::Unlocked(UnlockedState {
				query: "".into(),
				password_entry: PasswordEntry::new(),
				generator: GeneratorChoice::new(),
				is_password_visible: false,
				is_pin_visible: false,
				is_note_visible: false,
				last_copy_time: None,
				last_interaction_time: Some(Instant::now()),
				note: text_editor::Content::new(),
				status: vault.status(),
				vault,
				saving: false,
				confirm_delete: false,
				health: None,
				keys: None,
			});
		}
		Message::DbNameChanged(new_db_name) => {
			*has_slots = persistence::local_has_slots(&new_db_name);
			*db_name = new_db_name;
		}
		Message::DbPinChanged(new_pin) => {
			*db_pin = new_pin;
		}
		Message::DbPasswordChanged(new_password) => {
			*db_password = new_password;
		}
		Message::CloseWindow => {
			return window::latest().and_then(window::close);
		}
		Message::DragWindow => {
			return window::latest().and_then(window::drag);
		}
		Message::FocusPrevious => {
			return focus_previous::<Id>().discard();
		}
		Message::FocusNext => {
			return focus_next::<Id>().discard();
		}
		_ => {}
	}
	Task::none()
}

/// The key number in a "Key N did not answer" message from a removal.
fn missing_key_number(err: &str) -> Option<usize> {
	err.strip_prefix("Key ")?
		.split_whitespace()
		.next()?
		.parse()
		.ok()
}

fn update_unlocked(message: Message, app_state: &mut AppState) -> Task<Message> {
	let AppState::Unlocked(UnlockedState {
		query,
		password_entry,
		generator: choice,
		is_password_visible,
		is_pin_visible,
		is_note_visible,
		last_copy_time,
		last_interaction_time,
		note,
		status,
		vault,
		saving,
		confirm_delete,
		health,
		keys,
	}) = app_state
	else {
		unreachable!("update_unlocked called with locked state")
	};
	let db = &vault.database;
	const IDLE_MESSAGE: &str = "Idle time remaining:";
	match message {
		Message::None | Message::Tick => {}
		_ => {
			*last_interaction_time = Some(Instant::now());
			if status.starts_with(IDLE_MESSAGE) {
				*status = "".to_string();
			}
			// Anything but the second press cancels a pending delete.
			if !matches!(message, Message::PasswordEntryDelete) {
				*confirm_delete = false;
			}
		}
	}
	match message {
		Message::QueryInput(new_text) => {
			*query = new_text;
		}
		Message::QuerySubmit => {
			return Task::done(Message::PasswordEntryGet);
		}
		Message::PasswordEntryNameInput(new_text) => {
			password_entry.set_name(&new_text);
		}
		Message::PasswordEntryUsernameInput(new_text) => {
			password_entry.set_username(&new_text);
		}
		Message::PasswordEntryPasswordInput(new_text) => {
			if *is_password_visible {
				password_entry.set_password(&new_text);
			}
		}
		Message::PasswordEntryPinInput(new_text) => {
			if *is_pin_visible {
				password_entry.set_pin(&new_text);
			}
		}
		Message::PasswordEntryUrlInput(new_text) => {
			password_entry.set_url(&new_text);
		}
		Message::PasswordEntryTagsInput(new_text) => {
			password_entry.set_tags(&new_text);
		}
		Message::PasswordEntryNoteAction(action) => {
			if *is_note_visible {
				note.perform(action);
				password_entry.set_note(&Zeroizing::new(note.text()));
			}
		}
		Message::NavigatePrevious => {
			*is_password_visible = false;
			*is_pin_visible = false;
			*is_note_visible = false;
			if let Some(found_password_entry) = db.previous(password_entry.get_name()) {
				*status = "Previous entry retrieved.".to_string();
				*password_entry = found_password_entry.clone();
				*note = text_editor::Content::new();
			} else {
				*status = "Previous entry not retrieved.".to_string();
				*password_entry = PasswordEntry::new();
				*note = text_editor::Content::new();
			};
		}
		Message::NavigateNext => {
			*is_password_visible = false;
			*is_pin_visible = false;
			*is_note_visible = false;
			if let Some(found_password_entry) = db.next(password_entry.get_name()) {
				*status = "Next entry retrieved.".to_string();
				*password_entry = found_password_entry.clone();
				*note = text_editor::Content::new();
			} else {
				*status = "Next entry not retrieved.".to_string();
				*password_entry = PasswordEntry::new();
				*note = text_editor::Content::new();
			};
		}
		Message::PasswordEntryGet => {
			*is_password_visible = false;
			*is_pin_visible = false;
			*is_note_visible = false;
			if let Some(found_password_entry) = db.query(query) {
				*status = "Entry retrieved.".to_string();
				*password_entry = found_password_entry.clone();
				*note = text_editor::Content::new();
			} else {
				*status = "Entry not retrieved.".to_string();
				*password_entry = PasswordEntry::new();
				*note = text_editor::Content::new();
			};
		}
		Message::PasswordEntrySet => {
			let name = password_entry.get_name();
			let note_string = password_entry.get_note();
			if !name.is_empty() {
				if let Some(mut old_entry) = db.get_password_entry_by_name(name) {
					old_entry.set_username(password_entry.get_username());
					old_entry.set_password(&password_entry.get_password());
					old_entry.set_pin(&password_entry.get_pin());
					old_entry.set_url(password_entry.get_url());
					old_entry.set_tags(password_entry.get_tags());
					old_entry.set_note(&note_string);
					db.set_password_entry(old_entry);
					*status = "Entry set.".to_string();
				} else {
					let mut new_entry = PasswordEntry::new();
					new_entry.set_name(name);
					new_entry.set_username(password_entry.get_username());
					new_entry.set_password(&password_entry.get_password());
					new_entry.set_pin(&password_entry.get_pin());
					new_entry.set_url(password_entry.get_url());
					new_entry.set_tags(password_entry.get_tags());
					new_entry.set_note(&note_string);
					db.set_password_entry(new_entry.clone());
					*password_entry = new_entry;
					*status = "New entry set.".to_string();
				}
			} else {
				*status = "Name cannot be empty.".to_string();
			}
		}
		Message::PasswordEntryDelete => {
			let name = password_entry.get_name().to_owned();
			if name.is_empty() {
				*status = "Nothing to delete: the entry has no name.".to_string();
			} else if !*confirm_delete {
				*confirm_delete = true;
				*status = format!("Delete '{name}'? Press Delete again to confirm.");
			} else {
				*confirm_delete = false;
				if db.delete_password_entry(&name) {
					*is_password_visible = false;
					*is_pin_visible = false;
					*is_note_visible = false;
					*password_entry = PasswordEntry::new();
					*note = text_editor::Content::new();
					*status = format!("Entry '{name}' deleted. Save to make it permanent.");
				} else {
					*status = format!("No saved entry named '{name}'.");
				}
			}
		}
		Message::GeneratePassword => {
			let kind = choice.kind();
			match generator::generate(&kind) {
				Some(secret) => {
					password_entry.set_password(&secret);
					*is_password_visible = true;
					let made = match kind {
						Kind::Characters { length, .. } => format!("{length} characters"),
						Kind::Passphrase { words } => format!("{words} words"),
					};
					*status = format!(
						"Generated {made}, {} bits. Set the entry to keep it.",
						generator::whole_bits(&kind)
					);
				}
				None => {
					*status = format!(
						"Nothing generated: choose a class and 1 to {} characters, or 1 to {} words.",
						generator::MAX_LENGTH,
						generator::MAX_WORDS
					);
				}
			}
		}
		Message::GeneratorKindToggled => {
			choice.words = !choice.words;
			choice.count = if choice.words {
				generator::WORD_COUNT.to_string()
			} else {
				generator::LENGTH.to_string()
			};
		}
		Message::GeneratorCountInput(text) => {
			if text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit()) {
				choice.count = text;
			}
		}
		Message::GeneratorClassToggled(bit) => {
			let c = &mut choice.classes;
			match bit {
				1 => c.upper = !c.upper,
				2 => c.lower = !c.lower,
				4 => c.digits = !c.digits,
				_ => c.symbols = !c.symbols,
			}
		}
		Message::ShowHealth => {
			let now = std::time::SystemTime::now()
				.duration_since(std::time::SystemTime::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or_default();
			let report = health::report(db, now);
			*status = if report.is_clean() {
				format!("{} entries, nothing to fix.", report.entries)
			} else {
				format!(
					"{} entries: {} reused groups, {} weak, {} stale, {} empty.",
					report.entries,
					report.reused.len(),
					report.weak.len(),
					report.stale.len(),
					report.empty.len()
				)
			};
			*health = Some(Box::new(report));
		}
		Message::HideHealth => {
			*health = None;
			*status = String::new();
		}
		Message::ShowKeys => {
			*keys = Some(Box::new(KeysScreen::new(db)));
			*status = String::new();
		}
		Message::HideKeys => {
			if keys.as_ref().is_some_and(|k| k.busy) {
				return Task::none();
			}
			*keys = None;
			*status = String::new();
		}
		Message::KeysPasswordInput(text) => {
			if let Some(keys) = keys {
				keys.password = text;
			}
		}
		Message::KeysPinInput(text) => {
			if let Some(keys) = keys {
				keys.pin = text;
			}
		}
		Message::KeysToggleTouchOnly => {
			if let Some(keys) = keys {
				keys.touch_only = !keys.touch_only;
			}
		}
		Message::RemoveKey(index) => {
			if let Some(keys) = keys {
				keys.confirm_remove = Some(index);
				keys.dropped.clear();
				*status = format!(
					"Removing key {} rekeys the vault: touch every other key when it blinks, then Save.",
					index + 1
				);
			}
		}
		Message::CancelRemoveKey => {
			if let Some(keys) = keys {
				keys.confirm_remove = None;
				keys.dropped.clear();
				*status = String::new();
			}
		}
		Message::ProtectVault | Message::AddKey | Message::ConfirmRemoveKey => {
			let Some(screen) = keys else {
				return Task::none();
			};
			if screen.busy {
				return Task::none();
			}
			let needs_password = !matches!(message, Message::AddKey);
			if needs_password && screen.password.is_empty() {
				*status = "Enter the master password to rekey.".to_string();
				return Task::none();
			}
			screen.busy = true;
			*status = "Touch your security key when it blinks.".to_string();
			let database = db.clone();
			let slots = screen.slots.clone();
			let password = screen.password.clone();
			let derive = move |salt: &[u8; 32], roaming: Option<&[u8; 32]>| {
				persistence::derive_master(&database, &password, salt, roaming)
			};
			let pin = screen.pin();
			let touch_only = screen.touch_only;
			let remove = screen.confirm_remove;
			let dropped = screen.dropped.clone();
			let action = match message {
				Message::ProtectVault => 0u8,
				Message::AddKey => 1,
				_ => 2,
			};
			// Blocking work on the executor thread, as the unlock's key
			// derivation already is; the GUI thread is not this one.
			return Task::perform(
				async move {
					match action {
						0 => crate::storage::keys::protect(&derive, pin, touch_only),
						1 => crate::storage::keys::add_key(&slots, pin, touch_only),
						_ => match remove {
							Some(index) => crate::storage::keys::remove_key(
								&derive, &slots, index, &dropped, pin,
							),
							None => Err("No key selected.".into()),
						},
					}
				},
				Message::KeysResult,
			);
		}
		Message::KeysResult(result) => {
			let Some(screen) = keys else {
				return Task::none();
			};
			screen.busy = false;
			match result {
				Ok(crate::storage::keys::KeysOutcome::Added(slot)) => {
					let mut slots = screen.slots.clone();
					slots.push(slot);
					crate::storage::keys::set_slots(db, &slots);
					screen.slots = slots;
					screen.password = Zeroizing::new(String::new());
					*status = "Key added. Save to keep it.".to_string();
				}
				Ok(crate::storage::keys::KeysOutcome::Rekeyed { key, salt, slots }) => {
					let key = std::sync::Arc::try_unwrap(key)
						.unwrap_or_else(|_| unreachable!("the ceremony owns its key"));
					db.rekey(key, &salt);
					crate::storage::keys::set_slots(db, &slots);
					vault.note_rekey();
					screen.slots = slots;
					screen.confirm_remove = None;
					screen.dropped.clear();
					screen.password = Zeroizing::new(String::new());
					*status = if screen.slots.is_empty() {
						"Protection removed and the vault rekeyed. Save to keep it.".to_string()
					} else {
						"Vault rekeyed. Save to keep it; other devices then adopt the bucket copy."
							.to_string()
					};
				}
				Err(err) => {
					// A key that did not answer during a removal may be dropped
					// by confirming again; the message names it.
					if let (Some(_), Some(number)) =
						(screen.confirm_remove, missing_key_number(&err))
					{
						screen.dropped.push(number - 1);
						*status = format!("{err} Press Remove again to drop key {number} as well.");
					} else {
						*status = err;
					}
				}
			}
		}
		Message::Save => {
			if *saving {
				return Task::none();
			}
			*saving = true;
			*status = "Saving Database...".to_string();
			return Task::perform(vault.save(), Message::SaveResult);
		}
		Message::SaveResult(msg) => {
			*saving = false;
			*status = msg;
		}
		Message::CloseWindow => {
			return window::latest().and_then(window::close);
		}
		Message::DragWindow => {
			return window::latest().and_then(window::drag);
		}
		Message::FocusPrevious => {
			return focus_previous::<Id>().discard();
		}
		Message::FocusNext => {
			return focus_next::<Id>().discard();
		}
		Message::ToggleNoteVisibility => {
			*is_note_visible = !*is_note_visible;
			*note = if *is_note_visible {
				text_editor::Content::with_text(&password_entry.get_note())
			} else {
				text_editor::Content::new()
			};
		}
		Message::TogglePasswordVisibility => {
			*is_password_visible = !*is_password_visible;
		}
		copy @ (Message::CopyUsername | Message::CopyPassword | Message::CopyPin) => {
			*last_copy_time = Some(Instant::now());
			let (label, value) = match copy {
				Message::CopyUsername => (
					"Username",
					Zeroizing::new(password_entry.get_username().to_owned()),
				),
				Message::CopyPassword => ("Password", password_entry.get_password()),
				Message::CopyPin => ("PIN", password_entry.get_pin()),
				_ => unreachable!(),
			};
			*status = format!("{label} copied.");
			// The wipe thread owns the timeout; the Tick below only reports it.
			clipboard::copy(value, COPY_TIMEOUT);
		}
		Message::TogglePinVisibility => {
			*is_pin_visible = !*is_pin_visible;
		}
		Message::Tick => {
			if let Some(lit) = last_interaction_time {
				let idle_elapsed = lit.elapsed();
				let idle_remaining = IDLE_TIMEOUT.saturating_sub(idle_elapsed).as_secs();
				if idle_remaining <= 20 {
					*status = format!("{IDLE_MESSAGE} {idle_remaining}s");
				}
				if idle_elapsed >= IDLE_TIMEOUT {
					return Task::done(Message::Lock);
				}
			}
			if let Some(lct) = *last_copy_time {
				let copy_elapsed = lct.elapsed();
				if copy_elapsed >= Duration::from_secs(4) {
					let copy_remaining = COPY_TIMEOUT.saturating_sub(copy_elapsed).as_secs();
					*status = format!("Clipboard clear time remaining: {copy_remaining}s");
				}
				if copy_elapsed >= COPY_TIMEOUT {
					*last_copy_time = None;
					*status = "Clipboard cleared.".to_string();
				}
			}
		}
		Message::Lock => {
			if keys.as_ref().is_some_and(|k| k.busy) {
				*status = "A key ceremony is running; wait for it to finish.".to_string();
				return Task::none();
			}
			clipboard::clear_pending();
			db.zeroize();
			*app_state = AppState::Locked(LockedState {
				db_name: "".into(),
				db_password: Zeroizing::new(String::new()),
				db_pin: Zeroizing::new(String::new()),
				has_slots: false,
				offer_adopt: false,
				is_processing: false,
				status: String::new(),
			});
		}
		_ => {}
	}
	Task::none()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn unlocked() -> AppState {
		let db = crate::storage::test_database();
		let mut entry = PasswordEntry::new();
		entry.set_name("example");
		entry.set_password("secret");
		entry.set_pin("1234");
		entry.set_note("private note");
		db.set_password_entry(entry);
		let mut app = new();
		let _ = update(
			&mut app,
			Message::UnlockResult(Ok(OpenedVault::for_test(db))),
		);
		let _ = update(&mut app, Message::QueryInput("example".into()));
		let _ = update(&mut app, Message::PasswordEntryGet);
		app
	}

	#[test]
	fn hidden_fields_reveal_edit_hide_and_save_without_losing_secrets() {
		let mut app = unlocked();
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(!state.is_password_visible && !state.is_pin_visible && !state.is_note_visible);
		assert!(state.note.text().is_empty());
		let _ = view(&app);
		let _ = update(
			&mut app,
			Message::PasswordEntryPasswordInput(Zeroizing::new("ignored".into())),
		);
		let _ = update(&mut app, Message::PasswordEntrySet);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		let saved = state
			.vault
			.database
			.get_password_entry_by_name("example")
			.unwrap();
		assert_eq!(saved.get_password().as_str(), "secret");
		assert_eq!(saved.get_note().as_str(), "private note");
		let _ = update(&mut app, Message::TogglePasswordVisibility);
		let _ = update(
			&mut app,
			Message::PasswordEntryPasswordInput(Zeroizing::new("replacement".into())),
		);
		let _ = update(&mut app, Message::TogglePasswordVisibility);
		let _ = update(&mut app, Message::ToggleNoteVisibility);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.note.text(), "private note");
		let _ = update(&mut app, Message::ToggleNoteVisibility);
		let _ = update(&mut app, Message::PasswordEntrySet);
		let _ = update(&mut app, Message::PasswordEntryGet);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(!state.is_password_visible && !state.is_note_visible);
		assert!(state.note.text().is_empty());
		assert_eq!(state.password_entry.get_password().as_str(), "replacement");
		assert_eq!(state.password_entry.get_pin().as_str(), "1234");
		let _ = update(&mut app, Message::Lock);
		assert!(matches!(app, AppState::Locked(_)));
	}

	#[test]
	fn delete_needs_a_second_press_and_generate_reveals_a_fresh_password() {
		let mut app = unlocked();
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.confirm_delete);
		assert!(
			state
				.vault
				.database
				.get_password_entry_by_name("example")
				.is_some()
		);
		// Any other action cancels the pending delete.
		let _ = update(&mut app, Message::QueryInput("example".into()));
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.confirm_delete);
		assert!(
			state
				.vault
				.database
				.get_password_entry_by_name("example")
				.is_some()
		);
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(!state.confirm_delete);
		assert!(
			state
				.vault
				.database
				.get_password_entry_by_name("example")
				.is_none()
		);
		assert!(state.password_entry.get_name().is_empty());
		let _ = update(&mut app, Message::GeneratePassword);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.is_password_visible);
		assert_eq!(state.password_entry.get_password().len(), generator::LENGTH);
		assert!(
			state
				.status
				.starts_with("Generated 24 characters, 152 bits.")
		);
	}

	#[test]
	fn the_health_report_shows_in_place_of_the_editor_and_comes_back() {
		let mut app = unlocked();
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		for (name, password) in [("shop", "secret"), ("pin", "1234")] {
			let mut entry = PasswordEntry::new();
			entry.set_name(name);
			entry.set_password(password);
			state.vault.database.set_password_entry(entry);
		}
		let _ = update(&mut app, Message::ShowHealth);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		let report = state.health.as_deref().expect("report on screen");
		assert_eq!(report.entries, 3);
		assert_eq!(
			state.status,
			"3 entries: 1 reused groups, 3 weak, 0 stale, 0 empty."
		);
		let lines = components::health_lines(report);
		assert_eq!(lines[0], "Reused password 1");
		assert_eq!(&lines[1..3], ["  example", "  shop"]);
		assert!(lines[3].starts_with("Weak passwords"));
		assert_eq!(lines[4], "  pin: 13 bits");
		assert!(
			lines
				.iter()
				.all(|l| !l.contains("secret") && !l.contains("1234"))
		);
		let _ = view(&app);
		let _ = update(&mut app, Message::HideHealth);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.health.is_none());
		assert!(state.status.is_empty());
		let _ = view(&app);
	}

	#[test]
	fn the_unlock_screen_asks_for_a_pin_and_offers_to_adopt() {
		let mut app = new();
		let _ = update(&mut app, Message::DbNameChanged("no-such-vault".into()));
		let AppState::Locked(state) = &app else {
			panic!()
		};
		assert!(!state.has_slots && !state.offer_adopt);
		let _ = update(
			&mut app,
			Message::DbPinChanged(Zeroizing::new("1234".into())),
		);
		let _ = update(
			&mut app,
			Message::UnlockResult(Err(persistence::DIFFERENT_VAULT_HELP.to_string())),
		);
		let AppState::Locked(state) = &app else {
			panic!()
		};
		assert!(state.offer_adopt);
		assert_eq!(state.status, persistence::DIFFERENT_VAULT_HELP);
		assert_eq!(state.db_pin.as_str(), "1234");
		let _ = view(&app);
		let _ = update(&mut app, Message::UnlockResult(Err("other".into())));
		let AppState::Locked(state) = &app else {
			panic!()
		};
		assert!(!state.offer_adopt);
	}

	#[test]
	fn the_keys_screen_applies_a_rekey_and_leaves_the_vault_alone_on_failure() {
		use crate::storage::keys::{KeysOutcome, slots_of};
		use libkeptino::roaming::{KeySlot, UvMode};
		let mut app = unlocked();
		let _ = update(&mut app, Message::ShowKeys);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.keys.as_deref().expect("keys screen").slots.is_empty());
		let before_salt = state.vault.database.salt();
		let _ = view(&app);

		// Protect without a password is refused before any ceremony.
		let _ = update(&mut app, Message::ProtectVault);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.status.starts_with("Enter the master password"));
		assert!(!state.keys.as_deref().unwrap().busy);

		// A ceremony that failed changes nothing.
		let _ = update(
			&mut app,
			Message::KeysPasswordInput(Zeroizing::new("pw".into())),
		);
		let _ = update(&mut app, Message::ProtectVault);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.keys.as_deref().unwrap().busy);
		let _ = update(&mut app, Message::KeysResult(Err("Canceled.".into())));
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.status, "Canceled.");
		assert_eq!(state.vault.database.salt(), before_salt);
		assert!(slots_of(&state.vault.database).is_empty());

		// A rekey outcome is applied: new salt, slots in the meta set.
		let new_salt = [9u8; 32];
		let slot = KeySlot::wrap(UvMode::TouchOnly, b"cred", [1; 32], &[2; 32], &[3; 32]).unwrap();
		use libkeptino::vault::KeyStore;
		let key = crate::storage::SecretMemory::from_bytes(&[7; 32]).unwrap();
		let _ = update(&mut app, Message::ProtectVault);
		let _ = update(
			&mut app,
			Message::KeysResult(Ok(KeysOutcome::Rekeyed {
				key: std::sync::Arc::new(key),
				salt: new_salt,
				slots: vec![slot.clone()],
			})),
		);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.vault.database.salt(), Some(new_salt));
		assert_eq!(slots_of(&state.vault.database), vec![slot.clone()]);
		assert_eq!(state.keys.as_deref().unwrap().slots.len(), 1);
		assert!(state.status.starts_with("Vault rekeyed."));
		let _ = view(&app);

		// Adding a key does not rekey.
		let second =
			KeySlot::wrap(UvMode::Verified, b"cred2", [4; 32], &[5; 32], &[3; 32]).unwrap();
		let _ = update(&mut app, Message::AddKey);
		let _ = update(
			&mut app,
			Message::KeysResult(Ok(KeysOutcome::Added(second.clone()))),
		);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.vault.database.salt(), Some(new_salt));
		assert_eq!(slots_of(&state.vault.database), vec![slot, second]);

		// Remove asks for confirmation; a missing key is named and can be dropped.
		let _ = update(&mut app, Message::RemoveKey(0));
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.keys.as_deref().unwrap().confirm_remove, Some(0));
		let _ = update(
			&mut app,
			Message::KeysPasswordInput(Zeroizing::new("pw".into())),
		);
		let _ = update(&mut app, Message::ConfirmRemoveKey);
		let _ = update(
			&mut app,
			Message::KeysResult(Err(
				"Key 2 did not answer (x). Plug it in and try again, or remove it too.".into(),
			)),
		);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.keys.as_deref().unwrap().dropped, vec![1]);
		assert!(state.status.contains("drop key 2 as well"));
		let _ = update(&mut app, Message::CancelRemoveKey);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.keys.as_deref().unwrap().dropped.is_empty());
		let _ = update(&mut app, Message::HideKeys);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.keys.is_none());
	}

	#[test]
	fn the_die_follows_the_generator_choice() {
		let mut app = unlocked();
		let _ = update(&mut app, Message::GeneratorKindToggled);
		let _ = update(&mut app, Message::GeneratePassword);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.generator.count, "6");
		assert!(state.status.starts_with("Generated 6 words, 77 bits."));
		// Six words of 3 to 9 letters joined by five hyphens; four table
		// words carry a hyphen of their own, so the count is a lower bound.
		let phrase = state.password_entry.get_password();
		assert!(phrase.split(generator::SEPARATOR).count() >= 6);
		assert!((23..=59).contains(&phrase.len()), "{}", *phrase);
		assert!(phrase.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
		let _ = view(&app);

		let _ = update(&mut app, Message::GeneratorKindToggled);
		for bit in [1u8, 2, 8] {
			let _ = update(&mut app, Message::GeneratorClassToggled(bit));
		}
		let _ = update(&mut app, Message::GeneratorCountInput("6x".into()));
		let _ = update(&mut app, Message::GeneratorCountInput("6".into()));
		let _ = update(&mut app, Message::GeneratePassword);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert_eq!(state.generator.count, "6");
		assert!(state.status.starts_with("Generated 6 characters, 19 bits."));
		let pin = state.password_entry.get_password();
		assert_eq!(pin.len(), 6);
		assert!(pin.bytes().all(|b| b.is_ascii_digit()));
		let _ = view(&app);

		let _ = update(&mut app, Message::GeneratorClassToggled(4));
		let _ = update(&mut app, Message::GeneratePassword);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.status.starts_with("Nothing generated"));
		assert_eq!(state.password_entry.get_password().len(), 6);
	}

	#[test]
	fn unlock_moves_password_out_of_ui_and_ignores_duplicate_submit() {
		let mut app = new();
		let _ = update(
			&mut app,
			Message::DbPasswordChanged(Zeroizing::new("master secret".into())),
		);
		let task = update(&mut app, Message::AttemptUnlock);
		let AppState::Locked(state) = &app else {
			panic!()
		};
		assert!(state.db_password.is_empty());
		assert!(state.is_processing);
		let _ = update(&mut app, Message::AttemptUnlock);
		// Dropping the unexecuted task also drops its wiping password buffer.
		drop(task);
	}
}
