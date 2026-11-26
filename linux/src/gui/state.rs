use crate::gui::{clipboard, components, generator, messages::Message, session_lock};
use crate::storage::{
	entry::PasswordEntry,
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
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct LockedState {
	db_name: String,
	db_password: Zeroizing<String>,
	is_processing: bool,
	status: String,
}

struct UnlockedState {
	query: String,
	password_entry: PasswordEntry,
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
			is_processing,
			status,
		}) => components::unlock_screen(db_name, db_password, is_processing, status),
		AppState::Unlocked(UnlockedState {
			query,
			password_entry,
			is_password_visible,
			is_pin_visible,
			is_note_visible,
			last_copy_time: _,
			last_interaction_time: _,
			note,
			status,
			..
		}) => components::password_screen(
			query,
			password_entry,
			is_password_visible,
			is_pin_visible,
			is_note_visible,
			note,
			status,
		),
	}
}

fn update_locked(message: Message, app_state: &mut AppState) -> Task<Message> {
	let AppState::Locked(LockedState {
		db_name,
		db_password,
		is_processing,
		status,
	}) = app_state
	else {
		unreachable!("update_locked called with non-Locked state")
	};
	match message {
		Message::AttemptUnlock => {
			if *is_processing {
				return Task::none();
			}
			*is_processing = true;
			status.clear();
			let db_name_clone = db_name.clone();
			let unlock_password = std::mem::replace(db_password, Zeroizing::new(String::new()));
			return Task::perform(
				async move { persistence::load(&db_name_clone, unlock_password).await },
				Message::UnlockResult,
			);
		}
		Message::UnlockResult(Err(err)) => {
			*is_processing = false;
			*status = err;
		}
		Message::UnlockResult(Ok(vault)) => {
			*app_state = AppState::Unlocked(UnlockedState {
				query: "".into(),
				password_entry: PasswordEntry::new(),
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
			});
		}
		Message::DbNameChanged(new_db_name) => {
			*db_name = new_db_name;
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

fn update_unlocked(message: Message, app_state: &mut AppState) -> Task<Message> {
	let AppState::Unlocked(UnlockedState {
		query,
		password_entry,
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
			password_entry.set_password(&generator::password(generator::LENGTH));
			*is_password_visible = true;
			*status = "Password generated. Set the entry to keep it.".to_string();
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
			clipboard::clear_pending();
			db.zeroize();
			*app_state = AppState::Locked(LockedState {
				db_name: "".into(),
				db_password: Zeroizing::new(String::new()),
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
		let db = crate::storage::database::Database::test_database();
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
		assert!(state.vault.database.get_password_entry_by_name("example").is_some());
		// Any other action cancels the pending delete.
		let _ = update(&mut app, Message::QueryInput("example".into()));
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.confirm_delete);
		assert!(state.vault.database.get_password_entry_by_name("example").is_some());
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(!state.confirm_delete);
		assert!(state.vault.database.get_password_entry_by_name("example").is_none());
		assert!(state.password_entry.get_name().is_empty());
		let _ = update(&mut app, Message::GeneratePassword);
		let AppState::Unlocked(state) = &app else {
			panic!()
		};
		assert!(state.is_password_visible);
		assert_eq!(state.password_entry.get_password().len(), generator::LENGTH);
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
