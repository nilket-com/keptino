use crate::gui::{
	clipboard, components,
	messages::{ListFilter, Message},
	session_lock,
};
use crate::storage::{
	PasswordEntry,
	persistence::{self, OpenedVault},
};
use iced::{
	Element, Event, Size, Subscription, Task, application, keyboard,
	widget::{
		Id,
		operation::{self, RelativeOffset, focus_next, focus_previous},
		text_editor,
	},
	window,
};
use libkeptino::generator::{self, Classes, Kind};
use libkeptino::health;
use std::collections::BTreeMap;
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
	/// The screen creates a new vault instead of unlocking one (ADR 0018).
	creating: bool,
	/// The new vault's password, entered a second time.
	db_password_confirm: Zeroizing<String>,
}

impl LockedState {
	fn fresh() -> Self {
		Self {
			db_name: "".into(),
			db_password: Zeroizing::new(String::new()),
			db_pin: Zeroizing::new(String::new()),
			has_slots: false,
			offer_adopt: false,
			is_processing: false,
			status: String::new(),
			creating: false,
			db_password_confirm: Zeroizing::new(String::new()),
		}
	}
}

/// The keys screen: the vault's slots and the inputs its ceremonies need.
pub struct KeysScreen {
	pub slots: Vec<libkeptino::roaming::KeySlot>,
	/// The master password, needed to derive the new key for a rekey.
	pub password: Zeroizing<String>,
	/// The password typed again, asked for only when no enrolled key can
	/// release the secret that checks it (ADR 0041).
	pub confirm: Zeroizing<String>,
	pub needs_confirm: bool,
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
			confirm: Zeroizing::new(String::new()),
			needs_confirm: false,
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

/// A row of the list pane: the core's list projection of one entry,
/// read without opening its sealed record (ADR 0022).
pub struct Row {
	pub name: String,
	pub username: Zeroizing<String>,
	/// Wiped with the rest of the unlocked state when the vault locks.
	pub tags: Vec<Zeroizing<String>>,
	pub weak: bool,
}

fn load_rows(db: &crate::storage::Database) -> Vec<Row> {
	let mut rows = Vec::new();
	db.visit_list_rows(|name, row| {
		rows.push(Row {
			name: name.to_owned(),
			username: row.username.clone(),
			tags: row
				.tags
				.split(',')
				.map(str::trim)
				.filter(|tag| !tag.is_empty())
				.map(|tag| Zeroizing::new(tag.to_owned()))
				.collect(),
			weak: row.weak,
		});
	});
	rows
}

/// The rows the list pane shows: those the find lands on, if there is find
/// text, and that the chip lets through. Both lists are in name order.
fn visible<'a>(
	rows: &'a [Row],
	query: &str,
	matches: &[String],
	filter: &ListFilter,
) -> Vec<&'a Row> {
	let finding = !query.trim().is_empty();
	rows.iter()
		.filter(|row| !finding || matches.binary_search(&row.name).is_ok())
		.filter(|row| match filter {
			ListFilter::All => true,
			ListFilter::Tag(tag) => row.tags.iter().any(|own| **own == *tag),
			ListFilter::Weak => row.weak,
		})
		.collect()
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
	/// The names the find text lands on, in navigation order.
	matches: Vec<String>,
	/// The entry on screen has edits that are not set.
	draft: bool,
	/// Entries were set, deleted or rekeyed since the last save.
	unsaved: bool,
	/// The list pane's rows, rebuilt when entries are set or deleted.
	rows: Vec<Row>,
	filter: ListFilter,
	/// The name the editor opened, if it opened a stored entry.
	opened: Option<String>,
	/// Entries set since the last save, flagged in the list.
	/// Entries set since the last save, each with the number of its latest
	/// set, so a save clears only the sets it carried.
	set_names: BTreeMap<String, u64>,
	/// `set_names` as the save in flight snapshotted it.
	saving_names: BTreeMap<String, u64>,
	/// Numbers the sets.
	set_count: u64,
	generator_open: bool,
	preview: Option<Zeroizing<String>>,
	preview_revealed: bool,
	/// The results float under find.
	list_open: bool,
	/// The result row the arrow keys and Enter act on.
	list_cursor: Option<usize>,
}

impl UnlockedState {
	fn new(vault: OpenedVault) -> Self {
		let rows = load_rows(&vault.database);
		Self {
			query: String::new(),
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
			matches: Vec::new(),
			draft: false,
			unsaved: false,
			rows,
			filter: ListFilter::All,
			opened: None,
			set_names: BTreeMap::new(),
			saving_names: BTreeMap::new(),
			set_count: 0,
			generator_open: false,
			preview: None,
			preview_revealed: false,
			list_open: false,
			list_cursor: None,
		}
	}

	/// Opens the results with the cursor on the open entry's row, or the
	/// first; one popover at a time.
	fn open_list(&mut self) {
		let names = self.visible_names();
		self.list_cursor = self
			.opened
			.as_ref()
			.and_then(|opened| names.iter().position(|name| name == opened))
			.or((!names.is_empty()).then_some(0));
		self.list_open = true;
		self.close_generator();
	}

	/// Whether the chip in effect lets this entry's row through.
	fn chip_allows(&self, name: &str) -> bool {
		let row = self.rows.iter().find(|row| row.name == name);
		match &self.filter {
			ListFilter::All => true,
			ListFilter::Tag(tag) => row.is_some_and(|row| row.tags.iter().any(|own| **own == *tag)),
			ListFilter::Weak => row.is_some_and(|row| row.weak),
		}
	}

	fn close_list(&mut self) {
		self.list_open = false;
		self.list_cursor = None;
	}

	/// Where the open entry stands among the rows shown, when find text or
	/// a chip narrows them.
	fn find_count(&self) -> String {
		if self.query.trim().is_empty() && self.filter == ListFilter::All {
			return String::new();
		}
		let names = self.visible_names();
		let at = self
			.opened
			.as_ref()
			.and_then(|opened| names.iter().position(|name| name == opened));
		let count = match (at, names.len()) {
			(_, 0) => "no match".to_owned(),
			(Some(i), total) => format!("{} of {total}", i + 1),
			(None, 1) => "1 match".to_owned(),
			(None, total) => format!("{total} matches"),
		};
		match &self.filter {
			ListFilter::All => count,
			ListFilter::Tag(tag) => format!("{tag}: {count}"),
			ListFilter::Weak => format!("weak: {count}"),
		}
	}

	fn visible_names(&self) -> Vec<String> {
		visible(&self.rows, &self.query, &self.matches, &self.filter)
			.into_iter()
			.map(|row| row.name.clone())
			.collect()
	}

	/// Shows another entry, or none, in the editor. The reveals, the
	/// generator's preview and any draft go; a dropped draft is named in the
	/// returned notice, never saved.
	fn show(&mut self, entry: Option<PasswordEntry>) -> &'static str {
		self.is_password_visible = false;
		self.is_pin_visible = false;
		self.is_note_visible = false;
		self.note = text_editor::Content::new();
		self.opened = entry.as_ref().map(|entry| entry.get_name().to_owned());
		self.password_entry = entry.unwrap_or_default();
		self.close_generator();
		if std::mem::take(&mut self.draft) {
			" Unset edits were discarded."
		} else {
			""
		}
	}

	fn close_generator(&mut self) {
		self.generator_open = false;
		self.preview = None;
		self.preview_revealed = false;
	}

	/// A new preview from the current choice, or none if the choice is out
	/// of range.
	fn draw_preview(&mut self) {
		self.preview = generator::generate(&self.generator.kind());
	}

	/// Rebuilds the rows and the find after entries changed. A chip whose
	/// tag or weak entries are gone falls back to All.
	fn refresh_list(&mut self) {
		self.rows = load_rows(&self.vault.database);
		self.matches = self.vault.database.find(&self.query);
		let keep = match &self.filter {
			ListFilter::All => true,
			ListFilter::Tag(tag) => self
				.rows
				.iter()
				.any(|row| row.tags.iter().any(|own| **own == *tag)),
			ListFilter::Weak => self.rows.iter().any(|row| row.weak),
		};
		if !keep {
			self.filter = ListFilter::All;
		}
	}

	fn open(&mut self, name: &str) -> String {
		let entry = self.vault.database.get_password_entry_by_name(name);
		let found = entry.is_some();
		let dropped = self.show(entry);
		if found {
			format!("Entry retrieved.{dropped}")
		} else {
			format!("No entry named '{name}'.{dropped}")
		}
	}

	/// The editor and its popovers as the view draws them.
	fn editor_view(&self) -> components::EditorView<'_> {
		let set = self.set_names.len();
		components::EditorView {
			vault_name: self.vault.database.meta("db_name").unwrap_or_default(),
			query: &self.query,
			find_count: self.find_count(),
			entry: &self.password_entry,
			is_stored: self.opened.is_some(),
			revealed: components::Revealed {
				password: self.is_password_visible,
				pin: self.is_pin_visible,
				note: self.is_note_visible,
			},
			note: &self.note,
			draft: self.draft,
			unsaved: match (set, self.unsaved) {
				(0, false) => None,
				(0, true) => Some("Not saved".into()),
				(n, _) => Some(format!("{n} set, not saved")),
			},
			list: self.list_open.then(|| components::ListView {
				chips: self.chips(),
				rows: self.row_views(),
				cursor: self.list_cursor,
				opened: self.opened.as_deref(),
				finding: !self.query.trim().is_empty(),
			}),
			generator: self.generator_open.then_some(components::GeneratorView {
				choice: &self.generator,
				preview: self.preview.as_ref().map(|secret| secret.as_str()),
				revealed: self.preview_revealed,
			}),
			status: &self.status,
		}
	}

	/// All with the count, each tag, and the weak passwords if any.
	fn chips(&self) -> Vec<components::Chip> {
		let mut tags: BTreeMap<&str, usize> = BTreeMap::new();
		for row in &self.rows {
			for tag in &row.tags {
				*tags.entry(tag).or_default() += 1;
			}
		}
		let weak = self.rows.iter().filter(|row| row.weak).count();
		let mut chips = vec![components::Chip {
			label: format!("All {}", self.rows.len()),
			on: self.filter == ListFilter::All,
			amber: false,
			filter: ListFilter::All,
		}];
		for tag in tags.keys() {
			let filter = ListFilter::Tag((*tag).to_owned());
			chips.push(components::Chip {
				label: (*tag).to_owned(),
				on: self.filter == filter,
				amber: false,
				filter,
			});
		}
		if weak > 0 {
			chips.push(components::Chip {
				label: format!("{weak} weak"),
				on: self.filter == ListFilter::Weak,
				amber: true,
				filter: ListFilter::Weak,
			});
		}
		chips
	}

	/// The rows shown, flagged `set` or `weak`.
	fn row_views(&self) -> Vec<components::RowView<'_>> {
		visible(&self.rows, &self.query, &self.matches, &self.filter)
			.into_iter()
			.map(|row| components::RowView {
				name: &row.name,
				username: &row.username,
				flag: if self.set_names.contains_key(&row.name) {
					Some("set")
				} else if row.weak {
					Some("weak")
				} else {
					None
				},
			})
			.collect()
	}

	/// The list, find, editor and generator messages (ADR 0022). Returns
	/// None for a message this does not handle.
	fn update_panes(&mut self, message: &Message) -> Option<Task<Message>> {
		let db = self.vault.database.clone();
		match message {
			Message::QueryInput(text) => {
				self.matches = db.find(text);
				self.query = text.clone();
				self.open_list();
				// Typing puts the cursor on the first row shown.
				self.list_cursor = (!self.visible_names().is_empty()).then_some(0);
			}
			Message::QuerySubmit => {
				// The exact name if it is shown, else the first row shown,
				// else the tag.N form the core still answers.
				let names = self.visible_names();
				let query = self.query.trim().to_owned();
				let cursor = self
					.list_cursor
					.filter(|_| self.list_open)
					.and_then(|index| names.get(index));
				let pick = cursor
					.or(names.iter().find(|name| **name == query))
					.or(names.first())
					.cloned();
				self.close_list();
				if let Some(name) = pick {
					if self.opened.as_deref() != Some(&name) {
						self.status = self.open(&name);
					}
				} else if let Some(entry) = (!query.is_empty())
					.then(|| db.query(&query))
					.flatten()
					.filter(|entry| self.chip_allows(entry.get_name()))
				{
					// The open entry again keeps its edits, as a row press does.
					if self.opened.as_deref() != Some(entry.get_name()) {
						let dropped = self.show(Some(entry));
						self.status = format!("Entry retrieved.{dropped}");
					}
				} else {
					self.status = "No entry matches.".into();
				}
			}
			Message::OpenEntry(name) => {
				self.close_list();
				// Pressing the open row again keeps its edits.
				if self.opened.as_deref() != Some(name) {
					self.status = self.open(name);
				}
			}
			Message::FilterChosen(filter) => {
				self.filter = filter.clone();
				self.list_cursor = (!self.visible_names().is_empty()).then_some(0);
			}
			Message::FocusFind => {
				self.open_list();
				return Some(operation::focus("find"));
			}
			Message::ToggleList => {
				if self.list_open {
					self.close_list();
				} else {
					// Find takes the keys, so Enter and the arrows act on
					// the results the toggle opened.
					self.open_list();
					return Some(operation::focus("find"));
				}
			}
			Message::ListCursor(step) => {
				let count = self.visible_names().len();
				if !self.list_open || count == 0 {
					return Some(Task::none());
				}
				let index = match (self.list_cursor, *step > 0) {
					(Some(i), true) => (i + 1) % count,
					(Some(i), false) => (i + count - 1) % count,
					(None, true) => 0,
					(None, false) => count - 1,
				};
				self.list_cursor = Some(index);
				// Rows are one height, so this fraction keeps the row in view.
				let y = if count > 1 {
					index as f32 / (count - 1) as f32
				} else {
					0.0
				};
				return Some(operation::snap_to(
					"list",
					RelativeOffset {
						x: None,
						y: Some(y),
					},
				));
			}
			Message::Escape => {
				self.close_list();
				self.close_generator();
			}
			Message::NavigatePrevious | Message::NavigateNext => {
				let forward = matches!(message, Message::NavigateNext);
				let which = if forward { "Next" } else { "Previous" };
				let names = self.visible_names();
				// No row shown: leave the editor, and its draft, alone.
				if names.is_empty() {
					self.status = format!("{which}: no entry shown.");
					return Some(Task::none());
				}
				let at = self
					.opened
					.as_ref()
					.and_then(|opened| names.iter().position(|name| name == opened));
				let index = match (at, forward) {
					(Some(i), true) => (i + 1) % names.len(),
					(Some(i), false) => (i + names.len() - 1) % names.len(),
					(None, true) => 0,
					(None, false) => names.len() - 1,
				};
				if at != Some(index) {
					self.status = self.open(&names[index]);
				}
				self.close_list();
			}
			Message::PasswordEntryNew => {
				let dropped = self.show(None);
				self.status = format!("New entry: name it, fill it in, then Set entry.{dropped}");
			}
			Message::PasswordEntryRevert => {
				if !self.draft {
					self.status = "Nothing to revert.".into();
				} else {
					let entry = self
						.opened
						.as_ref()
						.and_then(|name| db.get_password_entry_by_name(name));
					self.show(entry);
					self.status = "Unset edits reverted.".into();
				}
			}
			Message::PasswordEntrySet => {
				let name = self.password_entry.get_name().to_owned();
				if name.is_empty() {
					self.status = "Name cannot be empty.".into();
					return Some(Task::none());
				}
				let entry = &self.password_entry;
				let note = entry.get_note();
				let (mut stored, is_new) = match db.get_password_entry_by_name(&name) {
					Some(old) => (old, false),
					None => {
						let mut fresh = PasswordEntry::new();
						fresh.set_name(&name);
						(fresh, true)
					}
				};
				stored.set_username(entry.get_username());
				stored.set_password(&entry.get_password());
				stored.set_pin(&entry.get_pin());
				stored.set_url(entry.get_url());
				stored.set_tags(entry.get_tags());
				stored.set_note(&note);
				db.set_password_entry(stored.clone());
				if is_new {
					self.password_entry = stored;
				}
				self.opened = Some(name.clone());
				self.set_count += 1;
				self.set_names.insert(name, self.set_count);
				self.draft = false;
				self.unsaved = true;
				// A set can add or drop the tag or name the find matches.
				self.refresh_list();
				self.status = if is_new {
					"New entry set. Save to keep it.".into()
				} else {
					"Entry set. Save to keep it.".into()
				};
			}
			Message::PasswordEntryDelete => {
				let name = self.password_entry.get_name().to_owned();
				if name.is_empty() {
					self.status = "Nothing to delete: the entry has no name.".into();
				} else if !self.confirm_delete {
					self.confirm_delete = true;
					self.status = format!("Delete '{name}'? Press Delete again to confirm.");
				} else {
					self.confirm_delete = false;
					if db.delete_password_entry(&name) {
						self.show(None);
						self.set_names.remove(&name);
						self.unsaved = true;
						self.refresh_list();
						self.status = format!("Entry '{name}' deleted. Save to make it permanent.");
					} else {
						self.status = format!("No saved entry named '{name}'.");
					}
				}
			}
			Message::PasswordEntryNameInput(text) => self.password_entry.set_name(text),
			Message::PasswordEntryUsernameInput(text) => self.password_entry.set_username(text),
			Message::PasswordEntryUrlInput(text) => self.password_entry.set_url(text),
			Message::PasswordEntryTagsInput(text) => self.password_entry.set_tags(text),
			// Hidden fields take no input; the inputs are read-only then too.
			Message::PasswordEntryPasswordInput(text) => {
				if self.is_password_visible {
					self.password_entry.set_password(text);
				}
			}
			Message::PasswordEntryPinInput(text) => {
				if self.is_pin_visible {
					self.password_entry.set_pin(text);
				}
			}
			Message::PasswordEntryNoteAction(action) => {
				if self.is_note_visible {
					self.note.perform(action.clone());
					self.password_entry
						.set_note(&Zeroizing::new(self.note.text()));
				}
			}
			Message::ToggleGenerator => {
				if self.generator_open {
					self.close_generator();
				} else {
					self.close_list();
					self.generator_open = true;
					self.preview_revealed = false;
					self.draw_preview();
				}
			}
			Message::TogglePreviewVisibility => {
				self.preview_revealed = !self.preview_revealed;
			}
			Message::GeneratePassword => {
				self.draw_preview();
				if self.preview.is_none() {
					self.status = format!(
						"Nothing generated: choose a class and 1 to {} characters, or 1 to {} words.",
						generator::MAX_LENGTH,
						generator::MAX_WORDS
					);
				}
			}
			Message::UseGenerated => {
				if let Some(secret) = self.preview.take() {
					self.password_entry.set_password(&secret);
					self.draft = true;
					self.close_generator();
					self.status = format!(
						"Password filled in, {} bits. Set the entry to keep it.",
						generator::whole_bits(&self.generator.kind())
					);
				}
			}
			_ => return None,
		}
		Some(Task::none())
	}
}

enum AppState {
	Locked(LockedState),
	Unlocked(Box<UnlockedState>),
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
	AppState::Locked(LockedState::fresh())
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
	iced::event::listen_with(|event, status, _window| {
		// A focused input takes Escape to unfocus itself; the popovers close
		// on it all the same. Other keys count only when no widget took them.
		let escape = matches!(
			&event,
			Event::Keyboard(keyboard::Event::KeyPressed {
				key: keyboard::Key::Named(keyboard::key::Named::Escape),
				..
			})
		);
		(escape || matches!(status, iced::event::Status::Ignored)).then(|| key_message(event))
	})
}

fn key_message(event: Event) -> Message {
	match event {
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
			} else if let keyboard::Key::Character(character) = key.as_ref()
				&& character.eq_ignore_ascii_case("f")
				&& modifiers.control()
			{
				Message::FocusFind
			} else if key == keyboard::Key::Named(keyboard::key::Named::ArrowUp) {
				Message::ListCursor(-1)
			} else if key == keyboard::Key::Named(keyboard::key::Named::ArrowDown) {
				Message::ListCursor(1)
			} else if key == keyboard::Key::Named(keyboard::key::Named::Escape) {
				Message::Escape
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
	}
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
			creating,
			db_password_confirm,
		}) => {
			if *creating {
				components::create_screen(
					db_name,
					db_password,
					db_password_confirm,
					is_processing,
					status,
				)
			} else {
				components::unlock_screen(
					db_name,
					db_password,
					db_pin,
					components::UnlockExtras {
						has_slots: *has_slots,
						offer_adopt: *offer_adopt,
					},
					is_processing,
					status,
				)
			}
		}
		AppState::Unlocked(state) => match (&state.health, &state.keys) {
			(Some(report), _) => components::health_screen(report, &state.status),
			(None, Some(keys)) => components::keys_screen(keys, &state.status),
			(None, None) => components::editor_screen(state.editor_view()),
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
		creating,
		db_password_confirm,
	}) = app_state
	else {
		unreachable!("update_locked called with non-Locked state")
	};
	match message {
		Message::AttemptUnlock | Message::AdoptRemote => {
			if *is_processing || *creating {
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
		Message::ToggleCreate => {
			if *is_processing {
				return Task::none();
			}
			*creating = !*creating;
			*offer_adopt = false;
			*db_password = Zeroizing::new(String::new());
			*db_password_confirm = Zeroizing::new(String::new());
			*status = if *creating {
				"The master password cannot be recovered. Keep it, and the pepper seed, safe."
					.into()
			} else {
				String::new()
			};
		}
		Message::AttemptCreate => {
			if *is_processing || !*creating {
				return Task::none();
			}
			if db_password.is_empty() {
				*status = "Enter a master password for the new vault.".into();
				return Task::none();
			}
			if **db_password != **db_password_confirm {
				*status = "The two passwords differ.".into();
				*db_password_confirm = Zeroizing::new(String::new());
				return Task::none();
			}
			*is_processing = true;
			*status = "Creating the vault; deriving the key takes a moment.".into();
			*db_password_confirm = Zeroizing::new(String::new());
			let password = std::mem::replace(db_password, Zeroizing::new(String::new()));
			let db_name_clone = db_name.clone();
			return Task::perform(
				async move { persistence::create(&db_name_clone, password).await },
				Message::UnlockResult,
			);
		}
		Message::DbPasswordConfirmChanged(new_password) => {
			*db_password_confirm = new_password;
		}
		Message::UnlockResult(Err(err)) => {
			*is_processing = false;
			*offer_adopt = err == persistence::DIFFERENT_VAULT_HELP;
			*status = err;
		}
		Message::UnlockResult(Ok(vault)) => {
			*app_state = AppState::Unlocked(Box::new(UnlockedState::new(vault)));
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
	let AppState::Unlocked(state) = app_state else {
		unreachable!("update_unlocked called with locked state")
	};
	let UnlockedState {
		is_password_visible,
		is_pin_visible,
		is_note_visible,
		last_interaction_time,
		status,
		confirm_delete,
		draft,
		..
	} = &mut **state;
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
	// Any edit to the entry on screen is a draft until it is set.
	if matches!(
		message,
		Message::PasswordEntryNameInput(_)
			| Message::PasswordEntryUsernameInput(_)
			| Message::PasswordEntryUrlInput(_)
			| Message::PasswordEntryTagsInput(_)
	) || (*is_password_visible && matches!(message, Message::PasswordEntryPasswordInput(_)))
		|| (*is_pin_visible && matches!(message, Message::PasswordEntryPinInput(_)))
		|| (*is_note_visible
			&& matches!(&message, Message::PasswordEntryNoteAction(action) if action.is_edit()))
	{
		*draft = true;
	}
	if let AppState::Unlocked(state) = app_state
		&& let Some(task) = state.update_panes(&message)
	{
		return task;
	}
	let AppState::Unlocked(state) = app_state else {
		unreachable!("update_unlocked called with locked state")
	};
	let UnlockedState {
		query: _,
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
		confirm_delete: _,
		health,
		keys,
		draft: _,
		unsaved,
		set_names,
		saving_names,
		generator_open,
		preview,
		..
	} = &mut **state;
	let db = &vault.database;
	match message {
		Message::GeneratorKindToggled => {
			choice.words = !choice.words;
			choice.count = if choice.words {
				generator::WORD_COUNT.to_string()
			} else {
				generator::LENGTH.to_string()
			};
			// The open panel's preview follows the choice.
			if *generator_open {
				*preview = generator::generate(&choice.kind());
			}
		}
		Message::GeneratorCountInput(text) => {
			if text.len() <= 3 && text.bytes().all(|b| b.is_ascii_digit()) {
				choice.count = text;
			}
			// The open panel's preview follows the choice.
			if *generator_open {
				*preview = generator::generate(&choice.kind());
			}
		}
		Message::GeneratorCountStep(step) => {
			let max = if choice.words {
				generator::MAX_WORDS
			} else {
				generator::MAX_LENGTH
			};
			// Typed input can hold any three digits; step, then clamp both ways.
			let count = choice.count.parse::<usize>().unwrap_or(0);
			let next = if step < 0 {
				count.saturating_sub(1)
			} else {
				count + 1
			}
			.clamp(1, max);
			choice.count = next.to_string();
			// The open panel's preview follows the choice.
			if *generator_open {
				*preview = generator::generate(&choice.kind());
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
			// The open panel's preview follows the choice.
			if *generator_open {
				*preview = generator::generate(&choice.kind());
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
		Message::KeysConfirmInput(text) => {
			if let Some(keys) = keys {
				keys.confirm = text;
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
				keys.confirm = Zeroizing::new(String::new());
				keys.needs_confirm = false;
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
			if screen.needs_confirm && *screen.confirm != *screen.password {
				*status = "The two passwords differ.".to_string();
				return Task::none();
			}
			screen.busy = true;
			*status = "Touch your security key when it blinks.".to_string();
			let confirmed = screen.needs_confirm;
			let database = db.clone();
			let slots = screen.slots.clone();
			let password = screen.password.clone();
			let checked = (database.clone(), password.clone());
			let derive = move |salt: &[u8; 32], roaming: Option<&[u8; 32]>| {
				persistence::derive_master(&database, &password, salt, roaming)
			};
			let verify = move |roaming: Option<&[u8; 32]>| {
				persistence::verify_password(&checked.0, &checked.1, roaming)
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
						0 => crate::storage::keys::protect(&derive, &verify, pin, touch_only),
						1 => crate::storage::keys::add_key(&slots, pin, touch_only),
						_ => match remove {
							Some(index) => crate::storage::keys::remove_key(
								&derive, &verify, &slots, index, &dropped, pin, confirmed,
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
					*unsaved = true;
					*status = "Key added. Save to keep it.".to_string();
				}
				Ok(crate::storage::keys::KeysOutcome::Rekeyed { key, salt, slots }) => {
					let key = std::sync::Arc::try_unwrap(key)
						.unwrap_or_else(|_| unreachable!("the ceremony owns its key"));
					db.rekey(key, &salt);
					crate::storage::keys::set_slots(db, &slots);
					vault.note_rekey();
					*unsaved = true;
					screen.slots = slots;
					screen.confirm_remove = None;
					screen.dropped.clear();
					screen.password = Zeroizing::new(String::new());
					screen.confirm = Zeroizing::new(String::new());
					screen.needs_confirm = false;
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
						if err == crate::storage::keys::CONFIRM_PASSWORD {
							screen.needs_confirm = true;
						}
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
			*unsaved = false;
			*saving_names = set_names.clone();
			*status = "Saving Database...".to_string();
			return Task::perform(vault.save(), Message::SaveResult);
		}
		Message::SaveResult(msg) => {
			*saving = false;
			// Saved locally counts as saved; nothing written does not.
			let failed = msg.starts_with("Not saved") || msg.starts_with("Local save failed");
			let carried = std::mem::take(saving_names);
			if failed {
				*unsaved = true;
			} else {
				// A set made while the save ran is newer than the one it
				// wrote, and stays flagged; a deleted name is already gone.
				set_names.retain(|name, number| carried.get(name) != Some(number));
			}
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
			*app_state = AppState::Locked(LockedState::fresh());
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
		let _ = update(&mut app, Message::QuerySubmit);
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
		let _ = update(&mut app, Message::QuerySubmit);
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
	fn delete_needs_a_second_press_and_the_generator_fills_a_fresh_password() {
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
		// The die opens the panel with a preview; the field is untouched
		// until the preview is used, and then it is a draft.
		let _ = update(&mut app, Message::ToggleGenerator);
		let state = editor(&app);
		assert_eq!(state.preview.as_ref().unwrap().len(), generator::LENGTH);
		assert!(state.password_entry.get_password().is_empty());
		assert!(!state.draft);
		let _ = view(&app);
		let preview = state.preview.clone().unwrap();
		let _ = update(&mut app, Message::UseGenerated);
		let state = editor(&app);
		assert_eq!(*state.password_entry.get_password(), *preview);
		assert!(state.draft && !state.generator_open && state.preview.is_none());
		assert!(
			!state.is_password_visible,
			"using a preview reveals nothing"
		);
		assert!(
			state.status.starts_with("Password filled in, 152 bits."),
			"{}",
			state.status
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
	fn removing_the_last_key_without_a_key_asks_for_the_password_twice() {
		let mut app = unlocked();
		let _ = update(&mut app, Message::ShowKeys);
		let _ = update(&mut app, Message::RemoveKey(0));
		let _ = update(
			&mut app,
			Message::KeysPasswordInput(Zeroizing::new("pw".into())),
		);
		let _ = update(&mut app, Message::ConfirmRemoveKey);
		let _ = update(
			&mut app,
			Message::KeysResult(Err(crate::storage::keys::CONFIRM_PASSWORD.into())),
		);
		let keys = |app: &AppState| match app {
			AppState::Unlocked(state) => (
				state.keys.as_deref().unwrap().needs_confirm,
				state.keys.as_deref().unwrap().busy,
				state.status.clone(),
			),
			_ => panic!(),
		};
		assert_eq!(
			keys(&app),
			(
				true,
				false,
				crate::storage::keys::CONFIRM_PASSWORD.to_string()
			)
		);
		let _ = view(&app);
		// A confirmation that differs starts nothing.
		let _ = update(
			&mut app,
			Message::KeysConfirmInput(Zeroizing::new("pv".into())),
		);
		let _ = update(&mut app, Message::ConfirmRemoveKey);
		assert_eq!(
			keys(&app),
			(true, false, "The two passwords differ.".to_string())
		);
		// The same password twice starts the removal.
		let _ = update(
			&mut app,
			Message::KeysConfirmInput(Zeroizing::new("pw".into())),
		);
		let _ = update(&mut app, Message::ConfirmRemoveKey);
		assert!(keys(&app).1, "the ceremony runs");
		// Canceling clears the confirmation.
		let _ = update(&mut app, Message::KeysResult(Err("Canceled.".into())));
		let _ = update(&mut app, Message::CancelRemoveKey);
		assert!(!keys(&app).0);
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
		let preview = |app: &AppState| editor(app).preview.clone();
		let _ = update(&mut app, Message::ToggleGenerator);
		let _ = update(&mut app, Message::GeneratorKindToggled);
		assert_eq!(editor(&app).generator.count, "6");
		// Six words of 3 to 9 letters joined by five hyphens; four table
		// words carry a hyphen of their own, so the count is a lower bound.
		let phrase = preview(&app).unwrap();
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
		assert_eq!(editor(&app).generator.count, "6");
		let pin = preview(&app).unwrap();
		assert_eq!(pin.len(), 6);
		assert!(pin.bytes().all(|b| b.is_ascii_digit()));
		let _ = update(&mut app, Message::GeneratePassword);
		assert_eq!(preview(&app).unwrap().len(), 6, "redraw keeps the choice");
		let _ = view(&app);

		// No class left: no preview, and Use does nothing.
		let _ = update(&mut app, Message::GeneratorClassToggled(4));
		assert!(preview(&app).is_none());
		let _ = update(&mut app, Message::GeneratePassword);
		assert!(editor(&app).status.starts_with("Nothing generated"));
		let _ = update(&mut app, Message::UseGenerated);
		assert!(editor(&app).generator_open && !editor(&app).draft);
		let _ = view(&app);
		// Closing drops the preview; leaving the entry closes the panel.
		let _ = update(&mut app, Message::GeneratorClassToggled(4));
		let _ = update(&mut app, Message::ToggleGenerator);
		assert!(!editor(&app).generator_open && preview(&app).is_none());
		let _ = update(&mut app, Message::ToggleGenerator);
		let _ = update(&mut app, Message::PasswordEntryNew);
		assert!(!editor(&app).generator_open && preview(&app).is_none());
	}

	/// A vault of four entries, two of them tagged "work".
	fn four_entries() -> AppState {
		let db = crate::storage::test_database();
		for (name, tags, password) in [
			("bank", "money", "b"),
			("mail", "work", "m"),
			("router", "", "r"),
			("wiki", "work", "correct-horse-battery-staple-42"),
		] {
			let mut entry = PasswordEntry::new();
			entry.set_name(name);
			entry.set_tags(tags);
			entry.set_password(password);
			db.set_password_entry(entry);
		}
		let mut app = new();
		let _ = update(
			&mut app,
			Message::UnlockResult(Ok(OpenedVault::for_test(db))),
		);
		app
	}

	fn editor(app: &AppState) -> &UnlockedState {
		match app {
			AppState::Unlocked(state) => state,
			AppState::Locked(_) => panic!("locked"),
		}
	}

	#[test]
	fn find_opens_the_first_row_and_the_arrows_step_through_the_rows() {
		let mut app = four_entries();
		let name = |app: &AppState| editor(app).password_entry.get_name().to_owned();
		let shown = |app: &AppState| editor(app).visible_names();
		// No find text: every row, and the arrows walk them.
		assert_eq!(shown(&app), ["bank", "mail", "router", "wiki"]);
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "bank");

		// Zero matches: Enter opens nothing, leaves the editor, says so.
		let _ = update(&mut app, Message::QueryInput("nothing".into()));
		assert!(shown(&app).is_empty());
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(name(&app), "bank");
		assert_eq!(editor(&app).status, "No entry matches.");

		// One match, by part of a name in another case.
		let _ = update(&mut app, Message::QueryInput("ROUT".into()));
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(name(&app), "router");
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "router", "one row wraps onto itself");

		// Several matches: a tag. Enter opens the first; the arrows wrap.
		let _ = update(&mut app, Message::QueryInput("work".into()));
		assert_eq!(shown(&app), ["mail", "wiki"]);
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(name(&app), "mail");
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "wiki");
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "mail");
		let _ = update(&mut app, Message::NavigatePrevious);
		assert_eq!(name(&app), "wiki");

		// A query with no match: the arrows keep the entry and its draft.
		let _ = update(&mut app, Message::PasswordEntryUrlInput("x".into()));
		let _ = update(&mut app, Message::QueryInput("nothing".into()));
		for arrow in [Message::NavigateNext, Message::NavigatePrevious] {
			let _ = update(&mut app, arrow);
			assert_eq!(name(&app), "wiki");
			assert!(editor(&app).draft, "no match never discards a draft");
		}
		let _ = update(&mut app, Message::PasswordEntrySet);

		// Set refreshes the matches as an entry gains or loses the tag.
		let _ = update(&mut app, Message::QueryInput("work".into()));
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(name(&app), "mail");
		let _ = update(&mut app, Message::PasswordEntryTagsInput("".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert_eq!(shown(&app), ["wiki"]);
		let _ = update(&mut app, Message::PasswordEntryTagsInput("work".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert_eq!(shown(&app), ["mail", "wiki"]);
		let _ = update(&mut app, Message::PasswordEntryTagsInput("".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "wiki");
		let _ = update(&mut app, Message::NavigateNext);
		assert_eq!(name(&app), "wiki", "mail left the matches");

		// An exact name wins over earlier partial matches.
		let _ = update(&mut app, Message::QueryInput("wiki".into()));
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(name(&app), "wiki");
		let _ = view(&app);
	}

	#[test]
	fn a_set_entry_is_saved_without_an_unset_draft_on_another() {
		let mut app = four_entries();
		let _ = update(&mut app, Message::QueryInput("bank".into()));
		let _ = update(&mut app, Message::QuerySubmit);
		let _ = update(
			&mut app,
			Message::PasswordEntryUrlInput("https://bank.example".into()),
		);
		assert!(editor(&app).draft && !editor(&app).unsaved);
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert!(!editor(&app).draft && editor(&app).unsaved);

		// An accidental edit on another entry stays a draft...
		let _ = update(&mut app, Message::QueryInput("mail".into()));
		let _ = update(&mut app, Message::QuerySubmit);
		let _ = update(&mut app, Message::PasswordEntryUsernameInput("oops".into()));
		assert!(editor(&app).draft);
		let _ = view(&app);
		// ...and Save writes the vault as set: bank's edit, not mail's.
		let task = update(&mut app, Message::Save);
		drop(task);
		let state = editor(&app);
		assert!(!state.unsaved && state.saving);
		let db = &state.vault.database;
		assert_eq!(
			db.get_password_entry_by_name("bank").unwrap().get_url(),
			"https://bank.example"
		);
		assert_eq!(
			db.get_password_entry_by_name("mail")
				.unwrap()
				.get_username(),
			""
		);
		let _ = update(
			&mut app,
			Message::SaveResult("Local save failed. Check disk space and file permissions.".into()),
		);
		assert!(editor(&app).unsaved, "a failed write is still unsaved");

		// Leaving the draft discards it, and says so.
		let _ = update(&mut app, Message::OpenEntry("bank".into()));
		let state = editor(&app);
		assert!(!state.draft);
		assert!(
			state.status.ends_with("Unset edits were discarded."),
			"{}",
			state.status
		);
		assert_eq!(
			state
				.vault
				.database
				.get_password_entry_by_name("mail")
				.unwrap()
				.get_username(),
			""
		);

		// Revealing a secret is not an edit; New clears the editor.
		let _ = update(&mut app, Message::TogglePasswordVisibility);
		assert!(!editor(&app).draft);
		let _ = update(&mut app, Message::PasswordEntryNew);
		assert_eq!(editor(&app).password_entry.get_name(), "");
	}

	#[test]
	fn the_generator_stepper_stays_in_range() {
		let mut app = four_entries();
		let count = |app: &AppState| editor(app).generator.count.clone();
		let _ = update(&mut app, Message::GeneratorCountInput("1".into()));
		let _ = update(&mut app, Message::GeneratorCountStep(-1));
		assert_eq!(count(&app), "1");
		let _ = update(&mut app, Message::GeneratorCountStep(1));
		assert_eq!(count(&app), "2");
		let _ = update(
			&mut app,
			Message::GeneratorCountInput(generator::MAX_LENGTH.to_string()),
		);
		let _ = update(&mut app, Message::GeneratorCountStep(1));
		assert_eq!(count(&app), generator::MAX_LENGTH.to_string());
		let _ = update(&mut app, Message::GeneratorKindToggled);
		let _ = update(
			&mut app,
			Message::GeneratorCountInput(generator::MAX_WORDS.to_string()),
		);
		let _ = update(&mut app, Message::GeneratorCountStep(1));
		assert_eq!(count(&app), generator::MAX_WORDS.to_string());
		// Typed past the maximum, either step lands back in range.
		let _ = update(&mut app, Message::GeneratorCountInput("999".into()));
		let _ = update(&mut app, Message::GeneratorCountStep(-1));
		assert_eq!(count(&app), generator::MAX_WORDS.to_string());
		let _ = update(&mut app, Message::GeneratorCountInput("0".into()));
		let _ = update(&mut app, Message::GeneratorCountStep(1));
		assert_eq!(count(&app), "1");
		let _ = update(&mut app, Message::ToggleGenerator);
		let _ = update(&mut app, Message::UseGenerated);
		assert!(editor(&app).draft, "a generated password is a draft");
	}

	#[test]
	fn chips_and_find_narrow_the_list_together() {
		let mut app = four_entries();
		let shown = |app: &AppState| editor(app).visible_names();
		let chips = |app: &AppState| {
			editor(app)
				.chips()
				.iter()
				.map(|chip| chip.label.clone())
				.collect::<Vec<_>>()
		};
		assert_eq!(chips(&app), ["All 4", "money", "work", "3 weak"]);
		let _ = update(
			&mut app,
			Message::FilterChosen(ListFilter::Tag("work".into())),
		);
		assert_eq!(shown(&app), ["mail", "wiki"]);
		let _ = update(&mut app, Message::QueryInput("m".into()));
		assert_eq!(shown(&app), ["mail"]);
		let _ = update(&mut app, Message::FilterChosen(ListFilter::Weak));
		assert_eq!(shown(&app), ["mail"]);
		let _ = update(&mut app, Message::QueryInput(String::new()));
		assert_eq!(shown(&app), ["bank", "mail", "router"]);
		let _ = view(&app);

		// The chip's tag leaves every entry: the list falls back to All.
		let _ = update(
			&mut app,
			Message::FilterChosen(ListFilter::Tag("money".into())),
		);
		let _ = update(&mut app, Message::OpenEntry("bank".into()));
		let _ = update(&mut app, Message::PasswordEntryTagsInput("".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert_eq!(editor(&app).filter, ListFilter::All);
		assert_eq!(chips(&app), ["All 4", "work", "3 weak"]);

		// With no row shown, the arrows leave the editor and its draft.
		let _ = update(&mut app, Message::QueryInput("nothing".into()));
		let _ = update(&mut app, Message::PasswordEntryUrlInput("x".into()));
		for arrow in [Message::NavigateNext, Message::NavigatePrevious] {
			let _ = update(&mut app, arrow);
			assert_eq!(editor(&app).password_entry.get_name(), "bank");
			assert!(editor(&app).draft);
		}
	}

	#[test]
	fn a_row_opens_its_entry_and_revert_restores_the_opened_one() {
		let mut app = four_entries();
		let _ = update(&mut app, Message::OpenEntry("mail".into()));
		assert_eq!(editor(&app).opened.as_deref(), Some("mail"));
		let _ = update(&mut app, Message::PasswordEntryUsernameInput("oops".into()));
		// The open row again keeps the edit; another row drops it, and says so.
		let _ = update(&mut app, Message::OpenEntry("mail".into()));
		assert_eq!(editor(&app).password_entry.get_username(), "oops");
		let _ = update(&mut app, Message::OpenEntry("wiki".into()));
		let state = editor(&app);
		assert_eq!(state.password_entry.get_name(), "wiki");
		assert!(!state.draft);
		assert!(
			state.status.ends_with("Unset edits were discarded."),
			"{}",
			state.status
		);

		// Revert puts the opened entry back, even after its name was edited.
		let _ = update(&mut app, Message::PasswordEntryNameInput("wiki2".into()));
		let _ = update(&mut app, Message::PasswordEntryUrlInput("u".into()));
		let _ = update(&mut app, Message::PasswordEntryRevert);
		let state = editor(&app);
		assert_eq!(state.password_entry.get_name(), "wiki");
		assert_eq!(state.password_entry.get_url(), "");
		assert!(!state.draft);
		assert_eq!(state.status, "Unset edits reverted.");
		let _ = update(&mut app, Message::PasswordEntryRevert);
		assert_eq!(editor(&app).status, "Nothing to revert.");

		// A new entry reverts to empty.
		let _ = update(&mut app, Message::PasswordEntryNew);
		let _ = update(&mut app, Message::PasswordEntryNameInput("new".into()));
		let _ = update(&mut app, Message::PasswordEntryRevert);
		assert_eq!(editor(&app).password_entry.get_name(), "");
		assert!(editor(&app).opened.is_none());
		let _ = view(&app);
	}

	#[test]
	fn the_set_flag_clears_on_a_save_and_stays_after_a_failed_one() {
		let mut app = four_entries();
		let flag = |app: &AppState, name: &str| {
			editor(app)
				.row_views()
				.into_iter()
				.find(|row| row.name == name)
				.and_then(|row| row.flag)
		};
		assert_eq!(flag(&app, "wiki"), None);
		assert_eq!(flag(&app, "bank"), Some("weak"));
		let _ = update(&mut app, Message::OpenEntry("wiki".into()));
		let _ = update(&mut app, Message::PasswordEntryUrlInput("u".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert_eq!(flag(&app, "wiki"), Some("set"));
		assert_eq!(
			editor(&app).editor_view().unsaved.as_deref(),
			Some("1 set, not saved")
		);

		let _ = update(&mut app, Message::Save);
		assert_eq!(
			flag(&app, "wiki"),
			Some("set"),
			"flagged until the save lands"
		);
		assert_eq!(
			editor(&app).editor_view().unsaved.as_deref(),
			Some("1 set, not saved")
		);
		let _ = update(
			&mut app,
			Message::SaveResult("Local save failed. Check disk space and file permissions.".into()),
		);
		assert_eq!(flag(&app, "wiki"), Some("set"));
		let _ = update(&mut app, Message::Save);
		let _ = update(
			&mut app,
			Message::SaveResult("Saved locally and to the bucket.".into()),
		);
		assert_eq!(flag(&app, "wiki"), None);
		assert_eq!(editor(&app).editor_view().unsaved, None);
		let _ = update(
			&mut app,
			Message::SaveResult("Saved locally and to the bucket.".into()),
		);
		assert_eq!(flag(&app, "wiki"), None);

		// Set again while a save runs: one entry counted once, still set after.
		let _ = update(&mut app, Message::PasswordEntryUrlInput("v".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		let _ = update(&mut app, Message::Save);
		let _ = update(&mut app, Message::PasswordEntryUrlInput("w".into()));
		let _ = update(&mut app, Message::PasswordEntrySet);
		assert_eq!(
			editor(&app).editor_view().unsaved.as_deref(),
			Some("1 set, not saved")
		);
		let _ = update(
			&mut app,
			Message::SaveResult("Saved locally and to the bucket.".into()),
		);
		assert_eq!(flag(&app, "wiki"), Some("set"), "the newer set is unsaved");
		let _ = update(&mut app, Message::Save);
		let _ = update(
			&mut app,
			Message::SaveResult("Saved locally and to the bucket.".into()),
		);
		assert_eq!(flag(&app, "wiki"), None);

		// A delete is unsaved with nothing set.
		let _ = update(&mut app, Message::OpenEntry("router".into()));
		let _ = update(&mut app, Message::PasswordEntryDelete);
		let _ = update(&mut app, Message::PasswordEntryDelete);
		assert_eq!(
			editor(&app).editor_view().unsaved.as_deref(),
			Some("Not saved")
		);
		assert!(
			editor(&app)
				.visible_names()
				.iter()
				.all(|name| name != "router")
		);
		let _ = view(&app);
	}

	#[test]
	fn the_results_float_under_find_and_the_keys_drive_them() {
		let mut app = four_entries();
		let state = |app: &AppState| {
			let state = editor(app);
			(state.list_open, state.list_cursor)
		};
		// Typing opens the results with the cursor on the first row.
		let _ = update(&mut app, Message::QueryInput("i".into()));
		assert_eq!(editor(&app).visible_names(), ["mail", "wiki"]);
		assert_eq!(state(&app), (true, Some(0)));
		let _ = view(&app);
		// The arrows move the cursor and wrap; Enter opens its row and closes.
		let _ = update(&mut app, Message::ListCursor(1));
		assert_eq!(state(&app), (true, Some(1)));
		let _ = update(&mut app, Message::ListCursor(1));
		assert_eq!(state(&app), (true, Some(0)));
		let _ = update(&mut app, Message::ListCursor(-1));
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(editor(&app).password_entry.get_name(), "wiki");
		assert_eq!(state(&app), (false, None));
		// Closed, the arrow keys do nothing.
		let _ = update(&mut app, Message::ListCursor(1));
		assert_eq!(state(&app), (false, None));

		// The toggle opens every row shown, the cursor on the open entry.
		let _ = update(&mut app, Message::QueryInput(String::new()));
		let _ = update(&mut app, Message::Escape);
		assert_eq!(state(&app), (false, None));
		let _ = update(&mut app, Message::ToggleList);
		assert_eq!(state(&app), (true, Some(3)));
		assert_eq!(editor(&app).editor_view().list.unwrap().rows.len(), 4);
		// One popover at a time.
		let _ = update(&mut app, Message::ToggleGenerator);
		assert!(editor(&app).generator_open && !editor(&app).list_open);
		let _ = view(&app);
		let _ = update(&mut app, Message::FocusFind);
		assert!(!editor(&app).generator_open && editor(&app).list_open);
		let _ = update(&mut app, Message::OpenEntry("bank".into()));
		assert_eq!(state(&app), (false, None));
		assert_eq!(editor(&app).find_count(), "");
		let _ = update(
			&mut app,
			Message::FilterChosen(ListFilter::Tag("work".into())),
		);
		assert_eq!(editor(&app).find_count(), "work: 2 matches");

		// Enter never opens a row the chip hides, by name or by tag.N.
		let _ = update(&mut app, Message::FilterChosen(ListFilter::Weak));
		for query in ["wiki", "work.2"] {
			let _ = update(&mut app, Message::QueryInput(query.into()));
			let _ = update(&mut app, Message::QuerySubmit);
			assert_eq!(editor(&app).password_entry.get_name(), "bank", "{query}");
			assert_eq!(editor(&app).status, "No entry matches.");
		}
		let _ = update(&mut app, Message::FilterChosen(ListFilter::All));
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(
			editor(&app).password_entry.get_name(),
			"wiki",
			"tag.N reaches it"
		);
		// tag.N naming the open entry keeps its draft.
		let _ = update(
			&mut app,
			Message::PasswordEntryUrlInput("https://draft.example".into()),
		);
		let _ = update(&mut app, Message::QuerySubmit);
		assert_eq!(
			editor(&app).password_entry.get_url(),
			"https://draft.example"
		);
		assert!(editor(&app).draft);
	}

	#[test]
	fn create_asks_for_the_password_twice_and_moves_it_out_of_the_ui() {
		let locked = |app: &AppState| match app {
			AppState::Locked(state) => (
				state.creating,
				state.is_processing,
				state.db_password.to_string(),
				state.db_password_confirm.to_string(),
				state.status.clone(),
			),
			AppState::Unlocked(_) => panic!("unlocked"),
		};
		let mut app = new();
		// Unlock's form never creates; Create is its own mode.
		let _ = update(&mut app, Message::AttemptCreate);
		assert!(!locked(&app).1);
		let _ = update(&mut app, Message::ToggleCreate);
		let _ = view(&app);
		assert!(locked(&app).0);
		assert!(locked(&app).4.contains("cannot be recovered"));
		let _ = update(&mut app, Message::DbNameChanged("new".into()));
		let _ = update(&mut app, Message::AttemptCreate);
		assert!(!locked(&app).1);
		assert!(locked(&app).4.contains("Enter a master password"));
		let _ = update(
			&mut app,
			Message::DbPasswordChanged(Zeroizing::new("one".into())),
		);
		let _ = update(
			&mut app,
			Message::DbPasswordConfirmChanged(Zeroizing::new("two".into())),
		);
		let _ = update(&mut app, Message::AttemptCreate);
		let (_, processing, password, confirm, status) = locked(&app);
		assert!(!processing && password == "one" && confirm.is_empty());
		assert_eq!(status, "The two passwords differ.");
		// Unlock is ignored while the create form is up.
		let _ = update(&mut app, Message::AttemptUnlock);
		assert!(!locked(&app).1);
		let _ = update(
			&mut app,
			Message::DbPasswordConfirmChanged(Zeroizing::new("one".into())),
		);
		let task = update(&mut app, Message::AttemptCreate);
		let (creating, processing, password, confirm, _) = locked(&app);
		assert!(creating && processing && password.is_empty() && confirm.is_empty());
		let _ = update(&mut app, Message::ToggleCreate);
		assert!(locked(&app).0, "Back waits for the running creation");
		drop(task);
		let _ = update(&mut app, Message::UnlockResult(Err("Not created.".into())));
		let _ = update(&mut app, Message::ToggleCreate);
		assert!(!locked(&app).0);
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
