//! The window's screens, drawn in the Nautilus tokens (ADR 0019,
//! doc/design.md): one filled cyan button per screen for the action that
//! commits, everything else outlined or an icon, secrets and figures in a
//! monospace face, and a status line whose parts are separated by pipes.

use crate::gui::{
	messages::{ListFilter, Message},
	state::{GeneratorChoice, KeysScreen},
};
use crate::{gui::colors, storage::PasswordEntry};
use iced::{
	Alignment, Background, Center, Color, Element, Fill, Font, Length, Padding,
	advanced::text::highlighter::PlainText,
	border, font,
	theme::{Palette, Theme},
	widget::{
		TextEditor, TextInput, button, center, checkbox, column, container, mouse_area, opaque,
		progress_bar, row, scrollable, space, stack, svg, text, text_editor, text_input, tooltip,
	},
};
use libkeptino::roaming::UvMode;
use libkeptino::{generator, health};
use zeroize::Zeroizing;

const BUTTON_HEIGHT: u32 = 38;
/// Fits "Unlocking" and "Creating" at the button face size.
const WORKING_BUTTON_WIDTH: f32 = 124.0;
const ICON_BUTTON_SIZE: u32 = 38;
const LABEL_WIDTH: u32 = 84;
/// A field's line, so an input is BUTTON_HEIGHT tall with its padding.
const FIELD_LINE: text::LineHeight = text::LineHeight::Absolute(iced::Pixels(20.0));
/// One height for every result row, so scrolling by fraction lands on a row.
const ROW_HEIGHT: u32 = 40;
const RADIUS: f32 = 8.0;
const PILL_RADIUS: f32 = 14.0;
/// A strength bar is full at this many bits; the generator's default
/// length lands near it.
const METER_FULL_BITS: f32 = 160.0;

const CLIPBOARD: &[u8] = include_bytes!("icons/clipboard.svg");
const DIE: &[u8] = include_bytes!("icons/die.svg");
const EYE_OPEN: &[u8] = include_bytes!("icons/show.svg");
const EYE_CROSSED: &[u8] = include_bytes!("icons/hide.svg");
const HEALTH: &[u8] = include_bytes!("icons/health.svg");
const KEY: &[u8] = include_bytes!("icons/key.svg");
const LOCK: &[u8] = include_bytes!("icons/lock.svg");
const REFRESH: &[u8] = include_bytes!("icons/refresh.svg");

const BOLD: Font = Font {
	weight: font::Weight::Semibold,
	..Font::DEFAULT
};

pub fn theme() -> Theme {
	Theme::custom(
		"Nautilus".to_string(),
		Palette {
			background: colors::GROUND,
			danger: colors::ROSE,
			primary: colors::CYAN,
			success: colors::GREEN,
			text: colors::TEXT,
			warning: colors::AMBER,
		},
	)
}

/// The title bar: the brand, the vault's name once one is open, its three
/// vault actions as icons, and the close button. The empty middle drags
/// the window.
pub fn title_bar<'a>(vault: Option<&str>) -> Element<'a, Message> {
	let mut bar = row![
		space::horizontal().width(14),
		text(super::state::APP_NAME)
			.size(16)
			.font(BOLD)
			.color(colors::GREEN),
	]
	.spacing(12)
	.align_y(Center);
	if let Some(name) = vault {
		bar = bar.push(
			text(name.to_owned())
				.size(14)
				.font(Font::MONOSPACE)
				.color(colors::MUTED),
		);
	}
	bar = bar.push(
		mouse_area(container(space::horizontal()).width(Fill).height(36))
			.on_press(Message::DragWindow),
	);
	if vault.is_some() {
		bar = bar
			.push(bar_icon(HEALTH, "Password health", Message::ShowHealth))
			.push(bar_icon(KEY, "Security keys", Message::ShowKeys))
			.push(bar_icon(LOCK, "Lock (Ctrl+L)", Message::Lock))
			.push(
				container(space::horizontal())
					.width(1)
					.height(20)
					.style(|_| container::Style {
						background: Some(colors::BAR_EDGE.into()),
						..Default::default()
					}),
			);
	}
	bar = bar.push(
		button(text("✕").size(16).align_x(Center).align_y(Center))
			.width(42)
			.height(36)
			.style(|_theme: &Theme, status: button::Status| button::Style {
				background: Some(Background::Color(match status {
					button::Status::Hovered => colors::ROSE_LINE,
					_ => Color::TRANSPARENT,
				})),
				text_color: match status {
					button::Status::Hovered => colors::TEXT,
					_ => colors::MUTED,
				},
				..button::Style::default()
			})
			.on_press(Message::CloseWindow),
	);
	container(bar.padding(Padding::ZERO.right(2)))
		.width(Fill)
		.height(40)
		.align_y(Center)
		.style(|_theme| container::Style {
			background: Some(colors::BAR.into()),
			border: border::Border {
				color: colors::BAR_EDGE,
				width: 1.0,
				radius: 0.0.into(),
			},
			..Default::default()
		})
		.into()
}

/// An icon in the title bar, named by its tooltip and its message.
fn bar_icon<'a>(icon: &'static [u8], label: &'a str, msg: Message) -> Element<'a, Message> {
	tooltip(
		icon_button(icon, msg),
		container(text(label).size(13).color(colors::TEXT))
			.padding([4, 8])
			.style(|_| container::Style {
				background: Some(colors::RAISED.into()),
				border: border::Border {
					color: colors::COBALT,
					width: 1.0,
					radius: 6.0.into(),
				},
				..Default::default()
			}),
		tooltip::Position::Bottom,
	)
	.into()
}

/// The status line: the message on the left, the timestamps on the right,
/// parts separated by pipes.
fn status_line<'a>(status: &'a str, right: &[String]) -> Element<'a, Message> {
	// The right parts keep their width and never wrap; the message takes
	// what is left and wraps onto a second line rather than squeezing them.
	let mut line = row![
		text(status)
			.size(13)
			.font(Font::MONOSPACE)
			.color(colors::SKY)
			.width(Fill)
	]
	.spacing(10)
	.align_y(Center);
	for (n, part) in right.iter().enumerate() {
		if n > 0 {
			line = line.push(pipe());
		}
		line = line.push(
			text(part.clone())
				.size(13)
				.font(Font::MONOSPACE)
				.color(colors::SKY)
				.wrapping(text::Wrapping::None),
		);
	}
	container(line.padding([0, 16]))
		.width(Fill)
		.padding([6, 0])
		.align_y(Center)
		.style(|_| container::Style {
			background: Some(colors::BAR.into()),
			border: border::Border {
				color: colors::BAR_EDGE,
				width: 1.0,
				radius: 0.0.into(),
			},
			..Default::default()
		})
		.into()
}

fn pipe<'a>() -> Element<'a, Message> {
	text("|")
		.size(13)
		.font(Font::MONOSPACE)
		.color(colors::DIVIDER)
		.into()
}

/// What the unlock screen shows besides the name and password.
#[derive(Clone, Copy)]
pub struct UnlockExtras {
	/// The local copy carries key slots: ask for the key's PIN too.
	pub has_slots: bool,
	/// The bucket copy has another salt: offer to adopt it.
	pub offer_adopt: bool,
}

pub fn unlock_screen<'a>(
	db_name: &str,
	db_password: &str,
	db_pin: &str,
	extras: UnlockExtras,
	is_processing: &bool,
	status: &'a str,
) -> Element<'a, Message> {
	let mut fields = column![
		center(
			text("Unlock a vault")
				.color(colors::TEXT)
				.size(22)
				.font(BOLD)
		)
		.height(36),
		labeled(
			"Vault",
			styled_text_input("name", db_name)
				.on_input(Message::DbNameChanged)
				.on_submit(Message::FocusNext)
		),
		labeled(
			"Password",
			styled_text_input("master password", db_password)
				.secure(true)
				.font(Font::MONOSPACE)
				.on_input(|value| Message::DbPasswordChanged(Zeroizing::new(value)))
				.on_submit(if extras.has_slots {
					Message::FocusNext
				} else {
					Message::AttemptUnlock
				})
		),
	]
	.spacing(12)
	.width(560);
	if extras.has_slots {
		fields = fields.push(labeled(
			"Key PIN",
			styled_text_input("security key PIN, if the key has one", db_pin)
				.secure(true)
				.font(Font::MONOSPACE)
				.on_input(|value| Message::DbPinChanged(Zeroizing::new(value)))
				.on_submit(Message::AttemptUnlock),
		));
	}
	let mut buttons = row![
		filled_button_sized(
			if *is_processing {
				"Unlocking"
			} else {
				"Unlock"
			},
			Message::AttemptUnlock,
			Some(WORKING_BUTTON_WIDTH),
		),
		outline_button(
			"Create vault",
			Message::ToggleCreate,
			colors::COBALT,
			colors::TEXT
		),
	]
	.spacing(12);
	if extras.offer_adopt {
		buttons = buttons.push(outline_button(
			"Adopt bucket copy",
			Message::AdoptRemote,
			colors::AMBER,
			colors::AMBER,
		));
	}
	fields = fields
		.push(space::vertical().height(4))
		.push(row![space::horizontal().width(LABEL_WIDTH + 12), buttons])
		.push(
			container(text(status).size(14).color(colors::SKY))
				.padding(Padding::ZERO.left(LABEL_WIDTH + 12)),
		);
	let panel = container(center(fields)).width(Fill).height(Fill);
	column![title_bar(None), panel].into()
}

/// The locked screen's other form: a name and the new master password,
/// twice. Creation never happens from Unlock (ADR 0018).
pub fn create_screen<'a>(
	db_name: &str,
	db_password: &str,
	db_password_confirm: &str,
	is_processing: &bool,
	status: &'a str,
) -> Element<'a, Message> {
	let buttons = row![
		filled_button_sized(
			if *is_processing { "Creating" } else { "Create" },
			Message::AttemptCreate,
			Some(WORKING_BUTTON_WIDTH),
		),
		outline_button("Back", Message::ToggleCreate, colors::COBALT, colors::TEXT),
	]
	.spacing(12);
	let fields = column![
		center(
			text("Create a vault")
				.color(colors::TEXT)
				.size(22)
				.font(BOLD)
		)
		.height(36),
		labeled(
			"Vault",
			styled_text_input("name", db_name)
				.on_input(Message::DbNameChanged)
				.on_submit(Message::FocusNext)
		),
		labeled(
			"Password",
			styled_text_input("new master password", db_password)
				.secure(true)
				.font(Font::MONOSPACE)
				.on_input(|value| Message::DbPasswordChanged(Zeroizing::new(value)))
				.on_submit(Message::FocusNext)
		),
		labeled(
			"Again",
			styled_text_input("the same password again", db_password_confirm)
				.secure(true)
				.font(Font::MONOSPACE)
				.on_input(|value| Message::DbPasswordConfirmChanged(Zeroizing::new(value)))
				.on_submit(Message::AttemptCreate)
		),
		space::vertical().height(4),
		row![space::horizontal().width(LABEL_WIDTH + 12), buttons],
		container(text(status).size(14).color(colors::SKY))
			.padding(Padding::ZERO.left(LABEL_WIDTH + 12)),
	]
	.spacing(12)
	.width(560);
	let panel = container(center(fields)).width(Fill).height(Fill);
	column![title_bar(None), panel].into()
}

/// Which hidden fields the user has revealed.
#[derive(Clone, Copy)]
pub struct Revealed {
	pub password: bool,
	pub pin: bool,
	pub note: bool,
}

/// A chip under find: All, a tag, or the weak passwords.
pub struct Chip {
	pub label: String,
	pub filter: ListFilter,
	pub on: bool,
	pub amber: bool,
}

/// A row of the list pane as drawn.
pub struct RowView<'a> {
	pub name: &'a str,
	pub username: &'a str,
	/// `set` or `weak`, in amber, at the row's end.
	pub flag: Option<&'static str>,
}

/// The generator panel under the password field, when it is open.
pub struct GeneratorView<'a> {
	pub choice: &'a GeneratorChoice,
	/// None when the choice is out of range.
	pub preview: Option<&'a str>,
	pub revealed: bool,
}

/// The results under find, when they are open: the chips, then the rows.
pub struct ListView<'a> {
	pub chips: Vec<Chip>,
	pub rows: Vec<RowView<'a>>,
	/// The row the arrow keys and Enter act on.
	pub cursor: Option<usize>,
	/// The name the editor opened; its row is marked.
	pub opened: Option<&'a str>,
	/// Find text is in effect, so an empty list means no match.
	pub finding: bool,
}

/// Everything the unlocked window draws (ADR 0022).
pub struct EditorView<'a> {
	pub vault_name: String,
	pub query: &'a str,
	/// Where the open entry stands among the rows shown, beside find.
	pub find_count: String,
	pub entry: &'a PasswordEntry,
	/// The editor shows a stored entry rather than a new one.
	pub is_stored: bool,
	pub revealed: Revealed,
	pub note: &'a text_editor::Content,
	/// The entry on screen has edits that are not set.
	pub draft: bool,
	/// "N set, not saved", or "Not saved" after a delete or rekey.
	pub unsaved: Option<String>,
	pub list: Option<ListView<'a>>,
	pub generator: Option<GeneratorView<'a>>,
	pub status: &'a str,
}

/// Where the popovers sit within the editor body. Inputs and buttons are
/// one height, so the rows above a popover have a fixed height too.
const BODY_PADDING: f32 = 14.0;
const BODY_SPACING: f32 = 12.0;
const FIELD_SPACING: f32 = 8.0;
const POPOVER_GAP: f32 = 4.0;
/// The results open under the find row.
const LIST_TOP: f32 = BODY_PADDING + BUTTON_HEIGHT as f32 + POPOVER_GAP;
/// The generator opens under the password row, the third field.
const GENERATOR_TOP: f32 = BODY_PADDING
	+ BUTTON_HEIGHT as f32
	+ BODY_SPACING
	+ 3.0 * BUTTON_HEIGHT as f32
	+ 2.0 * FIELD_SPACING
	+ POPOVER_GAP;
/// The results never reach the button row.
const LIST_MAX_HEIGHT: f32 = 520.0;

/// The unlocked window: find across the top, the entry under it, and the
/// results or the generator floating over the entry when open, so nothing
/// under them moves.
pub fn editor_screen(view: EditorView<'_>) -> Element<'_, Message> {
	let times = timestamps(view.entry);
	let find_row = row![
		container(
			row![
				styled_query_input("find by name or tag, Enter to open", view.query)
					.id("find")
					.on_input(Message::QueryInput)
					.on_submit(Message::QuerySubmit),
				text(view.find_count.clone())
					.size(13)
					.font(Font::MONOSPACE)
					.color(colors::MUTED)
					.wrapping(text::Wrapping::None),
			]
			.spacing(10)
			.align_y(Center)
		)
		.width(Fill),
		hint(
			outline_glyph_button(
				if view.list.is_some() { "▴" } else { "▾" },
				view.list.is_some(),
				Message::ToggleList
			),
			"All entries (Ctrl+F to find)"
		),
		hint(
			outline_glyph_button("‹", false, Message::NavigatePrevious),
			"Previous (Ctrl+Left)"
		),
		hint(
			outline_glyph_button("›", false, Message::NavigateNext),
			"Next (Ctrl+Right)"
		),
	]
	.spacing(8)
	.align_y(Center);

	let body = column![
		find_row,
		entry_fields(&view),
		container(action_row(&view)).padding(Padding::ZERO.top(8)),
	]
	.spacing(BODY_SPACING)
	.padding([BODY_PADDING, 16.0]);

	let mut layers = stack![container(body).width(Fill).height(Fill)];
	if let Some(list) = &view.list {
		layers = layers.push(popover(LIST_TOP, 16.0, results(list), Message::ToggleList));
	} else if let Some(generator) = &view.generator {
		layers = layers.push(popover(
			GENERATOR_TOP,
			16.0 + LABEL_WIDTH as f32 + 12.0,
			generator_panel(generator),
			Message::ToggleGenerator,
		));
	}
	column![
		title_bar(Some(&view.vault_name)),
		layers.width(Fill).height(Fill),
		status_line(view.status, &times),
	]
	.into()
}

/// A panel floating `top` pixels down the editor body. Clicks above it
/// reach the editor; a click beside or below it closes it.
fn popover<'a>(
	top: f32,
	left: f32,
	panel: Element<'a, Message>,
	close: Message,
) -> Element<'a, Message> {
	column![
		space::vertical().height(top),
		stack![
			mouse_area(container(space::horizontal()).width(Fill).height(Fill)).on_press(close),
			container(opaque(panel))
				.padding(Padding {
					top: 0.0,
					right: 16.0,
					bottom: 0.0,
					left,
				})
				.width(Fill),
		]
		.width(Fill)
		.height(Fill),
	]
	.width(Fill)
	.height(Fill)
	.into()
}

/// The results: chips for All, each tag and the weak passwords, then the
/// rows in name order, scrolling when they outgrow the panel.
fn results<'a>(list: &ListView<'a>) -> Element<'a, Message> {
	let mut chip_row = row![].spacing(6);
	for chip in &list.chips {
		chip_row = chip_row.push(chip_button(chip));
	}
	let mut rows = column![].spacing(2);
	if list.rows.is_empty() {
		rows = rows.push(
			container(
				text(if list.finding {
					"No entry matches."
				} else {
					"No entries here."
				})
				.size(14)
				.color(colors::MUTED),
			)
			.padding([10, 10]),
		);
	}
	for (index, row_view) in list.rows.iter().enumerate() {
		rows = rows.push(list_row(
			row_view,
			list.cursor == Some(index),
			list.opened == Some(row_view.name),
		));
	}
	let help = text("↑ ↓ move  |  Enter opens  |  Esc closes")
		.size(12)
		.font(Font::MONOSPACE)
		.color(colors::MUTED);
	container(
		column![
			chip_row.wrap().vertical_spacing(6),
			scrollable(rows.padding(Padding::ZERO.right(12)))
				.id("list")
				.height(Length::Shrink),
			help,
		]
		.spacing(10),
	)
	.padding([10, 12])
	.width(Fill)
	.max_height(LIST_MAX_HEIGHT)
	.style(|_| container::Style {
		background: Some(colors::RAISED.into()),
		border: border::Border {
			color: colors::COBALT,
			width: 1.0,
			radius: RADIUS.into(),
		},
		..Default::default()
	})
	.into()
}

fn chip_button(chip: &Chip) -> Element<'static, Message> {
	let on = chip.on;
	let amber = chip.amber;
	button(text(chip.label.clone()).size(13))
		.padding([4, 10])
		.style(move |_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(if on {
				colors::SEGMENT_ON
			} else if matches!(status, button::Status::Hovered) {
				colors::FIELD_HOVER
			} else {
				Color::TRANSPARENT
			})),
			text_color: if amber {
				colors::AMBER
			} else if on {
				colors::TEXT
			} else {
				colors::MUTED
			},
			border: border::Border {
				color: if on { colors::CYAN } else { colors::COBALT },
				width: 1.0,
				radius: PILL_RADIUS.into(),
			},
			..button::Style::default()
		})
		.on_press(Message::FilterChosen(chip.filter.clone()))
		.into()
}

fn list_row<'a>(row_view: &RowView<'a>, cursor: bool, open: bool) -> Element<'a, Message> {
	let initial = row_view
		.name
		.chars()
		.next()
		.map(|c| c.to_uppercase().to_string())
		.unwrap_or_default();
	let tile = container(
		text(initial)
			.size(14)
			.font(Font::MONOSPACE)
			.color(colors::CYAN),
	)
	.width(30)
	.height(30)
	.align_x(Center)
	.align_y(Center)
	.style(|_| container::Style {
		background: Some(colors::FIELD.into()),
		border: border::Border {
			color: colors::COBALT,
			width: 1.0,
			radius: 6.0.into(),
		},
		..Default::default()
	});
	let mut face = row![
		tile,
		container(
			text(row_view.name)
				.size(15)
				.color(colors::TEXT)
				.wrapping(text::Wrapping::None)
		)
		.width(Length::FillPortion(2))
		.clip(true),
		container(
			text(row_view.username)
				.size(14)
				.color(colors::MUTED)
				.wrapping(text::Wrapping::None)
		)
		.width(Length::FillPortion(3))
		.clip(true),
	]
	.spacing(12)
	.align_y(Center);
	face = face.push(
		container(
			text(row_view.flag.unwrap_or_default())
				.size(12)
				.font(Font::MONOSPACE)
				.color(colors::AMBER),
		)
		.width(40)
		.align_x(Alignment::End),
	);
	button(face)
		.width(Fill)
		.height(ROW_HEIGHT)
		.padding([0, 8])
		.style(move |_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(
				if cursor || matches!(status, button::Status::Hovered) {
					colors::FIELD_HOVER
				} else {
					Color::TRANSPARENT
				},
			)),
			text_color: colors::TEXT,
			border: border::Border {
				color: if cursor {
					colors::CYAN
				} else if open {
					colors::COBALT
				} else {
					Color::TRANSPARENT
				},
				width: 1.0,
				radius: 6.0.into(),
			},
			..button::Style::default()
		})
		.on_press(Message::OpenEntry(row_view.name.to_owned()))
		.into()
}

fn entry_fields<'a>(view: &EditorView<'a>) -> Element<'a, Message> {
	let entry = view.entry;
	let revealed = view.revealed;
	let password = if revealed.password {
		entry.get_password()
	} else {
		Zeroizing::new(String::new())
	};
	let password_input = styled_text_input(
		if revealed.password {
			"password"
		} else {
			"hidden, reveal to edit"
		},
		&password,
	)
	.font(Font::MONOSPACE)
	.on_input_maybe(
		revealed
			.password
			.then_some(|value| Message::PasswordEntryPasswordInput(Zeroizing::new(value))),
	)
	.on_submit(Message::FocusNext);
	let pin = if revealed.pin {
		entry.get_pin()
	} else {
		Zeroizing::new(String::new())
	};
	let pin_input = styled_text_input(
		if revealed.pin {
			"PIN"
		} else {
			"hidden, reveal to edit"
		},
		&pin,
	)
	.font(Font::MONOSPACE)
	.on_input_maybe(
		revealed
			.pin
			.then_some(|value| Message::PasswordEntryPinInput(Zeroizing::new(value))),
	)
	.on_submit(Message::FocusNext);
	// The hidden state holds empty Content in the revealed editor's place.
	// Only the revealed editor accepts input.
	let note_editor = styled_text_editor("note".into(), view.note).placeholder(if revealed.note {
		"note"
	} else {
		"hidden, reveal to edit"
	});
	let note_editor = if revealed.note {
		note_editor.on_action(Message::PasswordEntryNoteAction)
	} else {
		note_editor
	};

	column![
		labeled(
			"Name",
			styled_text_input("name", entry.get_name())
				.on_input(Message::PasswordEntryNameInput)
				.on_submit(Message::FocusNext)
		),
		labeled_row(
			"Username",
			row![
				styled_text_input("username", entry.get_username())
					.on_input(Message::PasswordEntryUsernameInput)
					.on_submit(Message::FocusNext),
				icon_button(CLIPBOARD, Message::CopyUsername),
			]
			.spacing(6)
		),
		labeled_row(
			"Password",
			row![
				password_input,
				icon_button(CLIPBOARD, Message::CopyPassword),
				visibility_button(revealed.password, Message::TogglePasswordVisibility),
				hint(
					toggle_icon_button(DIE, view.generator.is_some(), Message::ToggleGenerator),
					"Generate a password"
				),
			]
			.spacing(6)
		),
		labeled_row(
			"PIN",
			row![
				pin_input,
				icon_button(CLIPBOARD, Message::CopyPin),
				visibility_button(revealed.pin, Message::TogglePinVisibility),
			]
			.spacing(6)
		),
		labeled(
			"URL",
			styled_text_input("url", entry.get_url())
				.on_input(Message::PasswordEntryUrlInput)
				.on_submit(Message::FocusNext)
		),
		labeled(
			"Tags",
			styled_text_input("tags, comma separated", entry.get_tags())
				.on_input(Message::PasswordEntryTagsInput)
				.on_submit(Message::FocusNext)
		),
		row![
			container(text("Note").size(13).color(colors::MUTED))
				.width(LABEL_WIDTH)
				.align_x(Alignment::End)
				.padding(Padding::ZERO.top(10)),
			note_editor,
			visibility_button(revealed.note, Message::ToggleNoteVisibility),
		]
		.spacing(12)
		.height(Fill),
	]
	.spacing(FIELD_SPACING)
	.height(Fill)
	.into()
}

/// New and Delete on the left; on the right what is not set or saved,
/// Revert, Set entry and Save. Every button in the row looks alike; the
/// amber note carries the state.
fn action_row<'a>(view: &EditorView<'a>) -> Element<'a, Message> {
	let marker = if view.draft {
		"Entry edited, not set".to_owned()
	} else {
		view.unsaved.clone().unwrap_or_default()
	};
	row![
		outline_button(
			"New",
			Message::PasswordEntryNew,
			colors::COBALT,
			colors::TEXT
		),
		outline_button_maybe(
			"Delete",
			view.is_stored.then_some(Message::PasswordEntryDelete),
			colors::COBALT,
			colors::TEXT
		),
		space::horizontal(),
		text(marker).size(13).color(colors::AMBER),
		outline_button_maybe(
			"Revert",
			view.draft.then_some(Message::PasswordEntryRevert),
			colors::COBALT,
			colors::TEXT
		),
		outline_button(
			"Set entry",
			Message::PasswordEntrySet,
			colors::COBALT,
			colors::TEXT
		),
		outline_button("Save", Message::Save, colors::COBALT, colors::TEXT),
	]
	.spacing(10)
	.align_y(Center)
	.into()
}

/// A one-glyph outlined button, lit while what it opens is open.
fn outline_glyph_button<'a>(glyph: &'a str, on: bool, msg: Message) -> Element<'a, Message> {
	button(text(glyph).size(18).align_x(Center).align_y(Center))
		.width(ICON_BUTTON_SIZE)
		.height(ICON_BUTTON_SIZE)
		.style(move |theme: &Theme, status: button::Status| {
			let mut style = outline_style(colors::COBALT, colors::TEXT)(theme, status);
			if on {
				style.background = Some(Background::Color(colors::TOGGLE_ON));
				style.border.color = colors::CYAN;
			}
			style
		})
		.on_press(msg)
		.into()
}

/// A field with its label to the left.
fn labeled<'a>(label: &'a str, field: TextInput<'a, Message>) -> Element<'a, Message> {
	labeled_row(label, row![field])
}

fn labeled_row<'a>(label: &'a str, field: iced::widget::Row<'a, Message>) -> Element<'a, Message> {
	row![
		container(text(label).size(13).color(colors::MUTED))
			.width(LABEL_WIDTH)
			.align_x(Alignment::End),
		field.align_y(Center).width(Fill),
	]
	.spacing(12)
	.align_y(Center)
	.into()
}

/// The generator panel under the password field: a masked preview with
/// reveal and redraw, its strength, characters or words, how many, which
/// classes, and the button that puts the preview into the field.
fn generator_panel<'a>(view: &GeneratorView<'a>) -> Element<'a, Message> {
	let choice = view.choice;
	// The revealed preview is drawn from the borrowed secret, never copied
	// into a plain String that outlives its wiped buffer.
	let shown = match view.preview {
		Some(secret) if view.revealed => text(secret),
		Some(secret) => text("•".repeat(secret.chars().count())),
		None => text("Choose a class and a length in range."),
	};
	let preview = row![
		container(
			shown
				.size(15)
				.font(Font::MONOSPACE)
				.color(if view.preview.is_some() {
					colors::TEXT
				} else {
					colors::MUTED
				})
				.wrapping(text::Wrapping::None)
		)
		.width(Fill)
		.clip(true)
		.padding([9, 12])
		.style(|_| container::Style {
			background: Some(colors::FIELD.into()),
			border: border::Border {
				color: colors::COBALT,
				width: 1.0,
				radius: RADIUS.into(),
			},
			..Default::default()
		}),
		visibility_button(view.revealed, Message::TogglePreviewVisibility),
		hint(
			icon_button(REFRESH, Message::GeneratePassword),
			"Draw another"
		),
	]
	.spacing(6)
	.align_y(Center);

	let bits = generator::whole_bits(&choice.kind());
	let strong = bits >= health::WEAK_BITS;
	let meter_color = if strong { colors::GREEN } else { colors::AMBER };
	let meter = row![
		progress_bar(0.0..=METER_FULL_BITS, bits as f32)
			.length(Fill)
			.girth(4)
			.style(move |_| progress_bar::Style {
				background: Background::Color(colors::METER_TRACK),
				bar: Background::Color(meter_color),
				border: border::Border {
					radius: 2.0.into(),
					..Default::default()
				},
			}),
		text(format!("{bits} bits"))
			.size(13)
			.font(Font::MONOSPACE)
			.color(meter_color),
	]
	.spacing(10)
	.align_y(Center);

	let kind = row![
		segment("Characters", !choice.words),
		segment("Words", choice.words),
	];
	let count = row![
		stepper_button("−", "Fewer", Message::GeneratorCountStep(-1)),
		text_input("", &choice.count)
			.on_input(Message::GeneratorCountInput)
			.width(40)
			.size(14)
			.font(Font::MONOSPACE)
			.align_x(Center)
			.padding([5, 2])
			.style(|_: &Theme, _| text_input::Style {
				background: Background::Color(Color::TRANSPARENT),
				border: border::Border::default(),
				icon: colors::TEXT,
				placeholder: colors::PLACEHOLDER,
				value: colors::TEXT,
				selection: colors::SELECTION,
			}),
		stepper_button("+", "More", Message::GeneratorCountStep(1)),
	]
	.align_y(Center);
	let count = container(count).style(|_| container::Style {
		border: border::Border {
			color: colors::COBALT,
			width: 1.0,
			radius: 6.0.into(),
		},
		..Default::default()
	});
	let mut settings = row![kind, count].spacing(12).align_y(Center);
	if !choice.words {
		let c = choice.classes;
		let mut pills = row![].spacing(4);
		for (label, on, bit) in [
			("A-Z", c.upper, 1u8),
			("a-z", c.lower, 2),
			("0-9", c.digits, 4),
			("#%&", c.symbols, 8),
		] {
			pills = pills.push(pill(label, on, Message::GeneratorClassToggled(bit)));
		}
		settings = settings.push(pills);
	}
	let actions = row![
		space::horizontal(),
		outline_button(
			"Close",
			Message::ToggleGenerator,
			colors::COBALT,
			colors::TEXT
		),
		outline_button_maybe(
			"Use this password",
			view.preview.is_some().then_some(Message::UseGenerated),
			colors::CYAN,
			colors::TEXT
		),
	]
	.spacing(10)
	.align_y(Center);

	container(column![preview, meter, settings, actions].spacing(10))
		.padding([10, 12])
		.width(Fill)
		.style(|_| container::Style {
			background: Some(colors::RAISED.into()),
			border: border::Border {
				color: colors::COBALT,
				width: 1.0,
				radius: RADIUS.into(),
			},
			..Default::default()
		})
		.into()
}

fn segment<'a>(label: &'a str, on: bool) -> Element<'a, Message> {
	button(text(label).size(13).font(BOLD))
		.padding([6, 12])
		.style(move |_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(if on {
				colors::SEGMENT_ON
			} else if matches!(status, button::Status::Hovered) {
				colors::FIELD_HOVER
			} else {
				Color::TRANSPARENT
			})),
			text_color: if on { colors::TEXT } else { colors::MUTED },
			border: border::Border {
				color: colors::COBALT,
				width: 1.0,
				radius: 6.0.into(),
			},
			..button::Style::default()
		})
		.on_press_maybe((!on).then_some(Message::GeneratorKindToggled))
		.into()
}

fn stepper_button<'a>(label: &'a str, _hint: &'a str, msg: Message) -> Element<'a, Message> {
	button(text(label).size(15).align_x(Center))
		.width(26)
		.padding([4, 0])
		.style(|_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(match status {
				button::Status::Hovered => colors::FIELD_HOVER,
				_ => Color::TRANSPARENT,
			})),
			text_color: colors::TEXT,
			..button::Style::default()
		})
		.on_press(msg)
		.into()
}

fn pill<'a>(label: &'a str, on: bool, msg: Message) -> Element<'a, Message> {
	button(text(label).size(13).font(Font::MONOSPACE))
		.padding([5, 10])
		.style(move |_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(if on {
				colors::TOGGLE_ON
			} else if matches!(status, button::Status::Hovered) {
				colors::FIELD_HOVER
			} else {
				Color::TRANSPARENT
			})),
			text_color: if on {
				colors::TOGGLE_ON_TEXT
			} else {
				colors::MUTED
			},
			border: border::Border {
				color: if on { colors::CYAN } else { colors::TOGGLE_OFF },
				width: 1.0,
				radius: PILL_RADIUS.into(),
			},
			..button::Style::default()
		})
		.on_press(msg)
		.into()
}

/// The keys screen in place of the editor: the enrolled security keys,
/// the actions on them, and the way back.
pub fn keys_screen<'a>(keys: &'a KeysScreen, status: &'a str) -> Element<'a, Message> {
	let mut body = column![
		text("Security keys")
			.size(22)
			.font(BOLD)
			.color(colors::TEXT)
	]
	.spacing(10);
	if keys.slots.is_empty() {
		body = body.push(
			text("This vault is protected by its master password and this machine's pepper alone.")
				.size(15)
				.color(colors::TEXT),
		);
		body = body.push(
			text("Protecting it with a security key rekeys the vault: every device then needs the password, the pepper and an enrolled key. If every enrolled key is lost while the vault is locked, the vault cannot be opened.")
				.size(14)
				.color(colors::MUTED),
		);
	} else {
		body = body.push(
			text("Use any enrolled key to unlock this vault on Linux or Android.")
				.size(14)
				.color(colors::MUTED),
		);
	}
	for (index, slot) in keys.slots.iter().enumerate() {
		let mode = match slot.uv_mode {
			UvMode::Verified => "PIN or fingerprint",
			UvMode::TouchOnly => "touch only",
		};
		let id: String = slot
			.cred_id
			.iter()
			.take(4)
			.map(|b| format!("{b:02x}"))
			.collect();
		let remove = if keys.confirm_remove == Some(index) {
			row![
				outline_button(
					"Remove, rekeying",
					Message::ConfirmRemoveKey,
					colors::ROSE_LINE,
					colors::ROSE
				),
				outline_button(
					"Keep",
					Message::CancelRemoveKey,
					colors::COBALT,
					colors::TEXT
				),
			]
			.spacing(8)
		} else {
			row![outline_button(
				"Remove",
				Message::RemoveKey(index),
				colors::ROSE_LINE,
				colors::ROSE
			)]
		};
		body = body.push(
			container(
				row![
					text(format!("Key {}", index + 1))
						.size(15)
						.font(BOLD)
						.color(colors::TEXT),
					text(mode).size(14).color(colors::MUTED),
					text(format!("{id}…"))
						.size(13)
						.font(Font::MONOSPACE)
						.color(colors::MUTED),
					space::horizontal(),
					remove
				]
				.align_y(Center)
				.spacing(14)
				.padding([8, 12]),
			)
			.style(|_| container::Style {
				background: Some(colors::RAISED.into()),
				border: border::Border {
					color: colors::COBALT,
					width: 1.0,
					radius: RADIUS.into(),
				},
				..Default::default()
			}),
		);
	}
	let needs_password = keys.slots.is_empty() || keys.confirm_remove.is_some();
	if needs_password {
		body = body.push(
			styled_text_input("master password, to rekey", &keys.password)
				.secure(true)
				.font(Font::MONOSPACE)
				.on_input(|value| Message::KeysPasswordInput(Zeroizing::new(value))),
		);
	}
	body = body.push(
		styled_text_input("security key PIN, if the key has one", &keys.pin)
			.secure(true)
			.font(Font::MONOSPACE)
			.on_input(|value| Message::KeysPinInput(Zeroizing::new(value))),
	);
	body = body.push(
		checkbox(keys.touch_only)
			.label("Enroll touch-only (no PIN asked at unlock)")
			.text_size(14)
			.on_toggle(|_| Message::KeysToggleTouchOnly),
	);
	let action = if keys.slots.is_empty() {
		filled_button("Protect with a security key", Message::ProtectVault)
	} else {
		filled_button("Add a key", Message::AddKey)
	};
	let button_bar = row![
		outline_button("Back", Message::HideKeys, colors::COBALT, colors::TEXT),
		space::horizontal(),
		action,
	]
	.spacing(10)
	.padding([12, 16])
	.align_y(Center);
	let body = container(scrollable(body).height(Fill))
		.padding([16, 16])
		.width(Fill)
		.height(Fill);
	column![title_bar(None), body, button_bar, status_line(status, &[])].into()
}

/// The health report in place of the editor: four lists, names and figures
/// only, and the way back.
pub fn health_screen<'a>(report: &'a health::Report, status: &'a str) -> Element<'a, Message> {
	let mut lines = column![
		text("Password health")
			.size(22)
			.font(BOLD)
			.color(colors::TEXT)
	]
	.spacing(4);
	for line in health_lines(report) {
		let (color, size) = if line.starts_with("  ") {
			(colors::TEXT, 15)
		} else {
			(colors::AMBER, 14)
		};
		lines = lines.push(text(line).size(size).color(color));
	}
	let body = container(scrollable(lines).height(Fill))
		.padding([16, 16])
		.width(Fill)
		.height(Fill);
	let button_bar = row![
		outline_button("Back", Message::HideHealth, colors::COBALT, colors::TEXT),
		space::horizontal(),
	]
	.padding([12, 16])
	.align_y(Center);
	column![title_bar(None), body, button_bar, status_line(status, &[])].into()
}

/// The report as lines of text, in its one order: a heading, then one entry
/// per line, so a name with a comma in it stays whole.
pub fn health_lines(report: &health::Report) -> Vec<String> {
	let mut lines = Vec::new();
	if report.is_clean() {
		lines.push(format!(
			"{} entries. No reused, weak, stale or empty passwords.",
			report.entries
		));
		return lines;
	}
	if !report.reused.is_empty() {
		for (n, group) in report.reused.iter().enumerate() {
			lines.push(format!("Reused password {}", n + 1));
			for name in group {
				lines.push(format!("  {name}"));
			}
		}
	}
	if !report.weak.is_empty() {
		lines.push(format!(
			"Weak passwords, estimated under {} bits",
			health::WEAK_BITS
		));
		for weak in &report.weak {
			lines.push(format!("  {}: {} bits", weak.name, weak.bits));
		}
	}
	if !report.stale.is_empty() {
		lines.push("Not edited in a year".to_string());
		for stale in &report.stale {
			lines.push(format!(
				"  {}: last edited {}",
				stale.name,
				local_date(Some(stale.last_edited))
			));
		}
	}
	if !report.empty.is_empty() {
		lines.push("No password".to_string());
		for name in &report.empty {
			lines.push(format!("  {name}"));
		}
	}
	lines
}

fn visibility_button(visible: bool, msg: Message) -> Element<'static, Message> {
	icon_button(if visible { EYE_OPEN } else { EYE_CROSSED }, msg)
}

fn icon_button(data: &'static [u8], msg: Message) -> Element<'static, Message> {
	icon_button_with(data, colors::CYAN, false, msg)
}

fn icon_button_with(
	data: &'static [u8],
	ink: Color,
	on: bool,
	msg: Message,
) -> Element<'static, Message> {
	let icon = svg(svg::Handle::from_memory(data))
		.width(20)
		.height(20)
		.style(move |_, _| svg::Style { color: Some(ink) });
	button(center(icon))
		.width(ICON_BUTTON_SIZE)
		.height(ICON_BUTTON_SIZE)
		.padding(0)
		.style(move |_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(match status {
				button::Status::Hovered => colors::FIELD_HOVER,
				_ if on => colors::TOGGLE_ON,
				_ => Color::TRANSPARENT,
			})),
			border: border::Border {
				color: match status {
					button::Status::Hovered => colors::COBALT,
					_ if on => colors::CYAN,
					_ => Color::TRANSPARENT,
				},
				width: 1.0,
				radius: RADIUS.into(),
			},
			..button::Style::default()
		})
		.on_press(msg)
		.into()
}

/// A tooltip below any control.
fn hint<'a>(control: Element<'a, Message>, label: &'a str) -> Element<'a, Message> {
	tooltip(
		control,
		container(text(label).size(13).color(colors::TEXT))
			.padding([4, 8])
			.style(|_| container::Style {
				background: Some(colors::RAISED.into()),
				border: border::Border {
					color: colors::COBALT,
					width: 1.0,
					radius: 6.0.into(),
				},
				..Default::default()
			}),
		tooltip::Position::Bottom,
	)
	.into()
}

/// An icon button that shows whether what it opens is open.
fn toggle_icon_button(data: &'static [u8], on: bool, msg: Message) -> Element<'static, Message> {
	icon_button_with(data, colors::CYAN, on, msg)
}

/// An outlined button that is greyed out without a message.
fn outline_button_maybe<'a>(
	label: &'a str,
	msg: Option<Message>,
	line: Color,
	ink: Color,
) -> Element<'a, Message> {
	let enabled = msg.is_some();
	button(
		text(label)
			.size(15)
			.font(BOLD)
			.align_x(Center)
			.align_y(Center),
	)
	.height(BUTTON_HEIGHT)
	.padding([0, 16])
	.style(move |theme: &Theme, status: button::Status| {
		if enabled {
			outline_style(line, ink)(theme, status)
		} else {
			button::Style {
				background: Some(Background::Color(Color::TRANSPARENT)),
				text_color: colors::MUTED,
				border: border::Border {
					color: colors::TOGGLE_OFF,
					width: 1.0,
					radius: RADIUS.into(),
				},
				..button::Style::default()
			}
		}
	})
	.on_press_maybe(msg)
	.into()
}

/// The one filled button on a screen: the action that commits.
fn filled_button<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
	filled_button_sized(label, msg, None)
}

/// A filled button whose label changes while it works ("Unlock" then
/// "Unlocking") holds one width, wide enough for every label, so the
/// buttons beside it never shift.
fn filled_button_sized<'a>(
	label: &'a str,
	msg: Message,
	width: Option<f32>,
) -> Element<'a, Message> {
	let label = text(label)
		.size(15)
		.font(BOLD)
		.align_x(Center)
		.align_y(Center);
	let face = match width {
		Some(_) => button(label.width(Fill)),
		None => button(label),
	};
	face.width(width.map_or(Length::Shrink, Length::Fixed))
		.height(BUTTON_HEIGHT)
		.padding([0, 22])
		.style(|_: &Theme, status: button::Status| {
			let fill = match status {
				button::Status::Hovered => colors::SKY,
				_ => colors::CYAN,
			};
			button::Style {
				background: Some(Background::Color(fill)),
				text_color: colors::ON_CYAN,
				border: border::Border {
					color: fill,
					width: 1.0,
					radius: RADIUS.into(),
				},
				..button::Style::default()
			}
		})
		.on_press(msg)
		.into()
}

fn outline_button<'a>(
	label: &'a str,
	msg: Message,
	line: Color,
	ink: Color,
) -> Element<'a, Message> {
	button(
		text(label)
			.size(15)
			.font(BOLD)
			.align_x(Center)
			.align_y(Center),
	)
	.height(BUTTON_HEIGHT)
	.padding([0, 16])
	.style(outline_style(line, ink))
	.on_press(msg)
	.into()
}

fn outline_style(line: Color, ink: Color) -> impl Fn(&Theme, button::Status) -> button::Style {
	move |_, status| button::Style {
		background: Some(Background::Color(match status {
			button::Status::Hovered => colors::FIELD_HOVER,
			_ => Color::TRANSPARENT,
		})),
		text_color: ink,
		border: border::Border {
			color: match status {
				button::Status::Hovered => colors::CYAN,
				_ => line,
			},
			width: 1.0,
			radius: RADIUS.into(),
		},
		..button::Style::default()
	}
}

fn field_style(
	rest: Color,
	hover: Color,
	focus: Color,
) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
	move |_, status| {
		let (background, color, width) = match status {
			text_input::Status::Focused { .. } => (colors::FIELD, focus, 2.0),
			text_input::Status::Hovered => (colors::FIELD_HOVER, hover, 1.0),
			_ => (colors::FIELD, rest, 1.0),
		};
		text_input::Style {
			background: Background::Color(background),
			border: border::Border {
				color,
				width,
				radius: RADIUS.into(),
			},
			icon: colors::MUTED,
			placeholder: colors::PLACEHOLDER,
			value: colors::TEXT,
			selection: colors::SELECTION,
		}
	}
}

pub fn styled_text_input<'a, Message: Clone + 'a>(
	placeholder: &str,
	value: &str,
) -> TextInput<'a, Message> {
	text_input(placeholder, value)
		.padding([9, 12])
		.size(16)
		.line_height(FIELD_LINE)
		.style(field_style(
			colors::COBALT,
			colors::COBALT_HOVER,
			colors::CYAN,
		))
}

pub fn styled_query_input<'a, Message: Clone + 'a>(
	placeholder: &str,
	value: &str,
) -> TextInput<'a, Message> {
	text_input(placeholder, value)
		.padding([9, 12])
		.size(16)
		.line_height(FIELD_LINE)
		.width(Length::Fill)
		.style(field_style(colors::GREEN, colors::GREEN, colors::GREEN))
}

pub fn styled_text_editor<'a>(
	id: String,
	content: &'a text_editor::Content,
) -> TextEditor<'a, PlainText, Message> {
	text_editor(content)
		.id(id)
		.size(16)
		.padding([9, 12])
		.height(Fill)
		.wrapping(text::Wrapping::Word)
		.style(|_theme: &Theme, status: text_editor::Status| {
			let (background, color, width) = match status {
				text_editor::Status::Focused { .. } => (colors::FIELD, colors::CYAN, 2.0),
				text_editor::Status::Hovered => (colors::FIELD_HOVER, colors::COBALT_HOVER, 1.0),
				_ => (colors::FIELD, colors::COBALT, 1.0),
			};
			text_editor::Style {
				background: Background::Color(background),
				border: border::Border {
					color,
					width,
					radius: RADIUS.into(),
				},
				placeholder: colors::PLACEHOLDER,
				value: colors::TEXT,
				selection: colors::SELECTION,
			}
		})
}

/// The entry's two times for the right of the status line, in the local
/// time zone.
fn timestamps(entry: &PasswordEntry) -> [String; 2] {
	[
		format!("Modified {}", local_date(entry.modified())),
		format!("Created {}", local_date(entry.created())),
	]
}

/// Seconds since the Unix epoch as a local date and time, or "unknown".
fn local_date(seconds: Option<i64>) -> String {
	seconds
		.and_then(|seconds| jiff::Timestamp::from_second(seconds).ok())
		.map(|instant| {
			instant
				.to_zoned_datetime(jiff::tz::TimeZone::system())
				.strftime("%Y-%m-%d %H:%M")
				.to_string()
		})
		.unwrap_or_else(|| "unknown".to_string())
}
