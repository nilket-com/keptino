//! The window's screens, drawn in the Nautilus tokens (ADR 0019,
//! doc/design.md): one filled cyan button per screen for the action that
//! commits, everything else outlined or an icon, secrets and figures in a
//! monospace face, and a status line whose parts are separated by pipes.

use crate::gui::{
	messages::Message,
	state::{GeneratorChoice, KeysScreen},
};
use crate::{gui::colors, storage::PasswordEntry};
use iced::{
	Alignment, Background, Center, Color, Element, Fill, Font, Length, Padding,
	advanced::text::highlighter::PlainText,
	border, font,
	theme::{Palette, Theme},
	widget::{
		TextEditor, TextInput, button, center, checkbox, column, container, mouse_area,
		progress_bar, row, scrollable, space, svg, text, text_editor, text_input, tooltip,
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

/// What the editor marks around the entry: the vault's name, where the
/// find stands, and what has not been set or saved.
pub struct EditorMarks {
	pub vault_name: String,
	/// With find text: the entry's place among the matches, and their count.
	pub find: Option<(Option<usize>, usize)>,
	/// The entry on screen has edits that are not set.
	pub draft: bool,
	/// Entries were set or deleted since the last save.
	pub unsaved: bool,
}

pub fn password_screen<'a>(
	query: &str,
	password_entry: &PasswordEntry,
	generator: &'a GeneratorChoice,
	revealed: Revealed,
	marks: EditorMarks,
	note: &'a text_editor::Content,
	status: &'a str,
) -> Element<'a, Message> {
	let find_count = match marks.find {
		None => String::new(),
		Some((_, 0)) => "no match".to_string(),
		Some((Some(at), total)) => format!("{at} of {total}"),
		Some((None, 1)) => "1 match".to_string(),
		Some((None, total)) => format!("{total} matches"),
	};
	let find_row = row![
		container(
			row![
				styled_query_input("find by name or tag, Enter to open", query)
					.on_input(Message::QueryInput)
					.on_submit(Message::QuerySubmit),
				text(find_count)
					.size(13)
					.font(Font::MONOSPACE)
					.color(colors::MUTED),
			]
			.spacing(10)
			.align_y(Center)
		)
		.width(Fill),
		outline_icon_text("‹", "Previous match (Ctrl+Left)", Message::NavigatePrevious),
		outline_icon_text("›", "Next match (Ctrl+Right)", Message::NavigateNext),
	]
	.spacing(8)
	.align_y(Center);

	let password = if revealed.password {
		password_entry.get_password()
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
		password_entry.get_pin()
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
	let note_editor = styled_text_editor("note".into(), note).placeholder(if revealed.note {
		"note"
	} else {
		"hidden, reveal to edit"
	});
	let note_editor = if revealed.note {
		note_editor.on_action(Message::PasswordEntryNoteAction)
	} else {
		note_editor
	};

	let fields = column![
		labeled(
			"Name",
			styled_text_input("name", password_entry.get_name())
				.on_input(Message::PasswordEntryNameInput)
				.on_submit(Message::FocusNext)
		),
		labeled_row(
			"Username",
			row![
				styled_text_input("username", password_entry.get_username())
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
			]
			.spacing(6)
		),
		row![
			space::horizontal().width(LABEL_WIDTH + 12),
			generator_strip(generator)
		],
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
			styled_text_input("url", password_entry.get_url())
				.on_input(Message::PasswordEntryUrlInput)
				.on_submit(Message::FocusNext)
		),
		labeled(
			"Tags",
			styled_text_input("tags, comma separated", password_entry.get_tags())
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
	.spacing(8)
	.height(Fill);

	let marker = if marks.draft {
		"Entry edited, not set"
	} else if marks.unsaved {
		"Set, not saved"
	} else {
		""
	};
	let action_row = row![
		outline_button(
			"New",
			Message::PasswordEntryNew,
			colors::COBALT,
			colors::TEXT
		),
		outline_button(
			"Delete",
			Message::PasswordEntryDelete,
			colors::ROSE_LINE,
			colors::ROSE
		),
		space::horizontal(),
		text(marker).size(13).color(colors::AMBER),
		outline_button(
			"Set entry",
			Message::PasswordEntrySet,
			colors::CYAN,
			colors::TEXT
		),
		filled_button("Save", Message::Save),
	]
	.spacing(10)
	.align_y(Center);

	let body = column![
		find_row,
		fields,
		container(action_row).padding(Padding::ZERO.top(8)),
	]
	.spacing(12)
	.padding([14, 16]);
	column![
		title_bar(Some(&marks.vault_name)),
		container(body).width(Fill).height(Fill),
		status_line(status, &timestamps(password_entry)),
	]
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

/// The generator under the password field: characters or words, how many,
/// which classes, how strong, and the button that makes one.
fn generator_strip(choice: &GeneratorChoice) -> Element<'_, Message> {
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
	let mut strip = row![kind, count].spacing(12).align_y(Center);
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
		strip = strip.push(pills);
	}
	let bits = generator::whole_bits(&choice.kind());
	let strong = bits >= health::WEAK_BITS;
	let meter_color = if strong { colors::GREEN } else { colors::AMBER };
	strip = strip
		.push(
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
		)
		.push(
			text(format!("{bits} bits"))
				.size(13)
				.font(Font::MONOSPACE)
				.color(meter_color),
		)
		.push(
			button(
				row![
					svg(svg::Handle::from_memory(DIE))
						.width(16)
						.height(16)
						.style(|_, _| svg::Style {
							color: Some(colors::CYAN)
						}),
					text("Generate").size(13).font(BOLD),
				]
				.spacing(6)
				.align_y(Center),
			)
			.padding([5, 10])
			.style(outline_style(colors::CYAN, colors::TOGGLE_ON_TEXT))
			.on_press(Message::GeneratePassword),
		);
	container(strip.padding([8, 10]))
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
	let icon = svg(svg::Handle::from_memory(data))
		.width(20)
		.height(20)
		.style(|_, _| svg::Style {
			color: Some(colors::CYAN),
		});
	button(center(icon))
		.width(ICON_BUTTON_SIZE)
		.height(ICON_BUTTON_SIZE)
		.padding(0)
		.style(|_: &Theme, status: button::Status| button::Style {
			background: Some(Background::Color(match status {
				button::Status::Hovered => colors::FIELD_HOVER,
				_ => Color::TRANSPARENT,
			})),
			border: border::Border {
				color: match status {
					button::Status::Hovered => colors::COBALT,
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

/// A one-glyph outlined button with a tooltip, for the find arrows.
fn outline_icon_text<'a>(glyph: &'a str, hint: &'a str, msg: Message) -> Element<'a, Message> {
	tooltip(
		button(text(glyph).size(18).align_x(Center).align_y(Center))
			.width(ICON_BUTTON_SIZE)
			.height(ICON_BUTTON_SIZE)
			.style(outline_style(colors::COBALT, colors::TEXT))
			.on_press(msg),
		container(text(hint).size(13).color(colors::TEXT))
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
