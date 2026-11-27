use crate::gui::{
	messages::Message,
	state::{GeneratorChoice, KeysScreen},
};
use crate::{gui::colors, storage::PasswordEntry};
use iced::{
	Alignment, Background, Center, Color, Element, Fill, Font, Padding,
	advanced::text::highlighter::PlainText,
	border, font,
	theme::{Palette, Theme},
	widget::{
		TextEditor, TextInput, button, center, checkbox, column, container, mouse_area, row,
		scrollable, space, svg, text, text_editor, text_input, tooltip,
	},
};
use keptino_core::roaming::UvMode;
use keptino_core::{generator, health};
use zeroize::Zeroizing;

const DEFAULT_BUTTON_SIZE: (u32, u32) = (120, 40);
const ICON_BUTTON_SIZE: u32 = 44;
const CLIPBOARD: &[u8] = include_bytes!("icons/clipboard.svg");
const DIE: &[u8] = include_bytes!("icons/die.svg");
const EYE_OPEN: &[u8] = include_bytes!("icons/show.svg");
const EYE_CROSSED: &[u8] = include_bytes!("icons/hide.svg");

pub fn theme() -> Theme {
	Theme::custom(
		"BlackHole".to_string(),
		Palette {
			background: colors::BG_PRIMARY,
			danger: colors::DANGER,
			primary: colors::PRIMARY,
			success: colors::SUCCESS,
			text: colors::TEXT_PRIMARY,
			warning: colors::WARNING,
		},
	)
}

pub fn title_bar<'a>() -> Element<'a, Message> {
	container(
		row![
			mouse_area(container(row![
				space::horizontal(),
				space::horizontal().width(42),
				text(super::state::APP_NAME)
					.size(16)
					.font(Font {
						weight: font::Weight::Bold,
						..Default::default()
					})
					.color(colors::BRAND_GREEN),
				space::horizontal()
			]))
			.on_press(Message::DragWindow),
			button(
				text("✕")
					.font(Font {
						weight: font::Weight::Bold,
						..Default::default()
					})
					.size(18)
					.align_y(Center)
					.align_x(Center)
			)
			.width(42)
			.height(36)
			.style(|_theme: &Theme, status: button::Status| {
				match status {
					button::Status::Hovered => button::Style {
						background: Some(Background::Color(colors::BRAND_PURPLE)),
						text_color: colors::TEXT_TITLE_BUTTON_HOVER,
						..button::Style::default()
					},
					_ => button::Style {
						background: Some(Background::Color(Color::TRANSPARENT)),
						text_color: colors::TEXT_TITLE_BUTTON,
						..button::Style::default()
					},
				}
			})
			.on_press(Message::CloseWindow),
		]
		.padding(0)
		.align_y(iced::Center),
	)
	.width(Fill)
	.height(36)
	.style(|_theme| container::Style {
		background: Some(colors::BG_SECONDARY.into()),
		border: border::Border {
			color: colors::BORDER_SECONDARY,
			width: 2.0,
			radius: 0.0.into(),
		},
		..Default::default()
	})
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
		center(text("Unlock Database").color(colors::BRAND_GREEN).size(18)).height(30),
		styled_text_input("db_name...", db_name)
			.on_input(Message::DbNameChanged)
			.on_submit(Message::FocusNext),
		styled_text_input("db_password...", db_password)
			.secure(true)
			.on_input(|value| Message::DbPasswordChanged(Zeroizing::new(value)))
			.on_submit(if extras.has_slots {
				Message::FocusNext
			} else {
				Message::AttemptUnlock
			}),
	]
	.spacing(20)
	.width(600);
	if extras.has_slots {
		fields = fields.push(
			styled_text_input("security key PIN (if the key has one)...", db_pin)
				.secure(true)
				.on_input(|value| Message::DbPinChanged(Zeroizing::new(value)))
				.on_submit(Message::AttemptUnlock),
		);
	}
	let mut buttons = row![styled_button(
		if *is_processing {
			"Unlocking"
		} else {
			"Unlock"
		},
		Message::AttemptUnlock,
		DEFAULT_BUTTON_SIZE,
	)]
	.spacing(20);
	if extras.offer_adopt {
		buttons = buttons.push(styled_button(
			"Adopt bucket copy",
			Message::AdoptRemote,
			(220, 40),
		));
	}
	fields = fields
		.push(center(buttons).height(40))
		.push(center(text(status).color(colors::TEXT_STATUS)).height(100));
	let unlock_panel = container(center(fields)).width(Fill).height(Fill);

	column![title_bar(), unlock_panel].into()
}

fn styled_tooltip<'a, Message: 'a>(
	underlay: impl Into<Element<'a, Message>>,
	label: &'a str,
	adjacent_buttons: u32,
) -> Element<'a, Message> {
	// Iced snaps right-side tooltips to the window edge. Inset the label past the buttons.
	let padding = Padding::new(10.0).right(28 + ICON_BUTTON_SIZE * adjacent_buttons);
	tooltip(
		underlay,
		container(text(label).color(colors::BRAND_GREEN).size(18)).padding(padding),
		tooltip::Position::Right,
	)
	.into()
}

/// Which hidden fields the user has revealed.
#[derive(Clone, Copy)]
pub struct Revealed {
	pub password: bool,
	pub pin: bool,
	pub note: bool,
}

pub fn password_screen<'a>(
	query: &str,
	password_entry: &PasswordEntry,
	generator: &'a GeneratorChoice,
	revealed: Revealed,
	note: &'a text_editor::Content,
	status: &'a str,
) -> Element<'a, Message> {
	let (is_password_visible, is_pin_visible, is_note_visible) =
		(&revealed.password, &revealed.pin, &revealed.note);
	let query_input = styled_tooltip(
		styled_query_input("query...", query)
			.on_input(Message::QueryInput)
			.on_submit(Message::QuerySubmit),
		"Query",
		0,
	);
	let header = container(column![query_input]).padding([8, 4]).width(Fill);
	let name_input = styled_tooltip(
		styled_text_input("name", password_entry.get_name())
			.on_input(Message::PasswordEntryNameInput)
			.on_submit(Message::FocusNext),
		"Name",
		0,
	);
	let username_input = styled_text_input("username", password_entry.get_username())
		.on_input(Message::PasswordEntryUsernameInput)
		.on_submit(Message::FocusNext);
	let password = if *is_password_visible {
		password_entry.get_password()
	} else {
		Zeroizing::new(String::new())
	};
	let password_input = styled_text_input(
		if *is_password_visible {
			"password"
		} else {
			"Hidden — reveal to edit"
		},
		&password,
	)
	.on_input_maybe(
		is_password_visible
			.then_some(|value| Message::PasswordEntryPasswordInput(Zeroizing::new(value))),
	)
	.on_submit(Message::FocusNext);
	let username_copy_button = icon_button(CLIPBOARD, Message::CopyUsername);
	let password_copy_button = icon_button(CLIPBOARD, Message::CopyPassword);
	let password_visibility_toggle =
		visibility_button(*is_password_visible, Message::TogglePasswordVisibility);
	let pin = if *is_pin_visible {
		password_entry.get_pin()
	} else {
		Zeroizing::new(String::new())
	};
	let pin_input = styled_text_input(
		if *is_pin_visible {
			"pin"
		} else {
			"Hidden — reveal to edit"
		},
		&pin,
	)
	.on_input_maybe(
		is_pin_visible.then_some(|value| Message::PasswordEntryPinInput(Zeroizing::new(value))),
	)
	.on_submit(Message::FocusNext);
	let pin_copy_button = icon_button(CLIPBOARD, Message::CopyPin);
	let pin_visibility_toggle = visibility_button(*is_pin_visible, Message::TogglePinVisibility);
	let url_input = styled_tooltip(
		styled_text_input("url", password_entry.get_url())
			.on_input(Message::PasswordEntryUrlInput)
			.on_submit(Message::FocusNext),
		"URL",
		0,
	);
	let tags_input = styled_tooltip(
		styled_text_input("tags", password_entry.get_tags())
			.on_input(Message::PasswordEntryTagsInput)
			.on_submit(Message::FocusNext),
		"Tags",
		0,
	);
	// The hidden state contains empty Content, but occupies the same area as
	// the revealed editor. Only the revealed editor accepts input.
	let note_editor = styled_text_editor("note".into(), note).placeholder(if *is_note_visible {
		"note"
	} else {
		"Note hidden — reveal to edit"
	});
	let note_editor = if *is_note_visible {
		note_editor.on_action(Message::PasswordEntryNoteAction)
	} else {
		note_editor
	};
	let note_toggle = visibility_button(*is_note_visible, Message::ToggleNoteVisibility);
	let generator_row = generator_controls(generator);
	let note_row = row![styled_tooltip(note_editor, "Note", 1), note_toggle].height(Fill);

	let main_content = container(
		column![
			name_input,
			row![
				styled_tooltip(username_input, "Username", 1),
				username_copy_button
			],
			row![
				styled_tooltip(password_input, "Password", 3),
				password_copy_button,
				password_visibility_toggle,
				icon_button(DIE, Message::GeneratePassword)
			],
			generator_row,
			row![
				styled_tooltip(pin_input, "PIN", 2),
				pin_copy_button,
				pin_visibility_toggle
			],
			url_input,
			tags_input,
			note_row,
		]
		.spacing(4)
		.height(Fill),
	)
	.padding(4)
	.width(Fill)
	.height(Fill);
	let button_bar = row![
		space::horizontal(),
		styled_button("Get", Message::PasswordEntryGet, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Set", Message::PasswordEntrySet, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Save", Message::Save, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Delete", Message::PasswordEntryDelete, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Health", Message::ShowHealth, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Keys", Message::ShowKeys, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Lock", Message::Lock, DEFAULT_BUTTON_SIZE),
		space::horizontal(),
	]
	.padding(16)
	.align_y(Center);
	let status_bar = container(center(
		row![
			text("> ").color(colors::NAUTILUS_CYAN),
			text(status).color(colors::TEXT_STATUS),
			space::horizontal(),
			text(timestamps(password_entry)).color(colors::TEXT_STATUS),
			text(" <").color(colors::NAUTILUS_CYAN)
		]
		.spacing(1),
	))
	.height(30)
	.padding(1)
	.width(Fill);

	column![title_bar(), header, main_content, button_bar, status_bar].into()
}

/// The keys screen in place of the editor: the enrolled security keys,
/// the actions on them, and the way back.
pub fn keys_screen<'a>(keys: &'a KeysScreen, status: &'a str) -> Element<'a, Message> {
	let mut body = column![].spacing(8);
	if keys.slots.is_empty() {
		body = body.push(
			text("This vault is protected by its master password and this machine's pepper alone.")
				.size(16)
				.color(colors::TEXT_STATUS),
		);
		body = body.push(
			text("Protecting it with a security key rekeys the vault: every device then needs the password, the pepper and an enrolled key. If every enrolled key is lost while the vault is locked, the vault cannot be opened.")
				.size(14)
				.color(colors::TEXT_STATUS),
		);
	} else {
		body = body.push(
			text(
				"Security keys enrolled for this vault. Android opens a protected vault only after ADR 0013.",
			)
			.size(14)
			.color(colors::TEXT_STATUS),
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
		let line = format!("Key {}: {mode}, credential {id}…", index + 1);
		let remove = if keys.confirm_remove == Some(index) {
			row![
				styled_button("Remove, rekeying", Message::ConfirmRemoveKey, (200, 32)),
				styled_button("Keep", Message::CancelRemoveKey, (100, 32)),
			]
			.spacing(8)
		} else {
			row![styled_button(
				"Remove",
				Message::RemoveKey(index),
				(120, 32)
			)]
		};
		body = body.push(
			row![
				text(line).size(16).color(colors::TEXT_STATUS),
				space::horizontal(),
				remove
			]
			.align_y(Center)
			.spacing(12),
		);
	}
	let needs_password = keys.slots.is_empty() || keys.confirm_remove.is_some();
	if needs_password {
		body = body.push(
			styled_text_input("master password, to rekey...", &keys.password)
				.secure(true)
				.on_input(|value| Message::KeysPasswordInput(Zeroizing::new(value))),
		);
	}
	body = body.push(
		styled_text_input("security key PIN (if the key has one)...", &keys.pin)
			.secure(true)
			.on_input(|value| Message::KeysPinInput(Zeroizing::new(value))),
	);
	body = body.push(
		checkbox(keys.touch_only)
			.label("Enroll touch-only (no PIN asked at unlock)")
			.text_size(14)
			.on_toggle(|_| Message::KeysToggleTouchOnly),
	);
	let action = if keys.slots.is_empty() {
		styled_button(
			"Protect with a security key",
			Message::ProtectVault,
			(300, 40),
		)
	} else {
		styled_button("Add a key", Message::AddKey, (160, 40))
	};
	let button_bar = row![
		space::horizontal(),
		action,
		space::horizontal().width(20),
		styled_button("Back", Message::HideKeys, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Lock", Message::Lock, DEFAULT_BUTTON_SIZE),
		space::horizontal(),
	]
	.padding(16)
	.align_y(Center);
	let status_bar = container(center(
		row![
			text("> ").color(colors::NAUTILUS_CYAN),
			text(status).color(colors::TEXT_STATUS),
			text(" <").color(colors::NAUTILUS_CYAN)
		]
		.spacing(1),
	))
	.height(30)
	.padding(1)
	.width(Fill);
	let body = container(scrollable(body).height(Fill))
		.padding(12)
		.width(Fill)
		.height(Fill);
	column![title_bar(), body, button_bar, status_bar].into()
}

/// The health report in place of the editor: four lists, names and figures
/// only, and the way back.
pub fn health_screen<'a>(report: &'a health::Report, status: &'a str) -> Element<'a, Message> {
	let mut lines = column![].spacing(2);
	for line in health_lines(report) {
		lines = lines.push(text(line).size(16).color(colors::TEXT_STATUS));
	}
	let body = container(scrollable(lines).height(Fill))
		.padding(12)
		.width(Fill)
		.height(Fill);
	let button_bar = row![
		space::horizontal(),
		styled_button("Back", Message::HideHealth, DEFAULT_BUTTON_SIZE),
		space::horizontal().width(20),
		styled_button("Lock", Message::Lock, DEFAULT_BUTTON_SIZE),
		space::horizontal(),
	]
	.padding(16)
	.align_y(Center);
	let status_bar = container(center(
		row![
			text("> ").color(colors::NAUTILUS_CYAN),
			text(status).color(colors::TEXT_STATUS),
			text(" <").color(colors::NAUTILUS_CYAN)
		]
		.spacing(1),
	))
	.height(30)
	.padding(1)
	.width(Fill);
	column![title_bar(), body, button_bar, status_bar].into()
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

/// The die's settings: characters or words, how many, and which classes.
fn generator_controls(choice: &GeneratorChoice) -> Element<'_, Message> {
	let kind_button = styled_button(
		if choice.words { "Words" } else { "Characters" },
		Message::GeneratorKindToggled,
		(130, 32),
	);
	let count_input = styled_tooltip(
		styled_text_input("count", &choice.count)
			.on_input(Message::GeneratorCountInput)
			.width(64),
		if choice.words { "Words" } else { "Length" },
		0,
	);
	let bits =
		text(format!("{} bits", generator::whole_bits(&choice.kind()))).color(colors::TEXT_STATUS);
	let mut controls = row![kind_button, count_input].spacing(8).align_y(Center);
	if !choice.words {
		let c = choice.classes;
		for (label, on, bit) in [
			("A-Z", c.upper, 1u8),
			("a-z", c.lower, 2),
			("0-9", c.digits, 4),
			("#%&", c.symbols, 8),
		] {
			controls = controls.push(
				checkbox(on)
					.label(label)
					.text_size(14)
					.on_toggle(move |_| Message::GeneratorClassToggled(bit)),
			);
		}
	}
	controls.push(bits).into()
}

fn visibility_button(visible: bool, msg: Message) -> Element<'static, Message> {
	icon_button(if visible { EYE_OPEN } else { EYE_CROSSED }, msg)
}

fn icon_button(data: &'static [u8], msg: Message) -> Element<'static, Message> {
	let icon = svg(svg::Handle::from_memory(data))
		.width(24)
		.height(24)
		.style(|_, _| svg::Style {
			color: Some(colors::NAUTILUS_CYAN),
		});
	button(center(icon))
		.width(ICON_BUTTON_SIZE)
		.height(ICON_BUTTON_SIZE)
		.padding(0)
		.style(button_style)
		.on_press(msg)
		.into()
}

pub fn styled_button<'a, Message: Clone + 'a>(
	label: &str,
	msg: Message,
	size: (u32, u32),
) -> Element<'a, Message> {
	button(
		text(label.to_string())
			.size(18)
			.width(Fill)
			.align_x(Alignment::Center)
			.align_y(Alignment::Center)
			.font(Font {
				weight: font::Weight::Semibold,
				..Default::default()
			}),
	)
	.width(size.0)
	.height(size.1)
	.style(button_style)
	.on_press(msg)
	.into()
}

fn button_style(theme: &Theme, status: button::Status) -> button::Style {
	let base = button::primary(theme, status);
	match status {
		button::Status::Hovered => button::Style {
			background: Some(Background::Color(colors::BG_BUTTON_HOVER)),
			border: border::Border {
				color: colors::BORDER_ACCENT,
				width: 2.0,
				radius: 5.0.into(),
			},
			text_color: colors::TEXT_SECONDARY,
			..base
		},
		_ => button::Style {
			background: Some(Background::Color(colors::BG_BUTTON)),
			border: border::Border {
				color: colors::BORDER_PRIMARY,
				width: 1.0,
				radius: 5.0.into(),
			},
			text_color: colors::TEXT_SECONDARY,
			..base
		},
	}
}

pub fn styled_text_input<'a, Message: Clone + 'a>(
	default_str: &str,
	input_str: &str,
) -> TextInput<'a, Message> {
	text_input(default_str, input_str)
		.padding(10)
		.size(18)
		.style(|_theme: &Theme, status: text_input::Status| match status {
			text_input::Status::Focused { .. } => text_input::Style {
				background: Background::Color(colors::BG_INPUT_FOCUS),
				border: border::Border {
					color: colors::BORDER_ACCENT,
					width: 2.0,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER_HOVER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			text_input::Status::Hovered => text_input::Style {
				background: Background::Color(colors::BG_INPUT_HOVER),
				border: border::Border {
					color: colors::BORDER_HOVER,
					width: 1.5,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			_ => text_input::Style {
				background: Background::Color(colors::BG_INPUT),
				border: border::Border {
					color: colors::BORDER_PRIMARY,
					width: 1.0,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
		})
}

pub fn styled_query_input<'a, Message: Clone + 'a>(
	default_str: &str,
	input_str: &str,
) -> TextInput<'a, Message> {
	text_input(default_str, input_str)
		.padding(10)
		.size(18)
		.style(|_theme: &Theme, status: text_input::Status| match status {
			text_input::Status::Focused { .. } => text_input::Style {
				background: Background::Color(colors::BG_INPUT_FOCUS),
				border: border::Border {
					color: colors::BORDER_ACCENT_QUERY,
					width: 2.0,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER_HOVER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			text_input::Status::Hovered => text_input::Style {
				background: Background::Color(colors::BG_INPUT_HOVER),
				border: border::Border {
					color: colors::BORDER_HOVER_QUERY,
					width: 1.5,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			_ => text_input::Style {
				background: Background::Color(colors::BG_INPUT),
				border: border::Border {
					color: colors::BORDER_PRIMARY_QUERY,
					width: 1.0,
					radius: 5.0.into(),
				},
				icon: colors::TEXT_SECONDARY,
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
		})
}

pub fn styled_text_editor<'a>(
	id: String,
	content: &'a text_editor::Content,
) -> TextEditor<'a, PlainText, Message> {
	text_editor(content)
		.id(id)
		.size(18)
		.height(Fill)
		.wrapping(text::Wrapping::Word)
		.style(|_theme: &Theme, status: text_editor::Status| match status {
			text_editor::Status::Focused { .. } => text_editor::Style {
				background: Background::Color(colors::BG_INPUT_FOCUS),
				border: border::Border {
					color: colors::BORDER_ACCENT,
					width: 2.0,
					radius: 5.0.into(),
				},
				placeholder: colors::TEXT_PLACEHOLDER_HOVER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			text_editor::Status::Hovered => text_editor::Style {
				background: Background::Color(colors::BG_INPUT_HOVER),
				border: border::Border {
					color: colors::BORDER_HOVER,
					width: 1.5,
					radius: 5.0.into(),
				},
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
			_ => text_editor::Style {
				background: Background::Color(colors::BG_INPUT),
				border: border::Border {
					color: colors::BORDER_PRIMARY,
					width: 1.0,
					radius: 5.0.into(),
				},
				placeholder: colors::TEXT_PLACEHOLDER,
				value: colors::TEXT_SECONDARY,
				selection: colors::SELECTION,
			},
		})
}

/// "Modified: … | Created: …" in the local time zone, for the status bar.
fn timestamps(entry: &PasswordEntry) -> String {
	format!(
		"Modified: {} | Created: {} ",
		local_date(entry.modified()),
		local_date(entry.created())
	)
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
