//! The Nautilus tokens (ADR 0019, doc/design.md), by role. Every color the
//! window paints comes from here.

use iced::Color;

// Grounds, from the window back to the raised surfaces.
pub const GROUND: Color = rgb(1, 1, 1);
pub const BAR: Color = rgb(4, 4, 4);
pub const FIELD: Color = rgb(4, 4, 8);
pub const FIELD_HOVER: Color = rgb(8, 8, 15);
pub const RAISED: Color = rgb(11, 13, 20);

// Lines and accents.
pub const COBALT: Color = rgb(30, 77, 148);
pub const COBALT_HOVER: Color = rgb(35, 119, 195);
pub const CYAN: Color = rgb(32, 180, 204);
pub const GREEN: Color = rgb(80, 180, 80);
pub const SKY: Color = rgb(116, 184, 244);
pub const AMBER: Color = rgb(216, 179, 106);
pub const ROSE: Color = rgb(240, 138, 138);
pub const ROSE_LINE: Color = rgb(90, 38, 38);

// Text.
pub const TEXT: Color = rgb(230, 230, 230);
pub const MUTED: Color = rgb(138, 143, 152);
pub const PLACEHOLDER: Color = rgb(122, 112, 124);
/// Text on a filled cyan button.
pub const ON_CYAN: Color = rgb(2, 22, 26);

// Quiet structure: bar edges, the status line's pipes, toggles at rest.
pub const BAR_EDGE: Color = rgb(26, 42, 26);
pub const DIVIDER: Color = rgb(46, 74, 102);
pub const TOGGLE_OFF: Color = rgb(42, 53, 80);
pub const TOGGLE_ON: Color = rgb(13, 42, 51);
pub const TOGGLE_ON_TEXT: Color = rgb(191, 239, 247);
pub const SEGMENT_ON: Color = rgb(18, 48, 79);
pub const METER_TRACK: Color = rgb(21, 26, 36);
pub const SELECTION: Color = rgb(18, 72, 110);

const fn rgb(r: u8, g: u8, b: u8) -> Color {
	Color::from_rgb8(r, g, b)
}
