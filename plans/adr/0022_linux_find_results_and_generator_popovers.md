# ADR 0022 — Find results and the generator float over the Linux editor

## Status

Accepted.

## Why

ADR 0020 gave Android a vault list with find, tag chips and weak flags,
and a generator that opens from the password field. The Linux window
from ADR 0019 can only reach entries by typing into find and stepping
with the arrows; it has no way to see every entry. Its generator strip
also takes a row of the editor all the time. A list pane beside the
editor was tried and dropped. It squeezed the editor, and the operator
prefers the one wide editor under one full-width find.

## Decision

The window stays at 1000 by 800 with find across the top and the entry
under it, as in ADR 0019. The results and the generator are popovers.
They float over the editor and move nothing under them, so the note
keeps its height.

The results open under find while the user types, with a toggle beside
find, or with Ctrl+F. They hold:

- Chips: All with the count, one chip per tag, and an amber chip for weak
  passwords when there are any.
- Rows in name order, scrolling when they outgrow the panel. Each row
  shows an initial tile, the name and the username, and an amber `set`
  or `weak` when either applies.

Find matches part of a name, ignoring case, or an exact tag, as
`Database::find` does. The up and down arrows move a cursor through the
rows. Enter opens the cursor's row, or else the exact name, or else the
first row. Pressing a row opens it. Escape, or a press outside the
panel, closes it. With the results closed, find shows where the open
entry stands among the rows shown. The previous and next buttons, and
Ctrl+Left and Ctrl+Right, step through those rows and wrap. When no row
is shown, they leave the editor and its draft as they are.

The die on the password field opens the generator under that field. It
holds:

- A masked preview with reveal and redraw.
- A strength bar with the whole bits.
- Characters or Words, a length stepper, and the class pills.
- Close, and "Use this password".

"Use this password" puts the preview into the password field as an unset
edit. The generator's rules stay the core's (ADR 0008). Closing the
panel or leaving the entry drops the preview. Only one popover is open
at a time.

The button row keeps New and Delete on the left. On the right it has the
amber marker ("Entry edited, not set", or how many entries are set but
not saved), Revert, Set entry and Save. All the buttons in the row look
alike, outlined in cobalt; the amber note carries the state. Revert puts
back the entry as it was opened, or empties a new one. Set and Save stay
separate. Opening another entry drops unset edits, and the status line
says so. Buttons keep one width whatever their label says.

The rows read the core's list projection (ADR 0020), so drawing them
opens no sealed record. Linux opts in to that index the way Android
does.

## Limits

No change to the vault format, storage or ceremonies. While the vault is
unlocked, the usernames and tags are held in ordinary process memory, in
zeroizing buffers, as entry names and the tag index already are. No
password, PIN or note leaves sealed memory for the list. Health and Keys
remain full-window screens.

## Acceptance

Unit tests drive the results and the generator through their messages:

- Typing opens the results with the cursor on the first row.
- The arrows move the cursor and wrap.
- Enter opens the cursor's row and closes the results.
- A chip and find narrow the rows together.
- A row press opens that entry and drops a draft with the notice.
- With no row shown, the previous and next keys leave a draft alone.
- Revert restores the opened entry.
- "Use this password" fills the field as a draft.
- Only one popover is open at a time.
- The `set` flag clears on a successful save and stays after a failed one.

A screenshot of the unlocked window replaces `doc/img/sample_entry.png`.
