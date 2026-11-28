# ADR 0019 — The Nautilus design on Linux

## Status

Accepted.

## Why

The Linux window works but has grown by accretion: seven equal buttons in
one row mix entry actions with vault actions, the generator controls sit
loose between two fields, and the status line wraps its text in `>` and
`<`. Android is about to adopt one visual language with Linux (ADR 0020),
so the Linux head should state that language first, in code, from the
design canvas the operator approved.

## Decision

The palette, type and shapes are the Nautilus tokens: near-black grounds,
cobalt borders, cyan for actions and focus, green for the brand and find,
sky for status text, amber for unsaved or weak, rose for deletion and
failure. `colors.rs` holds them under those roles and nothing else picks
a color. Secrets, numbers and the status line use a monospace face.

Vault actions leave the button row: Health, Keys and Lock become labeled
icon buttons in the title bar beside the vault name. The row keeps the
entry actions: New and Delete on the left, Set entry and Save on the
right, Save the one filled button. Set and Save stay separate: an edit
counts only once it is set, so an accidental keystroke on one entry is
never saved with a deliberate edit on another. The row says when the
current entry has edits that are not set.

Get is removed. Enter in the find field opens the first match, the field
shows the match position and count, and previous and next buttons beside
it step through matches, as Ctrl+Left and Ctrl+Right do now.

The generator becomes a strip attached under the password field: a
Characters or Words switch, a length stepper, the class toggles as pills,
a strength bar with the whole bits, and a Generate button. Its rules are
the core's (ADR 0008); only the controls change.

The status line separates its parts with `|` and drops the `>` and `<`
markers.

## Limits

No behavior of the vault, storage or ceremonies changes. Keyboard paths
stay: Tab order follows the visual order, Ctrl+L locks.

## Acceptance

The unit tests drive each moved action through its message as before;
Get's message is gone and Enter in find selects the first match. The
generator strip produces the same output as before for each setting. A
screenshot of the unlocked window replaces `doc/img/sample_entry.png`.
