# Keptino Design — Nautilus

Nautilus is the shared visual language for both Keptino heads: Linux
(ADR 0019) and Android (ADR 0020). Every screen draws its colors, type,
spacing and radii from this document.

## 1. Color tokens

| Role | Hex | Usage |
|---|---|---|
| Ground, primary | `#010101` | Main window and screen background |
| Ground, bar | `#040404` | Title bars, top bars, bottom bars |
| Ground, field | `#040408` | Text fields and password inputs |
| Ground, raised | `#0B0D14` | Cards, list surfaces, dialogs, bottom sheets |
| Border, cobalt | `#1E4D94` | Default field, card and button borders |
| Accent, cyan | `#20B4CC` | Actions, active focus borders, filled primary button when used |
| Brand / find, green | `#50B450` | Keptino brand mark, find input border, clean/saved state |
| Status, sky | `#74B8F4` | Status line text and neutral readouts |
| Caution, amber | `#D8B36A` | Unsaved/unset edits, weak passwords, cautions |
| Danger, rose | `#F08A8A` | Delete actions, errors, failures |
| Text, primary | `#E6E6E6` | Labels, entry names, field values |
| Text, muted | `#8A8F98` | Hints, secondary metadata, inactive controls |

## 2. Typography

- **Screen titles**: Inter 22 semibold.
- **Field values and buttons**: Inter 15.
- **Field labels**: Inter 12.
- **Monospace**: JetBrains Mono (or the platform monospace fallback) for
  secrets, numbers, entropy bits, timestamps and the status line.

## 3. Shape and spacing

- **Spacing rhythm**: 4 px (4 dp on Android) step — `8` inside groups,
  `16` between groups.
- **Corner radii**:
  - `8` — text fields and buttons
  - `14` — pills, chips and filter toggles
  - `16` — sheets and dialogs
- **Touch targets (Android)**: at least 44 dp (48 dp where layout permits).

## 4. Interaction rules

- **At most one filled cyan button per screen**: reserved for the committing
  action of ceremony and mobile screens (Unlock, Create, Keys, Android
  vault list `Save`, Android `Set entry`, Android generator `Use this
  password`). The Linux editor stays calm with no filled or colored action
  buttons: every button in its action row uses the uniform cobalt outline
  with primary light text, and the amber note carries the unsaved state.
- **Set and Save stay separate on both heads**: edits to a working entry
  apply to the open vault only when explicitly set (`Set entry`), and write
  to disk and sync only on `Save`. Accidental keystrokes on one entry are
  never silently saved alongside an intentional edit on another.
- **Status line**: separate segments with `|` (no `>` or `<` wrappers).
- **Sealed secrets**: list views and headers never read or render secret
  fields (password, PIN, note). Secrets appear only when explicitly
  revealed or copied on the entry editor.

## 5. Head layouts

### Linux (ADR 0019, ADR 0022)

- **Title bar**: vault name beside labeled icon buttons for vault-level
  actions (`Health`, `Keys`, `Lock`).
- **Find bar and results popover**: green-bordered find input across the
  top with match position and previous/next controls when closed. Typing,
  pressing the toggle, or `Ctrl+F` opens a floating results popover under
  find (no layout shift) with `All`, tag and `weak` chips plus scrollable
  rows showing initial tile, name, non-secret username, and `set`/`weak`
  flags from the core list projection.
- **Password generator popover**: die icon on the password field opens a
  floating generator popover under that field with masked preview, reveal
  and redraw, strength bar with whole bits, `Characters | Words`, length
  stepper, class pills, `Close`, and `Use this password`. Only one popover
  is open at a time.
- **Bottom row**: entry actions on the left (`New`, `Delete`), and on the
  right the amber edit/unsaved indicator, `Revert`, `Set entry`, and
  `Save`. All five buttons use the same cobalt outline with light text;
  the amber indicator carries the state.

### Android (ADR 0020)

- **Unlock**: vault name, master password, security-key hint when slots are
  present, filled cyan `Unlock`, `Create a new vault` text button, local-only
  switch, and a settings gear for setup/import/export.
- **Vault list**: top bar with vault name, monospace status line, lock icon,
  overflow menu (`Health`, `Keys`, `Export`, `Settings`), and filled cyan
  `Save` beside an amber `N set, not saved` indicator when changes are
  pending; green-bordered find field; tag filter chips including `N weak`;
  entry rows with initial tile, name, non-secret username, and unsaved/weak
  flag; outlined `+` button for new entries.
- **Entry**: grouped field cards with inline copy, reveal and generate
  icons; bottom bar with amber unset-edits note, `Revert`, and filled cyan
  `Set entry`. Leaving an entry with unset edits discards them rather than
  silently applying them.
- **Generator bottom sheet**: live preview (masked or revealed per user
  choice), strength bar with whole bits, `Characters | Words` segmented
  control, length slider, character-class pills, and filled cyan `Use this
  password`.
