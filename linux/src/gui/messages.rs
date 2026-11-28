use crate::storage::keys::KeysOutcome;
use crate::storage::persistence::OpenedVault;
use iced::widget::text_editor;
use zeroize::Zeroizing;

/// Which rows the list pane shows besides the find (ADR 0022).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ListFilter {
	#[default]
	All,
	Tag(String),
	Weak,
}

#[derive(Clone)]
pub enum Message {
	AttemptUnlock,
	AttemptCreate,
	AdoptRemote,
	CloseWindow,
	CopyUsername,
	CopyPassword,
	CopyPin,
	DbNameChanged(String),
	DbPasswordChanged(Zeroizing<String>),
	DbPasswordConfirmChanged(Zeroizing<String>),
	DbPinChanged(Zeroizing<String>),
	DragWindow,
	FocusNext,
	FocusPrevious,
	/// Draws a new preview in the open generator panel.
	GeneratePassword,
	ToggleGenerator,
	TogglePreviewVisibility,
	/// Puts the preview into the password field as an unset edit.
	UseGenerated,
	GeneratorClassToggled(u8),
	GeneratorCountInput(String),
	GeneratorCountStep(i8),
	GeneratorKindToggled,
	HideHealth,
	HideKeys,
	Lock,
	NavigateNext,
	NavigatePrevious,
	/// A row of the list pane was pressed.
	OpenEntry(String),
	/// A chip under find was pressed.
	FilterChosen(ListFilter),
	FocusFind,
	/// Opens or closes the results under find.
	ToggleList,
	/// Moves the results' cursor up (-1) or down (1).
	ListCursor(i8),
	/// Closes whichever popover is open.
	Escape,
	None,
	PasswordEntryDelete,
	PasswordEntryNew,
	PasswordEntryRevert,
	PasswordEntryNameInput(String),
	PasswordEntryNoteAction(text_editor::Action),
	PasswordEntryPasswordInput(Zeroizing<String>),
	PasswordEntryPinInput(Zeroizing<String>),
	PasswordEntrySet,
	PasswordEntryTagsInput(String),
	PasswordEntryUrlInput(String),
	PasswordEntryUsernameInput(String),
	QueryInput(String),
	QuerySubmit,
	Save,
	ShowHealth,
	SaveResult(String),
	ShowKeys,
	KeysPasswordInput(Zeroizing<String>),
	KeysConfirmInput(Zeroizing<String>),
	KeysPinInput(Zeroizing<String>),
	KeysToggleTouchOnly,
	ProtectVault,
	AddKey,
	RemoveKey(usize),
	ConfirmRemoveKey,
	CancelRemoveKey,
	KeysResult(Result<KeysOutcome, String>),
	Tick,
	ToggleCreate,
	TogglePasswordVisibility,
	TogglePinVisibility,
	ToggleNoteVisibility,
	UnlockResult(Result<OpenedVault, String>),
}
