# ADR 0008 — Choose what the generator produces

## Status

Accepted.

## Why

ADR 0007 gave both heads one generator: 24 characters from a fixed
alphabet of letters, digits and symbols. Security review finding K8 asked
for more, because a generated secret is only useful where it is accepted
and only remembered where it can be read aloud: a site that refuses symbols
needs a letters-and-digits password, a PIN field needs digits, a disk or
Wi-Fi passphrase that is typed by hand needs words. KeePassXC offers
length, character classes and EFF wordlist passphrases. Keptino offers one
shape and shows nothing about its strength.

## Decision

`common/core::generator` grows from one function to one description of what
to make and two functions over it. A `Kind` is either `Characters` with a
length and a set of `Classes` (uppercase, lowercase, digits, symbols; each
on or off) or `Passphrase` with a word count. `generate` draws every
character or word uniformly by rejection sampling from OS randomness, as
the 24-character default already does, and returns the result in a wiping
buffer. `bits` returns the entropy of a `Kind` as the draw actually
produces it: length times the base-2 log of the alphabet size, or words
times the base-2 log of 7776. Nothing requires one of each class, so the
figure is exact, not an upper bound. `whole_bits` rounds it down to the
integer both heads show, so they never differ by one. The symbol class is
the 20 symbols already in use. A `Kind` with no class on, a length of zero
or over 256, or a word count of zero or over 32 is refused with `None`.

The passphrase words are the EFF large wordlist, 7776 lowercase words of at
most nine letters, compiled into core as a static table with its license
note. A test pins the BLAKE3 hash of the joined table so the list cannot
change silently, and checks its count, order and uniqueness. Words are
joined by a hyphen, and the word draw rejects two-byte values at or above
the largest multiple of 7776 so every word is equally likely. The
existing `password(length)` and `LENGTH` stay as the default
`Characters` kind, so nothing else moves.

Both heads keep their generate control and add the choice beside it:
characters or words, the length or word count, and the four class switches for
characters. The choice lives in the editor for the session; it is not
stored in the vault. After generating, the status line names what was
made and its bits, for example `Generated 6 words, 77 bits`. Linux adds
these controls to the password row of the iced editor. Android adds them to
its editor and passes the `Kind` over JNI as a kind code, a count and a
class bitmask, so the native side builds the `Kind` and calls the same
`generate`. The generated text still lands only in the sealed working
entry; Set and Save remain explicit as in ADR 0007.

`STYLE.md` gains two terms, passphrase and character class, because both
heads will show them.

## Limits

No file byte changes and no entry field is added; the generator setting is
a session choice, not vault data. Passphrase separators other than a
hyphen, capitalization, appended digits, custom alphabets, excluded
look-alike characters, pronounceable passwords and a stored per-vault
preference are out; each would be a new decision. The wordlist is the EFF
large list as published in 2016 and is not edited; a different list is a
new decision. The PIN field keeps its own input; generating a digits-only
password into the password field is the way to make a PIN.

## Acceptance

Core tests: every `Kind` generates the requested length or word count from
exactly its alphabet or the table; an empty class set, a zero length and
counts over the bounds are refused; `bits` matches the closed form for the
default kind, a digits-only kind and a passphrase; the wordlist hash,
count, order and uniqueness hold; the word draw never indexes past the
table. The Linux editor test generates a passphrase and a digits-only
password through messages and reads the status line. Android generates
each kind through JNI into the working entry. `ci/check.sh` is clean and
`android/interop/run.sh` passes at the debug cost.
