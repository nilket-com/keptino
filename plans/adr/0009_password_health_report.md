# ADR 0009 — Report the health of the passwords in a vault

## Status

Accepted.

## Why

The security review lists a password health and reuse report as the one
KeePassXC feature still missing after the generator: a user who has typed
the same password into several entries, kept a short one, or not changed one
in years has no way to find out from inside Keptino. KeePassXC also offers a
Have I Been Pwned check; the review excludes it, because it adds a third
party to an application that talks only to the user's own bucket. The
report must therefore work offline from what the vault already holds, and it
must not gather plaintext passwords in one place to do it.

## Decision

Add `common/core::health`. `report` walks the names of a database one entry
at a time and returns a `Report` of four lists, each naming entries only:

- reused: groups of two or more entries whose passwords are equal. Equality
  is decided on keyed BLAKE3 hashes under a random key drawn for that one
  report and discarded with it. Each password is opened, hashed and wiped
  before the next is read, so no two plaintexts are in memory together and
  the hashes are useless outside the report.
- weak: entries whose password is estimated below 50 bits. The estimate is
  the length times the base-2 log of the alphabet size, where the alphabet
  is the sum of the classes present: 26 for lowercase, 26 for uppercase, 10
  for digits, 33 for anything else. It is the figure a random draw would
  have, so a word or a date scores higher than it deserves; the report says
  "estimated" and the number is a ceiling.
- stale: entries last edited more than 365 days before the report. The
  field is the modified timestamp, which any edit advances, so the heads
  call it "last edited", not "password changed". An entry without that
  timestamp is never stale; the report invents no date.
- empty: entries with no password. An empty password appears here only,
  never as weak or reused.

The `Report` also carries the entry count. It holds names and numbers and
nothing from a secret field, so a head may keep it on screen. Every list has
one order: weakest first, oldest first, otherwise by name, so the heads and
the tests render the same report the same way. The two thresholds are
constants in core; a different one is a new decision.

Both heads add one control that builds the report from the open vault and
shows the four lists in that order, each entry on its own line with its
figure where there is one, and a way back to the editor. Linux adds a
Health button to the button bar and a report screen in place of the editor.
Android adds a report screen reached from its vault view; the native side
builds the `Report` and hands the lines over JNI as text with no secret in
them. A lock discards the report with the rest of the session.

`STYLE.md` gains the term health report.

## Limits

No file byte changes and no entry field is added; the report is computed on
request and stored nowhere. No network check of any kind, now or later,
without its own decision. No dictionary, no pattern detection and no score
beyond the estimate; a word list check or a zxcvbn-style estimator is a new
decision. The report does not edit entries; the user fixes each one in the
editor, where the generator from ADR 0008 is one press away.

## Acceptance

Core tests: two entries with the same password and a third with another
yield one reused group of two; a 6-digit password is weak and a 24-character
generated one is not; an entry edited 400 days ago is stale and one edited
yesterday is not; an entry without a password is empty; a report over an
empty database has four empty lists; the report contains no password text,
checked by searching its rendering for every password in the fixture; two
entries without a password are empty and not reused; an entry without a
modified timestamp is not stale; the lists come out in their one order. The
Linux state test opens the report through messages and reads its lines, then
returns to the editor. Android builds the report through JNI on a synthetic
vault. `ci/check.sh` is clean and `android/interop/run.sh` passes at the
debug cost.
