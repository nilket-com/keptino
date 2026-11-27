# Writing and naming policy

Adopted from rnx. This applies to everything people read: docs, decision
records, reviews, code comments, diagnostics, status messages, commit
subjects and chat summaries. Code identifiers follow the API they belong to.

## 1. One English: American

Use American spelling in prose. If a word is not in this table, use
Merriam-Webster's first spelling.

| Use | Not |
|---|---|
| color | colour |
| behavior | behaviour |
| canceled, canceling | cancelled, cancelling |
| license (noun and verb) | licence |
| analyze, initialize, normalize, serialize | analyse, initialise, normalise, serialise |
| gray | grey |
| modeling, labeled | modelling, labelled |
| center | centre |
| authorize | authorise |

**Public identifiers follow their API.** Public names in code, file names,
CLI flags and data keys follow the API they belong to (Rust std, a crate,
Android). Do not rename a public identifier only to change its spelling.

**If you touch it, you refactor it.** When a change modifies a file, it
brings that whole file up to this policy: prose, comments, diagnostics and
private identifiers, not only the changed lines. Untouched files are left
alone: no spelling-only sweeps.

**Never rewritten:** committed vault fixtures, credential names and salts
bound into user data (`digipepper`, `backblaze`, `aws`, `gcs`, `r2`, the
Android Keystore aliases), git history.

## 2. One name per concept

Pick the established term and keep it; a new word reads as a new concept.

| Term | Meaning | Do not say |
|---|---|---|
| vault | one encrypted database and the file that holds it | database file, safe, store |
| entry | one named record with username, password, PIN, note, URL, tags | item, credential, account |
| envelope | the plaintext layer of a vault file: meta entries beside the ciphertext | header, wrapper |
| mirror check | the comparison of the envelope against the authenticated copy inside | AAD, format 2 (that was a marker, now legacy) |
| revision | the counter a save advances, carried in the envelope | version, generation |
| generation | a previous save kept beside the vault as `.keptino.N` | backup, snapshot |
| pepper | the TPM- or Keystore-held secret mixed into key derivation | key file, second factor |
| cost | the Argon2 memory, passes and lanes a vault was derived with | parameters, settings |
| candidate | the local or remote copy considered at unlock | version, side |
| head | a platform application: Linux, Android | client, frontend, app |
| core | the shared library the heads consume | engine, backend |
| accepted advisory | a `cargo audit` finding kept with a reason in `.cargo/audit.toml` | ignored, suppressed |
| record | one numbered decision: its plan and its implementations | ticket, task, PR |
| security key | a FIDO2 hardware authenticator enrolled with `hmac-secret` | token, dongle, YubiKey (except when naming a specific device) |
| key slot | one enrolled security key's wrapped copy of a vault's roaming secret | credential blob, wrapper |

Add a term here before introducing it.

## 3. Plain technical prose

- Say what happened, with the number: "25 tests pass", not "all tests pass".
- No filler or sales words: robust, seamless, leverage, comprehensive,
  cutting-edge, crucial, powerful, elegant, "it is worth noting", "in order
  to".
- No hedging stacks. State confidence once, with its basis.
- Verbs over nominalizations: "we measured", not "a measurement was
  performed".
- Short sentences. One idea per sentence.
- Estimates are labeled as estimates, with their inputs.

## 4. Commit subjects and decisions

Follow `ci/commit-subjects.md`. Publish one numbered plan immediately
followed by its single implementation. Put tests and supporting documentation
in the implementation. Write an imperative summary in American English,
beginning with a lowercase letter or digit. Omit trailing periods and bodies.
