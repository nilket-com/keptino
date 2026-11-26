# Commit history preflight

Adopted from ket. Two git hooks and one read-only checker keep the history
uniform: every subject follows one grammar, messages have no body, author
and committer are Joel's identity, and architecture decisions are numbered.
The checker inspects `refs/remotes/origin/main..candidate` without changing
refs or fetching.

Activate the hooks once per clone:

    git config core.hooksPath .githooks

`commit-msg` refuses a bad subject or any body at commit time, before
signing. `pre-push` runs the full history check on every commit about to be
pushed. Run either check by hand with:

    python3 -B ci/commit_subjects.py --repo . --commit HEAD
    python3 -B ci/test_commit_subjects.py

## Subjects

    fix: terse summary
    test: terse summary
    docs: terse summary
    plan: adr NNNN terse summary
    impl: adr NNNN terse summary
    docs: adr NNNN terse summary

The summary starts with a lowercase letter or digit and continues in
printable ASCII. No scopes, no parentheses, no capital first character, no
delivery or incident labels, no separate evidence subjects. Product nouns and
acronyms are fine. Messages have no body: no paragraphs, no trailers, no
attribution lines. The subject carries the whole message; the diff and the
review documents carry the reasoning.

## Decisions

A numbered decision lives in `plans/adr/NNNN_name.md`. A `plan` commit adds
or amends exactly that one file and nothing else, takes the next number in
the directory (0001 in a new directory), and stays under 400 lines. An
`impl` or numbered `docs` commit needs an earlier `plan` of the same number
in first-parent ancestry. A decision allows five implementations unless
`ci/commit-subject-allowlist.json` records a reviewed higher limit; the same
file can grandfather an unchanged oversized document by exact path and blob.
Absent policy grants no exceptions; malformed policy makes the check HOLD.

History before the adoption of this preflight is not re-checked: the hooks
and checker look only at commits not yet on `origin/main`.

The lint cannot tell whether a conforming `fix:` hides a design change.
Code review enforces that distinction; passing syntax does not replace it.
