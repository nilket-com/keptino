# Decision and implementation cadence

From ADR 0001 onward, publish complete, consecutive pairs on main.

    plan: adr 0001 share one cargo workspace
    impl: adr 0001 build both heads in the workspace
    plan: adr 0002 share the vault format
    impl: adr 0002 use the shared format on both heads

Each plan adds one regular Markdown file under `plans/adr/NNNN_name.md`
and contains at most 400 lines. The next commit implements that number.
Include its code, tests and supporting documentation in one reviewed change.
A documentation or tooling change can have its own pair. Keep unnumbered
research proposals under `plans/proposals/` until scheduled.

Keep work in progress local. Assemble one signed implementation after both
owners have cleared their changes. To rework your most recent local commit
in an isolated worktree, `git reset --soft HEAD^` returns its changes to
the index. Review the staged diff and commit again. Coordinate any rewrite
of published history with the operator and team and use an explicit lease.

Use Joel Bondurant's configured author and committer identity. Sign both
commits. Subjects use printable ASCII with a lowercase letter or digit at
the start of the summary. Omit parentheses, incident labels and message
bodies. Point Git at the project's trusted signers for SSH verification.

Activate the hooks once per clone with `git config core.hooksPath .githooks`.
The commit hook checks the next subject. The push hook and `ci/check.sh`
validate the whole chain beginning at the parent of ADR 0001, including
when the outgoing history replaces the remote tip. Main must end at a
completed pair. Merges, gaps, rewrites of decision documents in subsequent
commits, and standalone housekeeping commits fail the check.

    python3 -B ci/commit_subjects.py --repo . --commit HEAD
    python3 -B ci/test_commit_subjects.py
