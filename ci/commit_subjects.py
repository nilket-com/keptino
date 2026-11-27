#!/usr/bin/env python3
"""Check Keptino's signed decision and implementation history."""
import argparse
import json
import re
import subprocess
from pathlib import Path

# Parent of the first numbered decision. A moving remote ref cannot attest
# to the prefix of a replacement history or an already-published commit.
ANCHOR = "7c05561aa2162bef2b55f09f69416f8e391bfb88"
IDENTITY = ("Joel Bondurant", "em@joelbondurant.com")
ADR = re.compile(r"(plan|impl): adr ([0-9]{4}) ([a-z0-9][\x20-\x7e]*)")
LABELS = re.compile(r"\b(?:cut [a-z][0-9]*|e[0-9]+(?:[._-][0-9]+)*|(?:crypto|pd|f-own|f-ctr)[-_][0-9]+)\b", re.I)


class HistoryError(Exception):
    pass


def git(repo, *args):
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    if result.returncode:
        raise HistoryError(result.stderr.strip() or "git command failed: " + args[0])
    return result.stdout


def resolve(repo, ref):
    return git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip()


def subject_error(subject):
    if not ADR.fullmatch(subject):
        return "expected plan: adr NNNN summary or impl: adr NNNN summary"
    if "(" in subject or ")" in subject or LABELS.search(subject):
        return "parentheses and delivery or incident labels are forbidden"
    return None


def expected_subject(repo, parent, anchor=ANCHOR):
    if parent == anchor:
        return "plan", "0001"
    subject = git(repo, "show", "-s", "--format=%s", parent).rstrip("\n")
    match = ADR.fullmatch(subject)
    if not match:
        raise HistoryError("parent has no numbered plan or implementation")
    kind, number, _ = match.groups()
    if kind == "plan":
        return "impl", number
    return "plan", f"{int(number) + 1:04d}"


def check_changes(repo, commit, kind, number):
    fields = git(repo, "diff-tree", "--no-commit-id", "--name-status",
                 "--no-renames", "-r", "-z", commit).split("\0")[:-1]
    changes = list(zip(fields[::2], fields[1::2]))
    if kind == "plan":
        if len(changes) != 1 or changes[0][0] != "A":
            return "plan must add exactly one decision file"
        path = changes[0][1]
        if not re.fullmatch(r"plans/adr/" + number + r"[_-][^/\n]+\.md", path):
            return "expected a decision in plans/adr for " + number
        if not git(repo, "ls-tree", "-z", commit, "--", path).startswith("100644 blob "):
            return "decision must be a regular Markdown file"
        lines = git(repo, "show", commit + ":" + path).splitlines()
        if not lines or not any(line.strip() for line in lines) or len(lines) > 400:
            return "decision must contain text and fit within 400 lines"
    else:
        if not changes:
            return "implementation must change the tree"
        if any(path == "plans/adr" or path.startswith("plans/adr/") for _, path in changes):
            return "numbered decision files change only in their own plan commit"
        if all(path.endswith("_evidence.md") for _, path in changes):
            return "a standalone evidence summary cannot implement a decision"
    return None


def evaluate(repo, candidate, anchor=ANCHOR):
    head = resolve(repo, candidate)
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != "false":
        raise HistoryError("complete history required")
    if git(repo, "merge-base", anchor, head).strip() != anchor:
        raise HistoryError("candidate does not descend from the pre-ADR history")
    commits = git(repo, "rev-list", "--reverse", "--first-parent", anchor + ".." + head).splitlines()
    errors = []
    parent = anchor
    for index, commit in enumerate(commits):
        kind = "plan" if index % 2 == 0 else "impl"
        number = f"{index // 2 + 1:04d}"
        # %G? is Git's verification result, including the local trust settings.
        info = git(repo, "show", "-s", "--format=%P%x00%an%x00%ae%x00%cn%x00%ce%x00%G?%x00%B", commit)
        parents, author, email, committer, committer_email, signature, message = info.split("\0", 6)
        subject, _, body = message.partition("\n")
        problems = []
        if parents != parent:
            problems.append("expected a single parent in the decision chain")
        if (author, email) != IDENTITY or (committer, committer_email) != IDENTITY:
            problems.append("unexpected author or committer identity")
        if signature != "G":
            problems.append("expected a valid trusted signature")
        if body.strip():
            problems.append("commit messages must have no body")
        error = subject_error(subject)
        if error:
            problems.append(error)
        if not subject.startswith(f"{kind}: adr {number} "):
            problems.append(f"expected {kind}: adr {number}")
        if parents == parent:
            change_error = check_changes(repo, commit, kind, number)
            if change_error:
                problems.append(change_error)
        errors.extend(f"{commit[:12]}: {problem}" for problem in problems)
        parent = commit
    if not commits or len(commits) % 2:
        errors.append("publish complete plan and implementation pairs together")
    return {"base": anchor, "candidate": head, "pairs": len(commits) // 2,
            "verdict": "FAIL" if errors else "PASS", "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        report = evaluate(args.repo, args.commit)
    except (HistoryError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        report = {"verdict": "HOLD", "error": str(error)}
    print(json.dumps(report, indent=2))
    return {"PASS": 0, "FAIL": 1, "HOLD": 2}[report["verdict"]]


if __name__ == "__main__":
    main_status = main()
    raise SystemExit(main_status)
