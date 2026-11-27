#!/usr/bin/env python3
"""Exercise the published cadence in real Git histories with a test signing key."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import commit_subjects as lint


class CadenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.keys.cleanup)
        cls.key = Path(cls.keys.name) / "fixture"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.key)], check=True)
        cls.signers = cls.key.parent / "allowed_signers"
        cls.signers.write_text(lint.IDENTITY[1] + " " + cls.key.with_suffix(".pub").read_text())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        for key, value in {
            "user.name": lint.IDENTITY[0], "user.email": lint.IDENTITY[1],
            "gpg.format": "ssh", "user.signingkey": str(self.key),
            "gpg.ssh.allowedSignersFile": str(self.signers),
            "commit.gpgsign": "true", "core.hooksPath": os.devnull,
        }.items():
            self.git("config", key, value)
        self.commit("legacy baseline")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return lint.git(self.repo, *args).strip()

    def write(self, path, content="decision\n"):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git("add", "--", path)

    def commit(self, message, *options):
        self.git("commit", "--allow-empty", "-qm", message, *options)

    def plan(self, number="0001"):
        self.write("plans/adr/" + number + "_fixture.md")
        self.commit("plan: adr " + number + " decide")

    def impl(self, number="0001"):
        self.write("feature", number)
        self.commit("impl: adr " + number + " implement")

    def errors(self):
        return "\n".join(lint.evaluate(self.repo, "HEAD", self.base)["errors"])

    def test_complete_pairs_and_incomplete_push(self):
        self.assertTrue(self.errors())
        self.plan()
        self.assertIn("publish complete", self.errors())
        self.impl()
        self.assertEqual(self.errors(), "")
        self.plan("0002")
        self.impl("0002")
        self.assertEqual(self.errors(), "")

    def test_parent_subject_for_commit_hook(self):
        self.assertEqual(lint.expected_subject(self.repo, self.base, self.base), ("plan", "0001"))
        self.plan()
        self.assertEqual(lint.expected_subject(self.repo, "HEAD", self.base), ("impl", "0001"))
        self.impl()
        self.assertEqual(lint.expected_subject(self.repo, "HEAD", self.base), ("plan", "0002"))

    def test_original_drift_fails_even_after_publication(self):
        self.plan()
        self.impl()
        self.plan("0002")
        self.commit("impl: adr 0001 resume the old decision")
        self.git("update-ref", "refs/remotes/origin/main", self.git("rev-parse", "HEAD"))
        self.assertIn("expected impl: adr 0002", self.errors())

    def test_second_implementation_or_interleaved_patch_fails(self):
        self.plan()
        self.impl()
        for subject in ("impl: adr 0001 another step", "fix: tidy the tree", "docs: note progress"):
            with self.subTest(subject=subject):
                self.commit(subject)
                self.assertIn("expected plan: adr 0002", self.errors())
                self.git("reset", "--hard", "HEAD^")

    def test_plan_must_be_next_and_implementation_must_be_nonempty(self):
        self.plan("0002")
        self.assertIn("expected plan: adr 0001", self.errors())
        self.git("reset", "--hard", self.base)
        self.plan()
        self.commit("impl: adr 0001 implement")
        self.assertIn("must change the tree", self.errors())

    def test_decisions_are_immutable_outside_their_plan(self):
        self.plan()
        self.write("plans/adr/0001_fixture.md", "amended\n")
        self.commit("impl: adr 0001 implement")
        self.assertIn("only in their own plan", self.errors())

    def test_plan_checks_contents_path_mode_and_size(self):
        for path, content in (("plans/adr/0002_bad.md", "text"),
                              ("plans/adr/0001_bad.md", "\n"),
                              ("plans/adr/0001_bad.md", "line\n" * 401)):
            with self.subTest(path=path, length=len(content)):
                self.write(path, content)
                self.commit("plan: adr 0001 decide")
                self.assertGreaterEqual(len(self.errors().splitlines()), 2)
                self.git("reset", "--hard", self.base)
        self.write("extra", "included")
        self.plan()
        self.assertIn("exactly one", self.errors())
        self.git("reset", "--hard", self.base)
        path = self.repo / "plans/adr/0001_link.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to("elsewhere")
        self.git("add", ".")
        self.commit("plan: adr 0001 decide")
        self.assertIn("regular Markdown", self.errors())

    def test_signature_identity_body_and_summary(self):
        self.plan()
        self.git("config", "user.name", "Different Author")
        self.write("code")
        self.commit("impl: adr 0001 implement\n\ntrailer", "--no-gpg-sign")
        errors = self.errors()
        for problem in ("signature", "identity", "no body"):
            self.assertIn(problem, errors)
        for subject in ("docs: adr 0001 note", "plan: adr 0001 Uppercase",
                        "impl: adr 0001 add (scope)", "impl: adr 0001 complete Cut C"):
            self.assertTrue(lint.subject_error(subject))

    def test_merge_cannot_hide_side_history(self):
        self.plan()
        self.git("checkout", "-qb", "side")
        self.write("extra")
        self.commit("fix: interleave a patch")
        self.git("checkout", "-q", "main")
        self.git("merge", "--no-ff", "-qm", "impl: adr 0001 implement", "side")
        self.assertIn("single parent", self.errors())

    def test_unrelated_candidate_has_no_anchor(self):
        self.git("checkout", "--orphan", "other")
        self.commit("another root")
        with self.assertRaises(lint.HistoryError):
            lint.evaluate(self.repo, "HEAD", self.base)


if __name__ == "__main__":
    unittest.main()
