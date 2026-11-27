# ADR 0004 — Publish one implementation per decision

## Status

Accepted.

## Why

A five-commit allowance let implementation of one decision continue after
the next numbered decision had been published. The operator wants to see a
linear, auditable pair for each delivered change.

## Decision

Starting at ADR 0001, main consists of consecutive pairs. Each plan adds
one numbered decision. Its immediate child implements that decision. The
next plan takes the next integer. Changes to code, tests and documentation
belong to the implementation. Drafts and work in progress stay local.
Review the combined implementation and publish complete pairs together.

## Limits

Retain the history preceding ADR 0001. A signed, nonempty implementation
may deliver tooling or documentation. A follow-up gets a new decision.
Keep the existing subject, identity and 400-line decision limits.

## Acceptance

The commit hook checks the next subject. The push hook and local CI check
the candidate from a fixed pre-ADR parent, including already published
pairs. Reject a skipped number, mismatched or repeated implementation,
interleaving commit, merge, orphan plan, empty implementation, or change to
a numbered decision inside an implementation. Verify each commit signature.
