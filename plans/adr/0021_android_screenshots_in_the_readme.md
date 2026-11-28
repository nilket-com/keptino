# ADR 0021 — Show the Android screens in the README

## Status

Accepted for implementation after ADR 0020.

## Why

The README shows the Linux editor. Someone considering the Android app should
also be able to see how they would find an entry and change its password.

## Decision

Show the Android unlock screen, vault list, entry editor and password generator
in the root README. Link each labeled thumbnail to its full-size screenshot.

## Limits

Capture the shipped screen layouts with a synthetic vault on an emulator.
Keep the production secure window and everyday vaults out of the capture path.

## Acceptance

Inspect all four screenshots for legibility, masked passwords and sample data.
Check that each thumbnail and its full-size link resolve in the repository.
