# SLO Retro: Rust Hardening Follow-Ups

Fork-local SLO retro for [kerberosmansour/agent-governance-toolkit#7](https://github.com/kerberosmansour/agent-governance-toolkit/issues/7).

Related ticket: [ticket-5-rust-hardening-followups.md](../tickets/ticket-5-rust-hardening-followups.md)

Related verification: [rust-hardening-followups.md](../verification/rust-hardening-followups.md)

Related implementation PR: [#4](https://github.com/kerberosmansour/agent-governance-toolkit/pull/4)

## Completion Summary

The Rust follow-up branch addressed review warnings and follow-up hardening around prompt-injection edge cases, escape-sequence false positives, compact/atomic persistence, README examples, and formatter drift. The implementation PR is mergeable in the fork with DCO and dependency-review checks passing.

## What Went Well

- The upstream review comments were separated into blocking work, follow-up work, and bot noise.
- The implementation stayed within the Rust SDK surface.
- Prompt-injection tests now cover empty inputs, nested prompt-control tokens, escaped Unicode payloads, literal escape false positives, and large prompts.
- The DCO failure was diagnosed from the action log and fixed by adding a `Signed-off-by` trailer without losing SSH commit verification.
- The fork-local `upstream-main` base kept PR #4 reviewable despite the fork's divergent default `main` history.

## What Was Noisy

- GitHub bot comments made "docs signoff" look like a documentation issue, but the real failing check was DCO.
- The fork's default `main` branch diverged from Microsoft upstream because of an earlier squash-style merge, so a direct fork-main sync produced conflicts.
- `cargo fmt --all` fixed real drift but initially made one CRLF-sensitive file look noisier than the logical change.

## Rules For The Next Rust SLO Ticket

- Start with a fork-local ticket contract when the work is intended to follow SLO discipline.
- Put SLO artifacts in the fork only; keep upstream-facing PRs focused on product code, tests, and public docs unless maintainers request process evidence.
- Include `Signed-off-by` on commits from the start when DCO is enabled.
- Treat bot warnings as triage inputs; verify real check logs before changing code.
- Record branch base strategy explicitly when the fork's `main` diverges from upstream.

## Follow-Up Lanes

| lane | item | why |
|---|---|---|
| micro | Add a parent-directory fsync after atomic rename on Unix platforms. | Tightens crash consistency beyond temp-file `sync_all` plus rename. |
| micro | Add an explicit failure-path test for temp-file cleanup on write errors. | Makes the atomic write invariant more directly observable. |
| milestone | Build a shared prompt-defense conformance corpus across Rust, Go, .NET, and Python. | Prevents language SDK drift in prompt-injection behavior. |
| milestone | Add configurable prompt-injection corpora and thresholds to the Rust detector. | Makes tuning reviewable without changing code. |
| fresh-runbook | Reconcile the fork default branch with Microsoft upstream history. | The fork's `main` divergence creates confusing PR bases and merge conflicts. |

## Carry-Forward Issue Candidates

- `micro`: atomic persistence durability hardening.
- `milestone`: cross-language prompt-defense conformance suite.
- `fresh-runbook`: fork history reconciliation.

## Closeout

This retro closes the SLO process gap for the completed Rust follow-up branch. It is intentionally fork-local and should not be included in an upstream Microsoft PR unless maintainers ask for SLO process artifacts.
