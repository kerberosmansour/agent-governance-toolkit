# SLO Ticket 5: Rust Hardening Follow-Up Contract

Fork-local SLO artifact for [kerberosmansour/agent-governance-toolkit#5](https://github.com/kerberosmansour/agent-governance-toolkit/issues/5).

Related implementation PR: [#4](https://github.com/kerberosmansour/agent-governance-toolkit/pull/4)

## Status

| Field | Value |
|---|---|
| State | done |
| Implementation branch | `slo/rust-hardening-followups` |
| Evidence branch | `slo/rust-hardening-slo-artifacts` |
| Implementation commit | `13accc2e` |
| Scope | Rust SDK follow-up hardening and documentation |

## Goal

Capture the already-implemented Rust follow-up work in a durable SLO ticket contract so the fork has explicit scope, file allow-list, acceptance scenarios, and validation evidence.

## Out Of Scope

- Do not change Rust implementation behavior in this SLO artifact PR.
- Do not modify upstream Microsoft repository settings.
- Do not add fork-private SLO process docs to an upstream-facing PR unless maintainers explicitly request them.
- Do not reconcile the fork's divergent `main` history in this ticket.

## Files Allowed To Change

Implementation PR #4 changed:

- `agent-governance-rust/README.md`
- `agent-governance-rust/agentmesh/README.md`
- `agent-governance-rust/agentmesh/src/governance_support.rs`
- `agent-governance-rust/agentmesh/src/prompt_injection.rs`
- `agent-governance-rust/agentmesh/src/sandbox.rs`
- `agent-governance-rust/agentmesh/src/trust.rs`
- `agent-governance-rust/agentmesh/tests/prompt_injection.rs`

This SLO artifact PR may only add fork-local files under:

- `docs/slo/tickets/`
- `docs/slo/verification/`
- `docs/slo/lessons/`

## Files Read Before Changing

- `AGENTS.md`
- `docs/AGENTS.md`
- `agent-governance-rust/AGENTS.md`
- `agent-governance-rust/README.md`
- `agent-governance-rust/agentmesh/README.md`
- `agent-governance-rust/agentmesh/src/governance_support.rs`
- `agent-governance-rust/agentmesh/src/prompt_injection.rs`
- `agent-governance-rust/agentmesh/tests/prompt_injection.rs`

## Compatibility Requirements

| Requirement | Status | Notes |
|---|---|---|
| Preserve public prompt-injection result shape | satisfied | Existing compatibility tests still pass. |
| Preserve hash-only prompt audit behavior | satisfied | New and existing tests assert raw prompt content is absent. |
| Avoid new runtime dependencies | satisfied | Implementation uses standard library helpers. |
| Keep Rust workspace validation green | satisfied | See verification artifact. |
| Keep fork-local SLO artifacts out of upstream-facing docs unless requested | satisfied | These files live only in the fork branch stack. |

## Acceptance Scenarios

| id | scenario | expected result | evidence |
|---|---|---|---|
| S1 | Empty and whitespace prompts are scanned | Clean result, bounded audit metadata retained | `empty_and_whitespace_prompts_are_clean_and_audited` |
| S2 | Nested prompt-control tokens combine direct, delimiter, and role-play signals | Detector emits stable rule IDs for each signal family | `nested_prompt_control_tokens_emit_multiple_rule_ids` |
| S3 | Escaped Unicode text decodes to an instruction override | Detector flags `encoding:escaped_instruction` | `escaped_unicode_instruction_detected` |
| S4 | Literal `\x` / `\u` snippets in benign code or JSON are reviewed | Detector does not flag solely because escape markers exist | `literal_escape_sequences_in_code_are_not_flagged` |
| S5 | Large prompt contains late injection text | Detector catches late injection and audit remains hash-only | `large_prompt_detects_late_injection_without_raw_evidence` |
| S6 | File-backed audit and federation stores persist data | Writes use compact JSON via the atomic write path | `file_audit_sink_writes_compact_json`, `file_federation_store_writes_compact_json` |
| S7 | README readers need custom prompt guard examples | Workspace and crate READMEs show config and audit interpretation examples | Manual docs review |
| S8 | Full formatter gate previously failed on drift | `cargo fmt --all -- --check` passes | Validation command |

## Validation Plan

| command | expected | actual |
|---|---|---|
| `cargo test --release -p agentmesh --test prompt_injection` | pass | pass |
| `cargo fmt --all -- --check` | pass | pass |
| `git diff --check` | pass | pass |
| `cargo clippy --release --workspace --all-targets -- -D warnings` | pass | pass |
| `cargo test --release --workspace` | pass | pass |
| `cargo package --allow-dirty -p agentmesh` | pass | pass |

## Self-Review Gate

- [x] Changed files are limited to the Rust SDK implementation PR and fork-local SLO artifact paths.
- [x] Security-sensitive audit logging behavior is covered by tests and verification notes.
- [x] DCO and SSH commit verification are recorded in the evidence artifact.
- [x] Fork-only process evidence is separated from upstream-facing Rust changes.
- [x] Follow-up work is captured as lanes rather than mixed into the implementation PR.

## SLO Notes

This ticket was captured after implementation because the work began as a normal OSS follow-up PR. The fork-local SLO issue trail now records the missing contract and evidence so future follow-up work can start from an explicit ticket contract.

## Closure Summary

Completed behavior: PR #4 contains the Rust SDK follow-up implementation for prompt-injection edge cases, compact atomic persistence, README examples, and formatter drift.

Tests and validation: Prompt-injection integration tests, workspace formatting, clippy, workspace tests, package verification, DCO, and dependency review all passed. Detailed evidence is in `docs/slo/verification/rust-hardening-followups.md`.

Lessons and follow-ups: The retro records branch-base handling, DCO setup, bot-noise triage, and follow-up lanes for durability hardening, cross-language conformance, and fork history reconciliation.

PR and issue links: This SLO artifact branch closes issues #5, #6, and #7 and is stacked on PR #4.
