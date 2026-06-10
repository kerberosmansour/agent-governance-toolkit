---
title: Prompt-Injection Expected-Action Metrics Ticket
last_reviewed: 2026-06-10
owner: docs-team
---

# Prompt-Injection Expected-Action Metrics - SLO Ticket Contract v1

> Purpose: execute one bite-sized follow-up to PR #2924 with v4 SLO rigor.
> Source template: `ticket-contract-template_v_1.md`.

---

## 1. Ticket Metadata

| Field | Value |
|---|---|
| Ticket Contract ID | `ticket-pr2924-prompt-injection-expected-action-metrics` |
| Source tracker | GitHub PR review |
| Source issue | N/A - follow-up to review on [PR #2924](https://github.com/microsoft/agent-governance-toolkit/pull/2924) |
| Issue title | Wire `expected_action` into prompt-injection benchmark metrics |
| Labels | N/A |
| Assignee / owner | `mac-agent` |
| Target branch | `slo/prompt-injection-expected-action-metrics` |
| Primary stack | Rust, Python, Markdown |
| Default formatter command | `cargo fmt --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml -- --check` |
| Default typecheck / build command | `cargo check --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` |
| Default static analysis / lint command | `git diff --check` |
| Default unit / BDD command | `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` |
| Default runtime validation command | `TMPDIR="$(mktemp -d)" bash benchmarks/prompt-injection/run-smoke.sh` |
| Default dependency / security audit command | N/A - no dependency changes allowed |
| Default debugger or state-inspection tool | JSON artifact inspection with `python3 -m json.tool` or ad hoc Python assertions |
| Public interfaces stable by default | yes |
| Allowed new dependencies by default | none |
| Schema/config migration allowed by default | no |

### Public interfaces that must remain stable unless explicitly listed otherwise

- `benchmarks/prompt-injection/run-smoke.sh` remains the reproduction entry point.
- `benchmarks/prompt-injection/harness/agt-rules-baseline` CLI arguments remain backward compatible.
- Existing binary attack/benign fields in summary artifacts remain available.

---

## 2. Sizing Gate

| Check | Answer |
|---|---|
| User-visible outcome fits in one sentence | yes - the benchmark reports expected-action policy metrics instead of leaving `expected_action` as dead data. |
| Expected changed files <= 8 | yes |
| New public surfaces <= 1 | yes - additive JSON summary fields in benchmark artifacts. |
| No schema migration unless explicitly approved | yes |
| No cross-subsystem rewrite | yes |
| Can be reviewed as one PR | yes |
| Requires full v4 runbook instead | no - benchmark harness only. |

---

## 3. Issue Context

### Problem

The prompt-injection corpus labels each row with `expected_action` values such as `allow`, `require_approval`, `quarantine`, and `block`, but the current baseline harness only evaluates `attack_class != benign` against `rules_pred_attack`. This leaves action labels unused and prevents metrics such as `critical_allow` and `leak_allow` from being implemented honestly.

### Acceptance Criteria From Issue

- [ ] Add a deterministic benchmark-only `predicted_action` mapping without changing runtime detector behavior.
- [ ] Compare `predicted_action` with `expected_action` in per-row and summary artifacts.
- [ ] Emit `unsafe_action_success`, `critical_allow`, `leak_allow`, `action_exact_match`, and an action confusion matrix.
- [ ] Move action metrics from planned to implemented manifest/docs language only when generated artifacts contain them.
- [ ] Preserve the existing binary attack/benign baseline fields.

### Non-Goals

- Change AGT runtime prompt-injection detection or policy enforcement.
- Add embedding models, thresholds, or external services.
- Claim production detector performance.
- Wire `expected_action` into any runtime governance path.

### Reproduction / Current Signal

| Signal | Evidence |
|---|---|
| Baseline command | `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` |
| Current result | No action-aware tests or summary metrics exist. |
| Expected result | Harness exposes deterministic action metrics while preserving binary metrics. |

---

## 4. Compact Architecture Delta

| Component | Existing behavior | Change | Interface / trust boundary touched |
|---|---|---|---|
| Rust benchmark scorer | Converts detector output to binary `rules_pred_attack`. | Adds benchmark-only `rules_predicted_action` and action tally summary. | Benchmark artifact schema only. |
| Python metrics summarizer | Emits Wilson/base-rate metrics from binary tallies. | Copies action metrics from Rust summary into metrics artifact. | Benchmark artifact schema only. |
| Manifest/docs | Lists action metrics as planned. | Lists action metrics as implemented after regeneration. | Docs/benchmark metadata only. |

### Data Flow Delta

```text
corpus expected_action + risk/source labels
  -> Rust scorer detector result
  -> benchmark-only predicted_action
  -> action confusion + unsafe/critical/leak allow counters
  -> metrics artifact + README/docs summary
```

---

## 5. Contract Block

| Contract Row | Value |
|---|---|
| Inputs | PR #2924 corpus, Rust scorer output, generated JSON artifacts |
| Outputs | Harness tests, harness implementation, regenerated artifacts, docs, SLO ticket, follow-up PR |
| Interfaces touched | Additive benchmark JSON fields only |
| Files allowed to change | `benchmarks/prompt-injection/harness/agt-rules-baseline/src/main.rs`; `benchmarks/prompt-injection/harness/summarize-baseline.py`; `benchmarks/prompt-injection/harness/generate-corpus.py`; `benchmarks/prompt-injection/corpus/manifest-smoke.json`; `benchmarks/prompt-injection/artifacts/rules-baseline-smoke-summary.json`; `benchmarks/prompt-injection/artifacts/rules-baseline-smoke-metrics.json`; `benchmarks/prompt-injection/README.md`; `docs/benchmarks/prompt-injection-evaluation.md`; `docs/slo/tickets/ticket-pr2924-prompt-injection-expected-action-metrics.md` |
| Files to read before changing | `docs/AGENTS.md`; `docs/ARCHITECTURE.md`; `benchmarks/prompt-injection/harness/agt-rules-baseline/src/main.rs`; `benchmarks/prompt-injection/harness/summarize-baseline.py`; `benchmarks/prompt-injection/harness/generate-corpus.py`; `benchmarks/prompt-injection/README.md`; `docs/benchmarks/prompt-injection-evaluation.md` |
| New files allowed | `docs/slo/tickets/ticket-pr2924-prompt-injection-expected-action-metrics.md` only |
| New dependencies allowed | none |
| Migration allowed | no |
| Compatibility commitments | Existing CLI args, summary binary fields, and smoke reproduction command continue to work. |
| Data classification | Public - synthetic benchmark labels and metadata only; raw prompt text remains excluded from committed scorer evidence. |
| Proactive controls in play | OWASP LLM prompt-injection evaluation hygiene; metadata-only evidence; no runtime security defaults changed. |
| Abuse acceptance scenarios | Covered by BDD rows: critical/leak rows predicted `allow` are counted explicitly as unsafe action outcomes. |
| Resource bounds introduced/changed | O(number of rows x action labels); action labels are fixed to four values. |
| Invariants/assertions required | Unknown `expected_action` must fail fast; no raw text in per-row/summary/metrics artifacts; binary tallies remain unchanged. |
| Debugger / inspection expectation | JSON inspection is sufficient; debugger not required unless action metrics mismatch. |
| Static analysis gates | Rust fmt/check/test; Python compile through smoke script; `git diff --check`. |
| Reversibility / rollback path | Revert the follow-up commit; no persisted runtime state or schema migration. |
| Exemplar code to copy | Existing `Tally`/`map_json` patterns in the Rust scorer and `wilson` summarizer shape. |
| Anti-exemplar code not to copy | Do not copy runtime policy logic into the fixture or infer production enforcement semantics. |
| IAM secrets -> role -> trust-policy mapping | N/A - no IAM trust policy touched. |
| Refactoring discipline | Only small local extraction in the scorer is permitted; preserve existing binary tally structure. |
| AI tolerance contract | N/A - no AI component; deterministic fixture metrics only. |
| Forbidden shortcuts | No placeholder metrics, no hand-edited generated artifacts, no raw prompt text in evidence, no runtime detector changes. |

---

## 6. Implementation Plan

1. Run baseline test/build commands and record current absence of action metrics.
2. Add Rust unit tests for action prediction and action summary counters before implementation.
3. Implement fixed action labels, predicted-action mapping, action confusion, and unsafe counters in the Rust scorer.
4. Copy action metrics through the Python metrics summarizer.
5. Update generator manifest implemented/planned metric lists.
6. Regenerate smoke corpus and baseline artifacts through `run-smoke.sh`.
7. Update README/docs with action metric caveats.
8. Run validation commands and fill Actual Result rows.
9. Push the branch and open a stacked follow-up PR.

---

## 7. BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then | Evidence |
|---|---|---|---|---|---|
| Binary compatibility preserved | happy path | Existing smoke corpus and detector output | The scorer runs | Existing `overall`, `by_attack_class`, `by_bypass_class`, and `by_split` binary fields remain present. | `run-smoke.sh`; JSON inspection |
| Expected action is evaluated | happy path | Rows with `expected_action` labels | The scorer emits summary JSON | Summary includes action confusion and exact-match/unsafe counters. | Rust unit test and regenerated summary |
| Unknown action fails | invalid input | A row has an unsupported `expected_action` | The scorer parses the row | The process fails instead of silently counting bogus labels. | Rust unit test |
| Empty action buckets are stable | empty / degraded state | A split or subset has zero rows for one action | Metrics are rendered | Missing denominators render as zero/`null` without panic. | Rust unit test |
| Critical/leak allow is visible | abuse case | Critical or leakage-like rows are not detected | Predicted action is `allow` | `critical_allow`, `leak_allow`, and `unsafe_action_success` count those rows. | Rust unit test and metrics artifact |

---

## 8. Validation Plan

| Check | Command / Action | Expected Result | Actual Result | Status | Notes |
|---|---|---|---|---|---|
| Repo hygiene | `git status --short --branch && git rev-parse --abbrev-ref HEAD && git symbolic-ref --short refs/remotes/origin/HEAD` | On task branch; no unrelated changes in worktree | Branch `slo/prompt-injection-expected-action-metrics`; clean before contract write; default `origin/main` | pass | Stacked from PR #2924 branch because files are not on main yet. |
| Baseline before change | `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` | Green; no action-aware tests exist yet | pass: green with `running 0 tests` before test additions | pass |  |
| New tests fail first | `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` | Fails for missing action metrics before implementation | pass: failed with missing `predict_action`, `Action`, and `ActionTally` symbols | pass | Expected test-first failure. |
| Formatter | `cargo fmt --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml -- --check` | passes | pass after applying `cargo fmt` | pass | Initial check showed rustfmt layout diffs only. |
| Typecheck / build | `cargo check --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` | passes | pass | pass |  |
| Static analysis / lint | `git diff --check` | passes | pass | pass |  |
| Unit / BDD tests | `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml` | passes | pass: 5 tests passed | pass | Covers action mapping, unknown action rejection, empty denominators, and unsafe counters. |
| Runtime validation | `TMPDIR="$(mktemp -d)" bash benchmarks/prompt-injection/run-smoke.sh` | passes and regenerates artifacts | pass | pass | Also reasserted metadata-only evidence. |
| Corpus validation | `python3 benchmarks/prompt-injection/harness/check-corpus.py benchmarks/prompt-injection/corpus/injection-smoke.jsonl --manifest benchmarks/prompt-injection/corpus/manifest-smoke.json --summary-json /tmp/agt-check-corpus-summary-action-metrics.json` | passes | pass: `prompt-injection-corpus-check: PASS` | pass |  |
| Dependency / security audit | N/A | no dependencies changed | N/A - no dependency files changed | pass |  |
| Resource bound / invariant check | Rust unit tests + metadata-only assertion in `run-smoke.sh` | fixed action labels and no raw text leakage | pass: action labels fixed at four values; `raw_text_in_output=false` in summary/metrics | pass |  |
| Compatibility check | JSON inspection of summary and metrics artifacts | binary fields and new action metrics present | pass: `overall`, `by_bypass_class`, and `action_policy` present; action Wilson metrics present | pass | Counts: exact `160/280`, unsafe `103/110`, critical allow `60/64`, leak allow `36/36`. |
| `.gitignore` / artifact cleanup | `git status --short` | no stray artifacts | pass after removing local `target/`; only intended files changed | pass |  |

---

## 9. Workpad / Tracker Updates

N/A - this is a PR-review follow-up rather than a GitHub issue. AgentBus task `t_mq8g0sk0_120_0053f0d2` is the coordination workpad.

---

## 10. Self-Review Gate

- [x] Did I stay inside the file allow-list?
- [x] Did I write or update BDD tests before production code?
- [x] Did I confirm new tests failed for the right reason before implementing?
- [x] Did I preserve public interfaces unless explicitly allowed to change them?
- [x] Did I add or strengthen assertions/invariants where the contract required them?
- [x] Did I bound new resource growth or document why no bound applies?
- [x] Did I run formatter, typecheck/build, and static analysis?
- [x] Did I use a debugger or state-inspection tool when failure evidence was ambiguous?
- [x] Did I remove temporary proof edits, debug output, and placeholder logic?
- [x] Did I record evidence rather than claims?
- [x] Did I update the issue workpad and PR handoff notes?

---

## 11. Closure Summary

### Completed

- Added benchmark-only `rules_predicted_action` projection and action counters.
- Emitted action confusion, exact-match, unsafe-action, critical-allow, and leak-allow metrics in summary/metrics artifacts.
- Moved those action metrics from planned to implemented manifest metadata.
- Updated benchmark docs to explain that action projection is not runtime policy.

### Tests And Validation

- `cargo test --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml`: pass, 5 tests.
- `cargo fmt --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml -- --check`: pass.
- `cargo check --manifest-path benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml`: pass.
- `TMPDIR="$(mktemp -d)" bash benchmarks/prompt-injection/run-smoke.sh`: pass.
- `python3 benchmarks/prompt-injection/harness/check-corpus.py benchmarks/prompt-injection/corpus/injection-smoke.jsonl --manifest benchmarks/prompt-injection/corpus/manifest-smoke.json --summary-json /tmp/agt-check-corpus-summary-action-metrics.json`: pass.
- `git diff --check`: pass.
- `python3 scripts/docs/check_links.py`: pass, 0 new broken links.
- `python3 scripts/docs/check_frontmatter.py | rg 'docs/benchmarks/prompt-injection-evaluation.md|docs/slo/tickets/ticket-pr2924-prompt-injection-expected-action-metrics.md' || true`: pass, no warnings for touched docs after adding frontmatter.

### Lessons / Follow-Ups

- Follow-up PR is stacked on PR #2924 because the benchmark fixture files are not on `main` yet.
- The action projection intentionally exposes weak rules-only coverage rather than masking it; it is not a runtime policy recommendation.

### PR / Issue Links

- PR: Pending.
- Issue: N/A - PR review follow-up.
