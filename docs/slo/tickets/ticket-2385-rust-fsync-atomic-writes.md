# Rust Atomic Writes Parent Directory Fsync - SLO Ticket Contract v1

> **Purpose**: Harden Rust file-backed audit and federation stores by syncing the parent directory after successful atomic renames.
> **Audience**: AI coding agents first, humans second.
> **Source template**: Derived from `docs/slo/templates/runbook-template_v_4_template.md` via the v1 ticket-contract template.

---

## 1. Ticket Metadata

| Field | Value |
|---|---|
| Ticket Contract ID | `ticket-2385-rust-fsync-atomic-writes` |
| Source tracker | `GitHub Issues` |
| Source issue | [#2385](https://github.com/microsoft/agent-governance-toolkit/issues/2385) |
| Issue title | `Proposal: harden Rust atomic writes with parent-directory fsync` |
| Labels | `needs-review:MEDIUM` |
| Assignee / owner | `kerberosmansour` (issue author); maintainer ack from `imran-siddique` |
| Target branch | `slo/ticket-2385-rust-fsync-atomic-writes` |
| Primary stack | Rust workspace (`agent-governance-rust/`) |
| Default formatter command | `cargo fmt --all -- --check` |
| Default typecheck / build command | `cargo build --release --workspace --all-targets` |
| Default static analysis / lint command | `cargo clippy --release --workspace --all-targets -- -D warnings` |
| Default unit / BDD command | `cargo test --release -p agentmesh governance_support::tests::` |
| Default runtime validation command | `cargo test --release --workspace` |
| Default dependency / security audit command | `git diff -- agent-governance-rust/agentmesh/Cargo.toml agent-governance-rust/Cargo.lock` |
| Default debugger or state-inspection tool | `cargo test -- --nocapture` for ambiguous atomic-write failures |
| Public interfaces stable by default | `yes` |
| Allowed new dependencies by default | `none` |
| Schema/config migration allowed by default | `no` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- `agentmesh::governance_support::FileAuditSink::record` behavior and return type.
- `agentmesh::governance_support::FileFederationStore::save_policy` behavior and return type.
- On-disk JSON shape for audit entries and federation policies.
- Existing atomic-write guarantees: readers must not observe partial JSON, temp files are cleaned up on write or rename failure, and write errors are surfaced.

---

## 2. Sizing Gate

| Check | Answer |
|---|---|
| User-visible outcome fits in one sentence | `yes - file-backed Rust stores sync the parent directory after atomic rename where the platform supports it` |
| Expected changed files <= 8 | `yes - governance_support.rs, generated Cargo.lock metadata, and this ticket contract` |
| New public surfaces <= 1 | `yes - no public surface; private helper only` |
| No schema migration unless explicitly approved | `yes - no serialized schema change` |
| No cross-subsystem rewrite | `yes - localized to Rust governance file persistence` |
| Can be reviewed as one PR | `yes` |
| Requires full v4 runbook instead | `no - one durability improvement on an existing helper` |

---

## 3. Issue Context

### Problem

Issue #2385 asks whether the Rust SDK should add the durability step that follows a successful atomic rename by syncing the parent directory. Current `write_file_atomic` writes bytes to a temp file, calls `sync_all` on that temp file, and renames it into place. That prevents partial JSON reads, but on Unix-like filesystems the directory entry update is not fully durable across sudden power loss until the parent directory is synced.

### Acceptance Criteria From Issue

- [ ] Add a small helper that syncs the parent directory after a successful atomic rename where the platform supports it.
- [ ] Keep Windows behavior conservative and portable.
- [ ] Add tests that verify the helper is called through the atomic write path where feasible without relying on platform-specific crash simulation.
- [ ] Document the durability behavior briefly in code comments or Rust docs.

### Non-Goals

- No serialized schema changes for audit or federation stores.
- No new storage engine.
- No database-backed persistence.
- No new dependency.
- No public API change.

### Reproduction / Current Signal

| Signal | Evidence |
|---|---|
| Baseline command / UI path / failing test | `cargo test --release -p agentmesh governance_support::tests::` |
| Current result | 24 governance tests pass; no test or code path verifies parent-directory sync after rename |
| Expected result | New tests prove `write_file_atomic` invokes parent sync after rename and surfaces sync failure while preserving temp cleanup |

---

## 4. Compact Architecture Delta

| Component | Existing behavior | Change | Interface / trust boundary touched |
|---|---|---|---|
| `write_file_atomic` in `governance_support.rs` | temp file write, temp file `sync_all`, atomic rename, return `Ok` | after successful rename, sync the parent directory on Unix; no-op on non-Unix where standard library does not expose a portable directory fsync | private persistence helper only |
| `FileAuditSink` / `FileFederationStore` | both rely on `write_file_atomic` for compact JSON persistence | inherit stronger rename durability with no call-site change | on-disk durability semantics only |

### Data Flow Delta

```text
compact JSON bytes -> temp file write -> temp file sync_all -> rename into target -> parent directory sync -> Ok
```

---

## 5. Contract Block

| Contract Row | Value |
|---|---|
| Inputs | Issue #2385, `agent-governance-rust/agentmesh/src/governance_support.rs`, Rust workspace manifests |
| Outputs | Private helper change, regression tests, code comment, fork PR |
| Interfaces touched | N/A - private helper only |
| Files allowed to change | `agent-governance-rust/agentmesh/src/governance_support.rs`; `agent-governance-rust/Cargo.lock`; `docs/slo/tickets/ticket-2385-rust-fsync-atomic-writes.md` |
| Files to read before changing | `AGENTS.md`; `agent-governance-rust/AGENTS.md`; `docs/ARCHITECTURE.md`; `agent-governance-rust/Cargo.toml`; `agent-governance-rust/agentmesh/Cargo.toml`; `agent-governance-rust/agentmesh/src/governance_support.rs` |
| New files allowed | `docs/slo/tickets/ticket-2385-rust-fsync-atomic-writes.md` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | Existing file-backed store APIs keep their signatures; compact JSON shape is unchanged; temp-file cleanup semantics remain; parent sync errors are surfaced after rename because the durability guarantee is not proven when sync fails |
| Data classification | `Public` |
| Proactive controls in play | OWASP C1/C5: explicit failure handling; OWASP C9: audit durability; fail-closed persistence: sync failure returns `Err`; supply-chain minimization: no dependency |
| Abuse acceptance scenarios | Sudden-crash durability is improved on Unix by syncing the directory entry; tests avoid fake crash simulation and instead prove the sync hook runs after rename and errors propagate |
| Resource bounds introduced/changed | N/A - no new unbounded collection, retry loop, or background worker |
| Invariants/assertions required | Parent sync is invoked only after `fs::rename` succeeds; parent sync receives the target parent, defaulting relative targets to `.`; write or rename failure still removes temp files; non-Unix behavior is portable no-op |
| Debugger / inspection expectation | Use `cargo test -- --nocapture` only if the injected sync-order test fails ambiguously |
| Static analysis gates | `cargo fmt --all -- --check`; `cargo build --release --workspace --all-targets`; `cargo clippy --release --workspace --all-targets -- -D warnings`; `cargo test --release -p agentmesh governance_support::tests::`; `cargo test --release --workspace` |
| Reversibility / rollback path | Revert the private helper and tests; no migration or persistent format rollback needed |
| Exemplar code to copy | Existing `write_file_atomic` cleanup path in `agent-governance-rust/agentmesh/src/governance_support.rs` |
| Anti-exemplar code not to copy | Do not silently swallow Unix parent-directory sync errors; do not add a dependency; do not add crash-simulation tests that rely on platform-specific filesystem behavior; do not rewrite store APIs |
| IAM secrets→role→trust-policy mapping | `N/A - no IAM trust policy touched` |
| Refactoring discipline | Micro-refactor only: split parent path and sync behavior into private helpers after tests exist |
| AI tolerance contract | `N/A - no AI component` |
| Forbidden shortcuts | No placeholder sync hook, no public API expansion, no schema change, no broad persistence rewrite, no ignored durability error on Unix |

---

## 6. Implementation Plan

1. Record repo hygiene and baseline governance tests.
2. Write tests first for sync invocation after rename and sync-error propagation.
3. Confirm the tests fail before implementation because the injectable sync helper is absent.
4. Add private parent-path and parent-directory-sync helpers.
5. Call parent sync after successful rename in `write_file_atomic`.
6. Keep non-Unix behavior as a portable no-op with a code comment.
7. Run formatter, focused governance tests, build, clippy, full workspace tests, and hygiene gates.
8. Fill validation and closeout evidence, then open a fork PR.

---

## 7. BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then | Evidence |
|---|---|---|---|---|---|
| Parent directory synced after rename | happy path | a target file under a temp directory and an injected sync hook | atomic write succeeds | sync hook observes the renamed target content and receives the parent directory path | `write_file_atomic_calls_parent_directory_sync_after_rename` |
| Parent sync failure is surfaced | invalid input / degraded storage | injected parent sync returns an I/O error after rename | atomic write runs | the returned error is the sync failure; target content has been renamed; no temp file leaks | `write_file_atomic_surfaces_parent_directory_sync_error` |
| Missing parent still fails before sync | empty / degraded state | target path points into a missing parent directory | atomic write runs | returns error, target does not exist, sync hook is not called | existing `write_file_atomic_returns_err_when_parent_is_missing` plus focused governance tests |
| Rename failure still cleans temp file | abuse / degraded filesystem | target path is an existing directory | atomic write runs | returns error and no temp file leak remains | existing `write_file_atomic_cleans_temp_file_when_rename_fails` |

---

## 8. Validation Plan

| Check | Command / Action | Expected Result | Actual Result | Status | Notes |
|---|---|---|---|---|---|
| Repo hygiene | `git status --short --branch`; `git rev-parse --abbrev-ref HEAD`; `git symbolic-ref --short refs/remotes/origin/HEAD` | on task branch, no unrelated tracked dirty files | branch `slo/ticket-2385-rust-fsync-atomic-writes`; upstream `origin/main`; dirty tree has generated Cargo.lock metadata plus local SLO tickets | `pass` | Existing untracked `docs/slo` files from prior tickets are preserved and not staged unless explicitly in this ticket |
| Baseline before change | `cargo test --release -p agentmesh governance_support::tests::` | green on latest upstream main | 24 tests passed | `pass` | Running cargo updates lockfile package metadata from 3.6.0 to 3.7.0 on current main |
| New tests fail first | `cargo test --release -p agentmesh governance_support::tests::write_file_atomic_calls_parent_directory_sync_after_rename --no-run` | fails before implementation for missing injectable sync helper | failed with `E0425` for missing `write_file_atomic_with_parent_sync` in both new tests | `pass` | expected pre-implementation failure |
| Formatter | `cargo fmt --all -- --check` | passes | passed | `pass` | |
| Typecheck / build | `cargo build --release --workspace --all-targets` | passes | passed | `pass` | |
| Static analysis / lint | `cargo clippy --release --workspace --all-targets -- -D warnings` | passes | passed | `pass` | |
| Unit / BDD tests | `cargo test --release -p agentmesh governance_support::tests::` | passes | 26 tests passed | `pass` | baseline was 24 tests; this ticket adds 2 tests |
| Runtime validation | `cargo test --release --workspace` | passes | passed: 306 agentmesh lib tests, 1 mcp_reexport test, 6 prompt_defense_compat tests, 32 prompt_injection tests, 28 agentmesh-mcp tests, and 1 agentmesh doc test | `pass` | |
| Dependency / security audit | `git diff -- agent-governance-rust/agentmesh/Cargo.toml agent-governance-rust/Cargo.lock` | no new dependency; only generated package metadata drift if present | no Cargo.toml dependency change; Cargo.lock updates `agentmesh` and `agentmesh-mcp` package metadata from 3.6.0 to 3.7.0 to match workspace version | `pass` | |
| Resource bound / invariant check | inspect tests and helper path | sync occurs after rename, no temp leak on failures | `write_file_atomic_calls_parent_directory_sync_after_rename` asserts renamed content is visible before sync hook returns; sync-error test asserts no temp leak | `pass` | no new resource growth |
| Compatibility check | focused tests for file audit and federation stores | compact JSON shape and store APIs unchanged | focused governance tests include `file_audit_sink_writes_compact_json`, `file_federation_store_writes_compact_json`, and `file_federation_store_persists_multiple_orgs`; all passed | `pass` | |
| `.gitignore` / artifact cleanup | `git status --short` and `git diff --check` | no stray generated artifacts beyond scoped files | `git diff --check` passed; transient `ci-diff/` removed; only scoped tracked changes plus pre-existing untracked SLO docs remain | `pass` | |

---

## 9. Workpad / Tracker Updates

Upstream issue workpad is deferred to avoid noisy Microsoft issue comments while this is being validated in the fork. Local tracker state is this contract.

### Workpad Shape

```markdown
<!-- slo-ticket-workpad:v1 -->
### Plan
- [x] Write SLO ticket contract
- [x] Implement BDD-first
- [x] Verify runtime/static/security gates
- [ ] Open fork PR and hand off

### Acceptance Criteria
- [x] Parent directory sync helper added where supported
- [x] Windows/non-Unix behavior remains portable
- [x] Atomic write path tests prove sync hook is called after rename
- [x] Durability behavior documented in code comments

### Validation
- [x] Baseline governance tests pass
- [x] Formatter/build/clippy/focused tests/full workspace tests pass

### Evidence
- Baseline governance tests: 24 passed
- Focused governance tests after implementation: 26 passed
- Full release workspace tests passed

### Confusions
- Fork main is behind upstream main; this ticket is implemented on upstream main and pushed to the fork for a clean review diff.
```

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

- Pending.

### Tests And Validation

- Pending.

### Lessons / Follow-Ups

- Pending.

### PR / Issue Links

- PR: Pending.
- Issue: https://github.com/microsoft/agent-governance-toolkit/issues/2385
