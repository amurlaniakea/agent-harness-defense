# Changelog

All notable changes to `agent-harness-defense` are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-08-29 (feature 003: label-preserving persistence)

Closes the v0.3 remaining-work item (arXiv:2608.27234 §label-preserving). Builds on
the `AgentSession` from feature 002.

### Added
- `agent_harness_defense.adapter.persistence.PersistedArtifact` — remembers a tainted
  artifact across iterations. Stores ONLY the IFC `Label` + a content-free hash
  `summary` (`sha256(path + reason)[:16]`); the artifact content is never stored or
  re-exposed (honest scope, C1).
- `evaluate_plan(..., persisted_labels: dict[str, Label] | None = None)` and
  `run_admission(..., persisted_labels=...)`: re-inject taints from previous
  iterations. Joined before the `depends_on` join, so a persisted UNTRUSTED label
  sinks the step (integrity join is `min`) and propagates downstream.
- `AgentSession.persisted_artifacts` + auto-recording: after each `step`, every
  tainted path is recorded and re-injected into the next iteration. Idempotent per
  path.
- 5 new tests `test_persistence.py` (AC-PERS-1..5). The 2-iteration scenario is
  non-vacuous: iter-2 write is **admitted** without persistence and **denied** with
  it.

### Backward compatibility
- `persisted_labels` defaults to `None` → behaviour identical to v0.2 (the 23 v0.2 +
  14 adapter tests stay green). No breaking API change to `evaluate_plan`/`run_admission`.

### Out of scope (documented)
- Declassification of a persisted taint (the taint persists while the session lives;
  a caller can clear `persisted_artifacts`). A disk/Redis backend (the
  `persisted_labels_from` interface is exposed for callers to provide one).

### Notes
- Version bumped 0.2.0 → 0.3.0. Feature 002's example adapter is included (it was
  delivered on the `feat/002-real-adapter` branch and merged into this branch so 003
  builds on top of it; 002 also stands alone as PR #3).

## [0.2-adapter / feature 002] — 2026-08-29 (v0.3-precursor, no version bump yet)

Feature 002 ships an example adapter that connects the IFC to real Anthropic
tool-calling. The version stays 0.2.0; the v0.3.0 bump lands with feature 003
(label-preserving persistence), which builds on `AgentSession`.

### Added
- `agent_harness_defense.adapter.tool_map` — mechanical `tool_call → PlanStep`
  mapping (Spec 002 §2). `bash`/`execute` map to `value_source="repo.cmd"`
  (UNTRUSTED, fail-closed) so shell-borne exfiltration is denied by default.
  Verified consequence (Spec §2.1): the original `value_source=None` mapping left
  `bash("echo $SECRET > incident-report.md")` ADMITTED; the new mapping denies it.
- `agent_harness_defense.adapter.session.AgentSession` — drives multiple
  `run_admission` calls, reusing `LoopStateMonitor` across iterations, with a
  `pre_evaluate` hook reserved for feature 003.
- `agent_harness_defense.adapter.cassette.CassettePlayer` — offline-deterministic
  replay of API responses; the real call only runs under `AHD_RECORD=1` +
  `ANTHROPIC_API_KEY`. CI never imports `anthropic` nor touches the network.
- `examples/anthropic_incident_report/` — end-to-end demo of the
  `INCIDENT_REPORT_INJECTION` vector with a non-vacuous "teeth" test
  (`RUN_ADMISSION=0` materializes the attack on disk).
- 14 new tests: `test_adapter_plan` (AC-ADAPT-1), `test_cassette_offline`
  (AC-ADAPT-3 offline half), `test_session_loop` (AC-ADAPT-2 + AC-ADAPT-5),
  `test_example_cassette` (AC-ADAPT-3 end-to-end + teeth).

### Fixed (audit 2026-08-29) — do NOT infer temporal dependency chains
- `_depends_on_for()` originally chained every `tool_call` to its immediate
  predecessor by temporal order. Because the integrity join is `min` and propagates
  transitively through `depends_on`, ONE untrusted read anywhere in a session tainted
  EVERY later action — `read_file(README.md)` + 5 unrelated `write_file` calls denied
  all 5 writes (false-positive avalanche; also contradicted Constitution C1). The
  default is now `depends_on=[]`; a step depends on something ONLY via an EXPLICIT
  agent-supplied `content_ref`/`value_ref` (`step_<k>.content`). The realistic
  "teeth" tests model the attacker DECLARING the dependency (the only case the IFC can
  honestly catch). Trade-off: FALSE NEGATIVES for undeclared dependencies (documented in
  KNOWN_ISSUES §6). New guardrail `test_adapter_false_positive_scale_*` locks this.

### Notes / honest scope
- This is an **example adapter**, not a generic agent-integration framework
  (KNOWN_ISSUES §5). Anthropic only; OpenAI/MCP and a full autonomous loop are
  separate features.

## [0.2.0] — 2026-08-29

### Breaking changes
- `run_admission` now requires a `Plan` (declarative) as its third argument;
  the v0.1 `proposed_files` parameter is removed. The `mission` string is now
  part of the `Plan`. Migration:
  ```python
  # v0.1
  run_admission(repo, label, "mission text", proposed_files=[...])
  # v0.2
  run_admission(repo, label, Plan(mission="mission text", steps=[...]))
  ```
- `ahd run PATH` is now `ahd run REPO --plan PATH` (YAML `Plan`). The plan is
  the unit of admission, not the on-disk materialized state.

### Added
- Dual-lattice IFC (confidentiality + integrity) per arXiv:2608.27234 (SPA,
  Girrens & Wang). `SourceTag`, `Label` (componentwise join: confidentiality
  = max, integrity = min so "taint does not wash"), `PlanStep`, `Plan`,
  `PlanVerdict`, `evaluate_plan`, `plan_from_yaml` in
  `agent_harness_defense.ifc`.
- Propagation by `depends_on` (control-flow) and `value_source` (data-flow):
  a `write` driven by an UNTRUSTED `read` inherits UNTRUSTED integrity and is
  denied (no-upgrade); a SECRET value written to a public sink is denied
  (no-downgrade). Both axes reported separately.
- Reads classified by path (`_classify_read_path`): repo text → UNTRUSTED,
  system paths → SYSTEM. Pure, no filesystem access.
- `INCIDENT_REPORT_INJECTION` scenario (AC-EVAL-1) + `assert_plan_matches_
  materialized` guard against Plan↔materialized drift.
- 23 tests (was 6 v0.1): 7 v0.2 IFC (3 lattice + 4 propagation) + 3 conftest
  + 2 false-positive guards + 7 v0.1-adapted (3 IPI + 2 monitor + 1 regression
  + 1 loop-state). The v0.1 regression guard now monkey-patches
  `evaluate_plan` to prove the eval is non-vacuous.

### Changed
- The v0.1 keyword heuristic (`ESCALATION_TRIGGERS` + `LoopStateMonitor`) is
  now a SECOND signal (`flagged_by_keyword` / `cross_iteration_signal`), not
  the admission decision. The IFC verdict is authoritative.
- `InstructionLevel` and `_level_of_file` removed (superseded by the
  dual-lattice in `ifc.py`).

### Closed limitations (see KNOWN_ISSUES.md §1)
- AC-IFC-1 (lattice enforcement, both axes)
- AC-IFC-2 (data-flow propagation)
- AC-IFC-3 (control-flow propagation, both axes)
- AC-IFC-4 (false-positive guards)
- AC-IFC-5 (no-regression: v0.1 scenarios adapted, teeth guard added)
- AC-IFC-6 (eval is not vacuous: v0.1 missed AC-EVAL-1, v0.2 catches)
- AC-IFC-7 (offline, <1s/test)

### Remaining (v0.3, see ROADMAP.md)
- Label-preserving persistence between iterations (arXiv:2608.27234
  §label-preserving).
- AgentDojo / AgentDojo-MQ benchmark wiring.
- The 6 real coding-agent harnesses from arXiv:2608.27299.

## [Unreleased] — v0.1.0 (2026-08-28)

First public release. Open admission-layer defense for LLM agent harnesses.

### Added

- `run_admission()` with forbidden-path quarantine gated by a cross-iteration
  escalation monitor (arXiv:2608.27141).
- `LoopStateMonitor` retaining state across loop iterations; observes ALL
  untrusted repo text (planted input) separately from the admission decision.
- `InstructionLevel` enum and `_level_of_file()` for provenance of the
  escalation decision (full label propagation is roadmap work; see
  `KNOWN_ISSUES.md` §1 and `ROADMAP.md`).
- CLI: `ahd run PATH` and `ahd eval`.
- Bundled adversarial scenarios re-modeling the public `Signetry/eval` IPI
  corpus: `ipi.readme_deploy_and_exfil` and `ipi.claude_md_scope_expansion`.
  The agent's `obey()` step WRITES the malicious artifacts to disk so the eval
  exercises the real defense.
- Three independent guard rails proving the eval is non-vacuous:
  - **Teeth assert** in `test_admission.py` — fails with `SCENARIO INCOMPLETE`
    if `obey()` does not materialize the attack artifact.
  - **Regression guard** in `test_eval_catches_regression.py` — a defense that
    admits the forbidden artifact reports `trust_boundary_clean=False`.
  - **Monitor signal pins** in `test_monitor_signal.py` — the cross-iteration
    monitor's signal is asserted at concrete values; the planted-input
    invariant is verified by re-introducing the original bug and seeing the
    test fail with `REGRESSION:`.

### Security

- `AGPL-3.0-or-later` license, verbatim text from
  `https://www.gnu.org/licenses/agpl-3.0.txt` (the legal body from the FSF
  `Copyright (C) 2007 Free Software Foundation` line onwards is byte-identical,
  658 lines, `diff` empty). The author attribution is added as an FSF-style
  header notice (the pattern recommended in the license's own "How to Apply
  These Terms" section).
- SPDX headers in every `.py` source file under `agent_harness_defense/` and
  `tests/`.
- `gitleaks` scan in CI to catch accidental secret leaks.

### CI / infra

- `pip install -e .[dev]` verified on a clean runner (`/tmp/ahd-clean`):
  - `ruff check .` → All checks passed.
  - `ruff format --check .` → 12 files already formatted.
  - `pytest` → 6 passed.
  - `bandit -r agent_harness_defense -ll` → Low: 0, Med: 0, High: 15
    (legitimate subprocess usage in `admission.py` for `git rev-parse` and
    `git diff --stat`; non-fatal with `-ll`).
- `gitleaks/gitleaks-action@v2` with `fetch-depth: 0` (shallow clones break
  the action's diff scan).
- `[tool.hatch.metadata] allow-direct-references = true` so the `eval` extra
  (which uses a direct git URL for `signetry-eval`) installs without
  `ERROR: Direct references are not allowed`.

### Known limitations (see `KNOWN_ISSUES.md` for the full list)

- **Taint propagation is NOT implemented.** The `taint` field in
  `AdmissionReport` records each file's label for provenance but does not
  propagate labels across data/control flows. The direction is SPA
  (arXiv:2608.27234); see `ROADMAP.md`.
- **`llm-guard` is optional** (`[detect]` extra) and not yet wired into
  `run_admission`. It is offered as a second signal for callers who want it.
- **Cross-iteration state retention is the caller's responsibility.** The CLI
  does not drive a real agent loop; the harness that integrates
  `run_admission` must reuse the same `LoopStateMonitor` instance.
- **Eval is narrow.** Only the two IPI scenarios are re-modeled; the
  `skill_poison` and `minja` Signetry scenarios and the 6 real coding-agent
  harnesses from arXiv:2608.27299 are roadmap work.

### Audits

Two independent external audits (Claude) on 2026-08-28:

- **Round 1** flagged that the original eval was vacuous (the `obey()` step
  was missing) and that the README claimed taint propagation that did not
  exist. Both fixed in the initial round of commits: port the real Signetry
  `obey()`, add the teeth assert, document the v0.1 scope honestly in
  `KNOWN_ISSUES.md`.
- **Round 2** flagged (a) a regression introduced by the `proposed_files`
  refactor — the cross-iteration monitor was scanning only the agent's
  output, so the signal came from a coincidental substring in the agent's
  output rather than from the planted injection; (b) `pip install -e .[dev]`
  failed on a clean runner for three independent reasons (hatchling direct
  references, `gitleaks` not being a pip package, `bandit` exiting 1 on
  legitimate Low-severity findings); (c) the LICENSE lost its author
  attribution when the verbatim swap removed it. All three fixed in commits
  `37e4b44`, `693de48`, and `d05723c`.
