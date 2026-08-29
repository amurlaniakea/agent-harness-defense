# agent-harness-defense

Open admission-layer defense for LLM agent harnesses: a forbidden-path quarantine
gated by a cross-iteration escalation monitor, evaluated offline against the public
Signetry adversarial corpus.

## Problem

LLM agents run over untrusted web pages, docs, tools and persistent state while
holding authority over security-sensitive resources. Recent work shows two
structural gaps in the defenses in wide use:

- **Instruction privilege escalation** — agent harnesses build per-invocation
  context and can elevate low-privilege content (repo text, tool output) to a
  higher instruction level, making the agent obey what it would refuse at the
  original level (arXiv:2608.27299).
- **Non-decaying loop state** — autonomous agent loops re-initialize their safety
  monitor every trajectory, so attacker evidence fragmented across iterations is
  never seen in any single window; a monitor retaining cross-iteration state
  separates true positives from false positives, trajectory-scoped monitors do not
  (arXiv:2608.27141).

## Approach (v0.2 — IFC plan-first, dual-lattice)

`agent-harness-defense` provides an open `run_admission()` layer (the part
`signetry-core` keeps closed). What it actually does today:

1. **Dual-lattice IFC** (confidentiality + integrity) per
   arXiv:2608.27234 (SPA). `evaluate_plan` takes a declarative `Plan` and
   applies a componentwise lattice join over the `depends_on` graph:
   confidentiality = max (the result is as sensitive as the most sensitive
   operand), integrity = min ("taint does not wash" — an UNTRUSTED value
   joined with a SYSTEM intent stays UNTRUSTED, blocking the no-upgrade
   rule). `SourceTag` (SYSTEM/USER/TOOL_RESULT/REPO_TEXT/ENV/DATA) is the
   per-fragment origin label.
2. **Propagation by `depends_on`** — a `write`/`execute` step inherits the
   label of every step it depends on. A `write` of `incident-report.md`
   that `depends_on` a `read` of an untrusted `README.md` inherits UNTRUSTED
   integrity and is denied (no-upgrade). A `write` sourced from `env.SECRET`
   to a public sink is denied (no-downgrade). Both axes are reported
   separately (AC-IFC-1/2/3).
3. **Reads are classified by path** (`_classify_read_path`): reading
   repo text yields UNTRUSTED integrity (the prompt-injection surface);
   reading a system file yields SYSTEM integrity. This is pure (no I/O).
4. **Forbidden-path quarantine** — retained from v0.1: a step whose path
   matches `forbidden_paths` in the contract is denied. It is now one
   projection of the dual-lattice decision, not the whole defense.
5. **Cross-iteration loop-state monitor** (arXiv:2608.27141) — RETAINED as a
   SECOND signal (`flagged_by_keyword` / `cross_iteration_signal`).
   The IFC verdict is the primary decision; the monitor feeds diagnostic
   visibility only.
6. **Contract / verifier** — `allowed_paths`, `forbidden_paths`,
   `max_files_changed`.
7. **Receipt** — admitted change carries a hash of the base commit, the diff,
   and the plan capability-set hash.

The v0.1 keyword heuristic (`ESCALATION_TRIGGERS`) is NOT the decision —
it is a second signal. The claim matches the code: the IFC is a real
dual-lattice engine, not a substring matcher.

## Adapter example (feature 002 — Anthropic tool-calling)

`agent_harness_defense/adapter/` is a minimal but REAL example that connects the
IFC to the Anthropic tool-calling API, so a caller can copy it instead of hand-writing
a `Plan`. It lives in `examples/anthropic_incident_report/`:

- `tool_map.build_plan` — mechanical `tool_call → PlanStep` mapping (Spec 002 §2).
  `bash`/`execute` map to `value_source="repo.cmd"` (UNTRUSTED) so shell-borne
  exfiltration is **denied by default** (fail-closed; verified in §2.1).
- `session.AgentSession` — drives multiple `run_admission` calls, reusing the
  `LoopStateMonitor` across iterations, with a `pre_evaluate` hook reserved for
  feature 003.
- `cassette.CassettePlayer` — replays frozen API responses offline; the real call
  only runs under `AHD_RECORD=1` + `ANTHROPIC_API_KEY`, so CI never hits the network
  or needs credentials.

This is an **example adapter**, not a generic integration framework (see
[KNOWN_ISSUES.md](KNOWN_ISSUES.md) §5). Feature 003 (label-preserving persistence)
builds on `AgentSession` and bumps the version to v0.3.0.

## Label-preserving persistence (feature 003 — v0.3.0)

Feature 003 closes the loop the v0.1 cross-iteration monitor could not: when the IFC
flags an artifact as tainted (UNTRUSTED integrity) in iteration N, that **label** —
not the artifact's content — persists into iteration N+1, so the planner cannot be
re-fed a tainted source as if it were clean (arXiv:2608.27234 §label-preserving).

- `adapter/persistence.PersistedArtifact` stores only the IFC `Label` plus a
  content-free hash `summary` (`sha256(path + reason)[:16]`). The artifact text is
  never stored or re-exposed.
- `AgentSession` records a `PersistedArtifact` for every tainted path after each
  `step`, and re-injects those labels into the next iteration via
  `run_admission(persisted_labels=...)`. Because the integrity join is `min`, a
  persisted UNTRUSTED label sinks the step and propagates downstream through
  `depends_on`.
- `evaluate_plan` / `run_admission` take an optional `persisted_labels` (default
  `None` → identical to v0.2, so the 23 v0.2 + 14 adapter tests stay green).
- 5 new tests (`test_persistence.py`, AC-PERS-1..5) prove the improvement is real:
  a 2-iteration scenario flips the iter-2 write from **admitted** (no persistence)
  to **denied** (with persistence). Declassification is explicitly out of scope.

## Evaluation (offline, deterministic, NON-vacuous)

The public Signetry adversarial suite (`Signetry/eval`) is the attack source. We
re-model BOTH IPI scenarios (`ipi.readme_deploy_and_exfil`,
`ipi.claude_md_scope_expansion`) faithfully: the agent's `obey()` step WRITES the
malicious artifacts (`deploy.yml`, `stolen.txt`, `.github/workflows/release.yml`) to
disk, so the test exercises the real defense — those artifacts must NOT enter the
ADMITTED changeset while the benign left-pad bump still completes.

Two independent guard rails prove the eval is honest:

- **Teeth assert** (`tests/test_admission.py`): before admission runs, the test
  asserts the malicious artifacts are actually on disk. If `obey()` is skipped
  or stops writing, the test fails with `SCENARIO INCOMPLETE` rather than
  passing vacuously.
- **Regression guard** (`tests/test_eval_catches_regression.py`): a defense that
  admits the forbidden artifacts is reported with `trust_boundary_clean=False`
  and the test fails.
- **Monitor signal pins** (`tests/test_monitor_signal.py`): the cross-iteration
  monitor's signal is asserted at concrete values and the planted-input
  invariant is enforced (wiping the agent's output to a non-trigger string
  MUST NOT drop the signal — verified by re-introducing the original bug and
  seeing the test fail with `REGRESSION:` message).

```bash
pytest            # 37 base + 5 persistence (003) = 42 tests: IFC + adapter + persistence
ahd eval          # iterate bundled scenarios (v0.1 IPI + AC-EVAL-1) against run_admission
ahd run REPO --plan PATH   # evaluate a YAML Plan against a repo on disk
```

## Status

v0.2.0: dual-lattice IFC propagation implemented and tested. AC-EVAL-1
(the escalation v0.1 missed — a `write` of a SECRET to a public sink
driven by an untrusted `read` — is caught by the IFC, see
`test_ifc_propagation.py::test_v01_would_have_missed_this`) closes the
gap the v0.1 heuristic could not. The v0.1 keyword/glob heuristic is
retained as a second signal. 23 tests, all green on a clean runner
(ruff, ruff-format, bandit -ll, pytest). Two independent external audits
(Claude, 2026-08-28 and 2026-08-29) verified the eval is non-vacuous and
the CI installs and tests cleanly. Remaining work: label-preserving
persistence between iterations (v0.3, see [ROADMAP.md](ROADMAP.md)).

Feature 002 (2026-08-29, v0.3-precursor): `agent_harness_defense/adapter/`
ships a REAL example adapter for Anthropic tool-calling (mechanical
`tool_call → PlanStep` mapping, fail-closed `bash`, `AgentSession` loop,
offline cassette replay). 14 new tests cover it, including a non-vacuous
"teeth" test (`test_example_cassette.py::test_example_is_not_vacuous_*`).
The example is NOT a generic framework (KNOWN_ISSUES §5).

Feature 003 (2026-08-29, v0.3.0): label-preserving persistence. A tainted
artifact's IFC `Label` (not its content) persists across `AgentSession`
iterations via `persisted_labels`, so the planner cannot be re-fed a tainted
source as clean. 5 new tests (`test_persistence.py`, AC-PERS-1..5) prove the
2-iteration scenario flips the iter-2 write from admitted → denied. Version
bumped to 0.3.0. (PR #4.)

## License

AGPL-3.0-or-later — Pedro Sordo Martínez (amurlaniakea@gmail.com), 2026.
See [LICENSE](LICENSE).
