# KNOWN ISSUES — agent-harness-defense

This file tracks limitations and pending work that affect what the project can
honestly claim. Each entry references the audit / paper that motivated it.

## 1. Label-preserving persistence between iterations — CLOSED in v0.3.0 (CRÍTICO 2, re-scoped 2026-08-29)

**Status:** Implemented in v0.3.0 (feature 003). See `ROADMAP.md` and `adapter/persistence.py`.

**What the code does now (v0.2.0 + adapter 002 + persistence 003):**
- Dual-lattice IFC (confidentiality + integrity) over an explicit
  declarative `Plan` (`agent_harness_defense.ifc`). `SourceTag`,
  `Label` (componentwise join: confidentiality = max, integrity = min),
  `PlanStep`, `Plan`, `PlanVerdict`, `evaluate_plan`.
- Label propagation across `depends_on` (control-flow) and `value_source`
  chains (data-flow). A `write` driven by an UNTRUSTED read (repo text)
  inherits UNTRUSTED integrity and is denied (no-upgrade). A SECRET value
  written to a public sink is denied (no-downgrade). Both axes are reported
  separately (AC-IFC-1/2/3).
- The v0.1 heuristic (`ESCALATION_TRIGGERS` + `LoopStateMonitor`) is
  RETAINED as a SECOND signal (`flagged_by_keyword` /
  `cross_iteration_signal`), never authoritative.

**Label-preserving persistence (v0.3.0, feature 003) — now closed:**
- `adapter/persistence.py` defines `PersistedArtifact(path_or_id, label, summary, iteration)`.
  Only the IFC **result** is stored — `label` (a pair of ints) plus a content-free
  hash `summary` (`sha256(path + reason)[:16]`). The artifact **content** is never
  stored or re-exposed (arXiv:2608.27234 §label-preserving).
- `AgentSession` records a `PersistedArtifact` for every tainted path after each
  `step`, and re-injects those labels into the next iteration via
  `run_admission(persisted_labels=...)`. Because the integrity join is `min`, a
  persisted UNTRUSTED label sinks the step and propagates to downstream steps
  through `depends_on`.
- `evaluate_plan`/`run_admission` take an optional `persisted_labels: dict[str, Label]`
  (default `None` → identical to v0.2, AC-PERS-5). Declassification is explicitly
  out of scope (documented); the taint persists while the `AgentSession` lives.
- 5 new tests (`test_persistence.py`, AC-PERS-1..5) cover the shape, the 2-iteration
  non-vacuous scenario, and content-free summaries.

**Why it is honest to call v0.3.0 complete:** the planner cannot be re-fed a tainted
source as if clean across iterations, and the eval proves it (a 2-iteration test
flips iter-2 from admitted → denied when persistence is on, and stays admitted when
off).

## 2. `llm-guard` is an optional detection signal, not a runtime dep (MENOR 1)

`llm-guard>=0.3.16` is **not** imported anywhere in the core. It is offered as an
optional `detect` extra (`pip install agent-harness-defense[detect]`) for callers
who want a second, library-grade signal on top of the v0.1 keyword/glob engine.
It is intentionally not in `dependencies` to avoid a heavy install (the package
pulls ML models) for users who do not need it.

When/if it is wired into `run_admission` as a real signal, the import and usage
will land in a single commit and `dependencies` will be updated accordingly.

## 3. Governance exception at v0.1 release (MENOR 4)

The repo was opened as a remote on 2026-08-28 with a single initial commit
(~260 lines of real logic and one adversarial scenario) — well below the
~90% completion threshold normally required before opening a remote. The
exception was accepted because:

- The `Signetry/eval` corpus is a moving public benchmark; iterating on a
  public remote is faster than reviewing an off-remote draft.
- Each audit round (Claude 2026-08-28) has produced a discrete, committable
  diff. The history (bd75265 → cf8c37a) shows the gap closure as small,
  reviewable commits.

From this point on, future releases follow the normal threshold. The release
gate (ruff clean, pytest green, eval has teeth) is enforced in CI.

## 4. Cross-iteration state retention is the caller's responsibility (MENOR 3)

`LoopStateMonitor` only retains state across loop iterations if the **caller**
reuses the same instance between `run_admission` calls. The CLI does not yet
drive a real agent loop, so the cross-iteration guarantee is structural
(typed signature + retained state) but is not exercised by the bundled
`ahd eval` command. Wiring it to a real agent harness (e.g. one of the 6
harnesses from arXiv:2608.27299) is roadmap work.

## 5. No declarative-Plan generator existed until adapter 002 (CLOSED as EXAMPLE, 2026-08-29)

Before feature 002, every caller had to hand-write the `Plan` (the §1 dual-lattice
work). Feature 002 ships `agent_harness_defense/adapter/` — a minimal but REAL
example that translates Anthropic tool-calls into `PlanStep`s via `AgentSession`
+ `CassettePlayer`, plus `examples/anthropic_incident_report/` demonstrating the
`INCIDENT_REPORT_INJECTION` vector end-to-end (with a non-vacuous "teeth" test).

HONEST SCOPE: this is an **example adapter**, not a generic agent-integration
framework. It covers the Anthropic tool-calling shape only; OpenAI/MCP and a
full autonomous loop are separate features. The mechanical mapping is fail-closed
for `bash`/`execute` (`value_source="repo.cmd"` → UNTRUSTED → denied) because the
shell can move data the Plan never sees (verified in Spec 002 §2.1).

## 6. Adapter does NOT infer cross-step dependencies (audited 2026-08-29)

**Status:** Fixed in adapter 002 (commit on `feat/002-real-adapter`).
Documented here so the trade-off is explicit. The same fix is included in
`feat/003-label-persistence` via the merge of this branch.

**What happened:** the original `_depends_on_for()` chained every `tool_call` to
its immediate predecessor by temporal order (`depends_on=[prev_id]`). Because the
integrity join is `min` and propagates transitively through `depends_on`, a SINGLE
untrusted read anywhere in a session tainted EVERY later action regardless of real
relation. Reproduced end-to-end: `read_file(README.md)` + 5 unrelated
`write_file(module_N.py)` → all 5 writes denied by `integrity_violation`. Since
almost every real agent reads a README/ docs at startup, this would have blocked
normal work (false-positive avalanche). It also contradicted the Constitution's C1
("NO reconstruye dependencias transversales que el agente no declaró").

**Fix:** `_depends_on_for()` now returns `[]` by default. A step acquires a
`depends_on` ONLY via an EXPLICIT agent-supplied `content_ref`/`value_ref`
(`step_<k>.content`). Without it, the step stands alone.

**Honest trade-off (C1/C6):** the adapter now has FALSE NEGATIVES for undeclared
dependencies — if the agent reads an untrusted source and writes its content WITHOUT
declaring the `content_ref`, the taint is NOT caught. This is the documented,
preferable alternative to denying every normal session. The realistic "teeth" test
(`test_adapter_plan.py::test_read_then_write_declared_dep_propagates_untrusted` and
`examples/anthropic_incident_report`) models the attacker DECLARING the dependency,
which is the only case the IFC can honestly catch. A new guardrail
(`test_adapter_false_positive_scale_read_then_many_unrelated_writes`) locks the
correct behaviour so the bug cannot silently return.
