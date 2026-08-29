# KNOWN ISSUES — agent-harness-defense

This file tracks limitations and pending work that affect what the project can
honestly claim. Each entry references the audit / paper that motivated it.

## 1. Label-preserving persistence between iterations is NOT implemented (CRÍTICO 2, re-scoped 2026-08-29)

**Status:** Implemented in v0.2.0 — see `ROADMAP.md` for the direction.

**What the code does now (v0.2.0):**
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

**What the code does NOT do yet (stage 1 of the plan):**
- Label-preserving persistence between iterations — once the IFC flags a
  payload in iteration N, that label is not carried into the planner's
  context in iteration N+1 (arXiv:2608.27234 §label-preserving). The
  monitor retains cross-iteration *signal*, but the *IFC label* is
  recomputed per call. This is the remaining v0.3 item.

**Why it is honest to call this v0.2:** the README's "Approach" section
now states the dual-lattice IFC explicitly. The roadmap (see `ROADMAP.md`)
sketches the persistence work needed to close the loop fully.

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
