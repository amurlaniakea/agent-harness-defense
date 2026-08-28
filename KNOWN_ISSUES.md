# KNOWN ISSUES — agent-harness-defense

This file tracks limitations and pending work that affect what the project can
honestly claim. Each entry references the audit / paper that motivated it.

## 1. Taint / information-flow propagation is NOT implemented (CRÍTICO 2, Claude audit 2026-08-28)

**Status:** pending — see `ROADMAP.md` for the direction.

**What the code does today (v0.1):**
- `InstructionLevel` (SYSTEM/USER/TOOL_RESULT/REPO_TEXT/DATA) labels every file
  the agent reads from the repo as LOW-privilege (`_level_of_file` returns
  `REPO_TEXT`).
- The label is used for **provenance** of the escalation decision (the report
  carries `taint: dict[rel -> level]`), not for propagation.
- The actual escalation decision is: (a) forbidden-path glob match against
  `contract.forbidden_paths`, gated by (b) a cross-iteration escalation signal
  (`LoopStateMonitor.accumulated_score >= 1.0`).

**What the code does NOT do yet:**
- Label propagation across arbitrary data flows (e.g. if a tool result is
  embedded in a later user prompt, propagate the tool-result label).
- Label propagation across control dependencies (e.g. an `if` branch whose
  condition depends on tainted data taints the branch).
- A principled explanation of *why* a specific elevation was denied beyond
  "forbidden path matched + cross-iteration signal fired".

**Why it is honest to call this v0.1:**
- The README's "Approach" section now states the heuristic explicitly
  (keyword + glob matching, no propagation). It does not claim IFC propagation.
- The roadmap (see `ROADMAP.md`) sketches the propagation work needed to call
  this an IFC engine rather than a v0.1 heuristic.

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
