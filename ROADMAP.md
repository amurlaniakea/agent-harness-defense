# ROADMAP — agent-harness-defense

This is the direction the project is heading, not a list of promises. Each
item links back to the research / audit that motivates it.

## CLOSED: from v0.1 heuristic to a real IFC engine (v0.2.0, 2026-08-29)

The admission layer WAS a keyword/glob engine (see `KNOWN_ISSUES.md` §1).
v0.2.0 shipped full **information-flow control** as described in
arXiv:2608.27234 (SPA: Securing Persistent LLM Agents Across Queries with
Plan-First Information-Flow Control):

- Per-fragment source tags (SYSTEM/USER/TOOL_RESULT/REPO_TEXT/ENV/DATA) over
  data and control dependencies, via an explicit declarative `Plan`.
- A planner emits a `Plan` once per query; `evaluate_plan` applies a
  dual-lattice IFC (confidentiality = max, integrity = min) over the
  `depends_on` graph. Low-privilege content elevated to a high-privilege
  command is denied (no-upgrade). SECRET→public-sink is denied (no-downgrade).
- The v0.1 heuristic is retained as a SECOND signal (`flagged_by_keyword` /
  `cross_iteration_signal`), not the decision.

## v0.3 (post-v0.2) — remaining work

- **Label-preserving persistence between iterations** (arXiv:2608.27234
  §label-preserving): carry IFC labels from iteration N into the planner
  context in iteration N+1, instead of recomputing per call. Closes the
  loop the v0.1 cross-iteration *signal* monitor could not.
- **AgentDojo / AgentDojo-MQ benchmark**: evaluate against the standard
  agent-security benchmark, not just the re-modeled Signetry IPI corpus.
- **Wiring the 6 real harnesses from arXiv:2608.27299** (see below).

## Wiring the 6 real harnesses from arXiv:2608.27299

The privilege-escalation paper evaluates 13 attack objectives across 6
coding-agent harnesses. The v0.1 eval is the Signetry IPI scenarios
(`ipi.readme_deploy_and_exfil`, `ipi.claude_md_scope_expansion`) only. Wiring
the 6 harnesses as a live banco (each running a benign task + an injected
README) is the path from "lab fixture" to "benchmark".

## Optional detection signal (llm-guard)

`agent-harness-defense[detect]` currently installs `llm-guard` but does not
call it. When wired, it will be a **second** signal fused with the v0.1
keyword engine — not a replacement, and never the sole defense.

## CI / release gate

ruff clean, ruff format clean, pytest green, eval has teeth, bandit clean.
See `.github/workflows/ci.yml`.
