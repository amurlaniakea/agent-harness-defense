# ROADMAP — agent-harness-defense

This is the direction the project is heading, not a list of promises. Each
item links back to the research / audit that motivates it.

## Near term: from v0.1 heuristic to a real IFC engine

The current admission layer is a keyword/glob engine (see `KNOWN_ISSUES.md`
§1). The v0.2 target is full **information-flow control** as described in
arXiv:2608.27234 (SPA: Securing Persistent LLM Agents Across Queries with
Plan-First Information-Flow Control):

- Track per-fragment instruction levels across data and control dependencies.
- A planner emits a declarative plan once per query; the runtime applies a
  dual-lattice IFC (confidentiality + integrity) over explicit data flows and
  control dependencies. Low-privilege content elevated to a high-privilege
  command is denied.
- Persist untrusted payloads in a quarantine so they are not re-exposed to the
  planner on later iterations.

The v0.1 work that this roadmap builds on:
- Forbidden-path quarantine (v0.1) becomes one **projection** of the
  dual-lattice decision rather than the whole defense.
- The cross-iteration monitor (v0.1, arXiv:2608.27141) becomes a consumer of
  IFC verdicts across iterations instead of a substring accumulator.

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
