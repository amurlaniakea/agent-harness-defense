# agent-harness-defense

Open admission-layer defense for LLM agent harnesses: taint / information-flow
control plus a cross-iteration state monitor, evaluated against the public
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

## Approach

`agent-harness-defense` provides an open `run_admission()` layer (the part
`signetry-core` keeps closed) with:

1. **Taint / info-flow tracker** — labels every content fragment with an
   instruction level (system / user / tool / data / repo-text) and propagates it
   across explicit data flows and control dependencies. Low-privilege content
   elevated to a high-privilege command is denied.
2. **Cross-iteration state monitor** — retains a safety state across loop
   iterations instead of re-initializing per trajectory.
3. **Contract / verifier** — `allowed_paths`, `forbidden_paths`,
   `max_files_changed` admission policy.
4. **Receipt** — admitted change carries a hash of the base commit, the diff, and
   the plan capability-set hash, so a prior authorization cannot bless a different
   change.

## Evaluation

The public Signetry adversarial suite (`Signetry/eval`) is used as an offline,
deterministic attack fixture. Our `run_admission` replaces `signetry-core`; the
suite poses the attacks and scores ASR (attack success rate) under defense at
preserved utility.

## License

AGPL-3.0-or-later — Pedro Sordo Martínez (amurlaniakea@gmail.com), 2026.
See [LICENSE](LICENSE).
