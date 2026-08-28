# Changelog

All notable changes to `agent-harness-defense` are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/) and the
project adheres to [Semantic Versioning](https://semver.org/).

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
