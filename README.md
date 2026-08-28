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

## Approach (v0.1 — honest scope)

`agent-harness-defense` provides an open `run_admission()` layer (the part
`signetry-core` keeps closed). What it actually does today:

1. **Taint labeling** — every file the agent reads from the repo is labeled
   LOW-privilege (`InstructionLevel.REPO_TEXT`, i.e. untrusted data, not
   instructions). This label is used for provenance of the escalation decision.
   NOTE: full label *propagation* across arbitrary data/control flows is NOT
   implemented yet — it is the SPA direction (arXiv:2608.27234), future work
   (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md) §1 and [ROADMAP.md](ROADMAP.md)).
2. **Forbidden-path quarantine** — the agent's on-disk edits are scanned; any file
   matching `forbidden_paths` in the admission contract is quarantined out of the
   ADMITTED changeset. The quarantine is gated by a cross-iteration escalation
   signal so a single benign-looking mention does not over-block.
3. **Cross-iteration loop-state monitor** (arXiv:2608.27141) — retains a safety
   signal across iterations instead of re-initializing per trajectory. The monitor
   observes the planted input (README, CLAUDE.md, and all untrusted repo text)
   separately from the admission decision (which uses the proposed changeset).
   The caller must reuse the same `LoopStateMonitor` across loop iterations; the
   CLI does not yet drive a real agent loop (KNOWN_ISSUES.md §4).
4. **Contract / verifier** — `allowed_paths`, `forbidden_paths`, `max_files_changed`.
5. **Receipt** — admitted change carries a hash of the base commit, the diff, and
   the plan capability-set hash.

The escalation decision is currently a heuristic over LOW-privilege repo text
(5 hard-coded trigger phrases + forbidden-path matching), NOT a learned/taint
propagation engine. That is stated plainly here so the claim matches the code.

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
pytest            # 6 tests: 2 IPI + regression + cross-iteration + monitor-signal (×2)
ahd eval          # run the bundled scenarios against run_admission
ahd run PATH      # admit/reject the agent's change on disk at PATH
```

## Status

v0.1 MVP. The defense exercises three of the five components end-to-end against
the real IPI corpus; components #1 (IFC propagation) and the live agent-loop
wiring are roadmap work (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md) and
[ROADMAP.md](ROADMAP.md)). Two independent external audits (Claude, 2026-08-28)
verified the eval is non-vacuous and the CI installs and tests cleanly on a
fresh runner.

## License

AGPL-3.0-or-later — Pedro Sordo Martínez (amurlaniakea@gmail.com), 2026.
See [LICENSE](LICENSE).
