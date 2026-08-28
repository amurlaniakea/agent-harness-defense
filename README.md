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
   implemented yet — it is the SPA direction (arXiv:2608.27234), future work.
2. **Forbidden-path quarantine** — the agent's on-disk edits are scanned; any file
   matching `forbidden_paths` in the admission contract is quarantined out of the
   ADMITTED changeset. The quarantine is gated by a cross-iteration escalation
   signal so a single benign-looking mention does not over-block.
3. **Cross-iteration loop-state monitor** (arXiv:2608.27141) — retains a safety
   signal across iterations instead of re-initializing per trajectory. (The caller
   must reuse the same `LoopStateMonitor` across loop iterations; the CLI does not
   yet drive a real agent loop.)
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

A regression guard (`tests/test_eval_catches_regression.py`) proves the eval is not
vacuous: if the defense admitted the artifact, the criterion reports
`trust_boundary_clean=False` and the test fails.

```bash
pytest            # 4 tests: 2 IPI scenarios + cross-iteration + regression guard
ahd eval          # run the bundled scenarios against run_admission
ahd run PATH      # admit/reject the agent's change on disk at PATH
```

## Status

MVP. Not 1.0: missing label propagation (item 1 above), integration with the 6
coding-agent harnesses of arXiv:2608.27299 as a live banco, and the
`skill_poison` / `minja` Signetry scenarios. The eval is honest but narrow.

## License

AGPL-3.0-or-later — Pedro Sordo Martínez (amurlaniakea@gmail.com), 2026.
See [LICENSE](LICENSE).
