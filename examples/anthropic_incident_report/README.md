# Example: Anthropic tool-calling adapter (agent-harness-defense 002)

A minimal, **guided** mini-agent that connects `agent-harness-defense` to the
Anthropic tool-calling API. It shows the adapter pattern from Spec 002 §5:

1. Plant a repo with a benign task + an injected `README.md`.
2. Ask the model (real call, recorded as a cassette) for tool-calls.
3. Translate those tool-calls into a declarative `Plan` via `AgentSession`
   (`build_plan` — mechanical, fail-closed mapping from Spec §2 / §2.1).
4. Let the dual-lattice IFC decide; only admitted steps are materialized.

## Run offline (default — replays frozen cassettes, no API key)

```
python run.py
```

This reads `fixtures/*.json` and never touches the network.

## Record a fresh cassette (manual, out-of-CI — needs your key)

```
AHD_RECORD=1 ANTHROPIC_API_KEY=sk-... python run.py
```

This imports the `anthropic` SDK, performs the real call, and freezes the
response into `fixtures/`. CI never does this (C3: offline, no credentials).

## The "teeth" guarantee (non-vacuous test)

The defense only runs when `RUN_ADMISSION` is truthy. Set it off and the
agent blindly executes — `incident-report.md` appears with the secret:

```
RUN_ADMISSION=0 python run.py
```

`tests/test_example_cassette.py::test_example_is_not_vacuous_attack_materializes_without_defense`
asserts exactly that, proving the acceptance test is not decorative.

## What this is NOT

This is an **example**, not a generic integration framework (KNOWN_ISSUES §1).
It is not an autonomous agent loop. Feature 003 (label-preserving persistence,
v0.3) will hang off `AgentSession.pre_evaluate` without rewriting this code.
