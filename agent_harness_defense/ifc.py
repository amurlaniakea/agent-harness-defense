# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martínez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

"""Dual-lattice information-flow control (IFC) for LLM agent plans.

This module implements the v0.2 IFC engine per arXiv:2608.27234 (SPA: Girrens &
Wang, plan-first information-flow control). The engine evaluates a declarative
`Plan` (a sequence of `PlanStep`s) and returns a `PlanVerdict` describing
which steps are admitted, denied (and why), and the resulting taint summary.

Two axes, both enforced:

- Integrity (no-upgrade): UNTRUSTED content cannot drive a SYSTEM-intent action.
  This catches privilege escalation (arXiv:2608.27299).
- Confidentiality (no-downgrade): SECRET content cannot end up in a PUBLIC sink.
  This catches exfiltration of env / tool results to public output paths.

The caller declares dependencies explicitly via `PlanStep.depends_on`; the
engine propagates labels along the declared `depends_on` graph. The engine
does NOT infer dependencies from materialised content on disk (see the spec
HONEST-scope note in `Memorias/IA y Computacion/agent-harness-defense/spec/
features/001-v0.2-ifc/spec.md` §11).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Literal

import yaml

# Confidentiality levels (max wins on join: SECRET > INTERNAL > PUBLIC).
CONFIDENTIALITY_PUBLIC = 0
CONFIDENTIALITY_INTERNAL = 1
CONFIDENTIALITY_SECRET = 2

# Integrity levels (max wins on join: SYSTEM > USER > UNTRUSTED).
INTEGRITY_UNTRUSTED = 0
INTEGRITY_USER = 1
INTEGRITY_SYSTEM = 2


def _glob_match(pattern: str, rel: str) -> bool:
    """Glob match used by `evaluate_plan` for the `forbidden_path` rule.

    Local copy of the helper in `admission.py` so that `ifc.py` stays
    self-contained (the plan calls for `ifc.py` to be pure IFC math, with
    `admission.py` being the integration layer that imports from `ifc.py`,
    not the other way around).
    """
    if pattern == rel:
        return True
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        if rel.endswith(suffix) or ("/" + rel).endswith("/" + suffix):
            return True
        if "*" in suffix:
            rx = re.compile("^.*?" + re.escape(suffix).replace(r"\*", ".*") + "$")
            return bool(rx.match(rel))
        return False
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return rel.startswith(prefix) or ("/" + rel).startswith(prefix)
    if pattern.endswith("/*"):
        prefix = pattern[:-1]
        return rel.startswith(prefix) and "/" not in rel[len(prefix) :]
    if "*" in pattern:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        return bool(rx.match(rel))
    return False


class SourceTag(IntEnum):
    """Origin of a content fragment.

    Values are unique (no IntEnum aliasing). The `DATA = 0` value sits at the
    bottom of the integrity/confidentiality scale, leaving room for future
    source tags (e.g. a `STALE_CACHE = -1` if we ever model one) without
    colliding with `USER = 4`. An earlier draft had `DATA = 4` which aliased
    `USER = 4` and would have silently broken any code comparing by value;
    this was fixed in the 2026-08-28 review (see tasks.md T003).
    """

    SYSTEM = 5
    USER = 4
    TOOL_RESULT = 3
    REPO_TEXT = 2
    ENV = 1
    DATA = 0  # lowest priority; aliasing with USER (4) would be a silent bug


@dataclass(frozen=True)
class Label:
    """Dual-lattice label: (confidentiality, integrity).

    Join is componentwise:
    - Confidentiality: `max` (the result is as sensitive as the more
      sensitive operand — SECRET is SECRET regardless of what it's mixed
      with).
    - Integrity: `min` (the result is as trusted as the LESS trusted
      operand — "taint does not wash"). Without this, a UNTRUSTED value
      crossed with a SYSTEM-intent would elevate to SYSTEM, which is exactly
      the privilege-escalation attack the no-upgrade rule must block.

    This was the FIX of 2026-08-28: the original v0.2 spec used `max` for
    both axes, which is the standard lattice join but models the no-upgrade
    rule incorrectly. The fix was discovered when AC-IFC-1.1 (`test_join_
    no_upgrade_blocks_untrusted_to_system`) failed because the join was
    elevating UNTRUSTED to SYSTEM through a SYSTEM read dependency.
    """

    confidentiality: int
    integrity: int

    def join(self, other: "Label") -> "Label":
        return Label(
            confidentiality=max(self.confidentiality, other.confidentiality),
            integrity=min(self.integrity, other.integrity),
        )

    @classmethod
    def label_of(cls, source: SourceTag) -> "Label":
        """Initial label for a content source.

        SECRET (env vars) is high-confidentiality but low-integrity: it must
        not be exposed publicly, but it also must not direct privileged actions.
        """
        table: dict[SourceTag, Label] = {
            SourceTag.SYSTEM: cls(CONFIDENTIALITY_PUBLIC, INTEGRITY_SYSTEM),
            SourceTag.USER: cls(CONFIDENTIALITY_INTERNAL, INTEGRITY_USER),
            SourceTag.TOOL_RESULT: cls(CONFIDENTIALITY_INTERNAL, INTEGRITY_UNTRUSTED),
            SourceTag.REPO_TEXT: cls(CONFIDENTIALITY_PUBLIC, INTEGRITY_UNTRUSTED),
            SourceTag.ENV: cls(CONFIDENTIALITY_SECRET, INTEGRITY_UNTRUSTED),
            SourceTag.DATA: cls(CONFIDENTIALITY_INTERNAL, INTEGRITY_USER),
        }
        return table[source]

    def __str__(self) -> str:  # pragma: no cover - debug aid
        c = ("PUBLIC", "INTERNAL", "SECRET")[self.confidentiality]
        i = ("UNTRUSTED", "USER", "SYSTEM")[self.integrity]
        return f"({c}, {i})"


@dataclass(frozen=True)
class PlanStep:
    """A single step in a Plan.

    `value_source` is a string token that resolves to a SourceTag at evaluation
    time (e.g. "env.SECRET" -> SourceTag.ENV). Cross-step references
    (e.g. "step_1.content") resolve to the joined label of step_1's output.

    `depends_on` is the explicit dependency graph. The IFC joins the labels of
    every step in `depends_on` before evaluating this step's rules. The caller
    is responsible for declaring the chain; the engine does NOT infer it.
    """

    id: str
    action: Literal["read", "write", "execute"]
    path: str | None = None
    value_source: str | None = None
    depends_on: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Plan:
    """A complete plan to be evaluated by the IFC engine."""

    mission: str
    steps: list[PlanStep] = field(default_factory=list)


@dataclass
class PlanVerdict:
    """The result of evaluating a Plan.

    `denied_reasons` maps a step id to the list of reason codes that denied it.
    The reason codes include (non-exhaustive):

    - "integrity_violation": step's effective label is UNTRUSTED but the step
      declares a SYSTEM-intent action (no-upgrade).
    - "confidentiality_violation": step writes a SECRET value to a path that
      is treated as a PUBLIC sink (no-downgrade).
    - "forbidden_path": step's path matches a forbidden_paths glob in the
      Contract.
    - "depends_on_denied_step": at least one step in `depends_on` was denied,
      so this step is also denied by transitivity.
    """

    admitted_steps: list[str] = field(default_factory=list)
    denied_steps: list[str] = field(default_factory=list)
    denied_reasons: dict[str, list[str]] = field(default_factory=dict)
    taint_summary: dict[str, Label] = field(default_factory=dict)
    flagged_by_keyword: list[str] = field(default_factory=list)
    flagged_by_ifc: list[str] = field(default_factory=list)
    cross_iteration_signal: float = 0.0
    receipt: dict[str, str] = field(default_factory=dict)


class PlanRequiredError(Exception):
    """Raised when a non-Plan object is passed where a Plan is required.

    Migration helper for the v0.1 -> v0.2 breaking change: callers that
    used to pass `proposed_files: list[str]` now need a `Plan`; this
    error tells them how to fix it.
    """


# Paths that are treated as PUBLIC sinks for the no-downgrade check. Any
# write of a SECRET value to one of these paths is a confidentiality_violation.
# This is conservative: a caller can refine it via Contract later.
DEFAULT_PUBLIC_SINKS: frozenset[str] = frozenset(
    {
        "incident-report.md",
        "stdout",
        "log.txt",
        "report.md",
    }
)


def _resolve_source(token: str | None) -> SourceTag:
    """Resolve a `value_source` token to a SourceTag.

    Supported forms:
    - "env.VAR"   -> SourceTag.ENV
    - "data.X"    -> SourceTag.DATA
    - "system"    -> SourceTag.SYSTEM
    - "user"      -> SourceTag.USER
    - None or "literal" -> SourceTag.DATA (default)
    Anything else falls back to SourceTag.DATA; the caller should declare
    a more specific source.
    """
    if token is None or token == "literal":
        return SourceTag.DATA
    if token.startswith("env."):
        return SourceTag.ENV
    if token.startswith("data."):
        return SourceTag.DATA
    if token.startswith("system"):
        return SourceTag.SYSTEM
    if token.startswith("user"):
        return SourceTag.USER
    if token.startswith("repo") or token.startswith("step_"):
        return SourceTag.REPO_TEXT
    return SourceTag.DATA


def _classify_read_path(path: str | None) -> SourceTag:
    """Classify a `read` step's target path into a SourceTag.

    evaluate_plan is pure (no filesystem access), so the classification is
    static and based on path conventions only. The default for any path
    we cannot classify cleanly is REPO_TEXT — the conservative choice for
    v0.2, because "reading a file from the repo" is exactly the prompt-
    injection surface AC-IFC-2 is built to catch. Biasing toward UNTRUSTED
    means a `write` that depends on a `read` of an unrecognized path will
    propagate UNTRUSTED, which is the safer direction.

    Recognised conventions (no I/O):

    - Absolute system paths (``/etc/...``, ``/proc/...``, ``/sys/...``,
      ``/dev/...``)         -> SourceTag.SYSTEM
    - Absolute user paths (``/home/...``, ``~/...``, ``~/.config/...``,
      ``$HOME/...``)        -> SourceTag.USER
    - Tool output paths (``/tmp/...``) -> SourceTag.TOOL_RESULT
    - Environment-var paths (``env:VAR``) -> SourceTag.ENV
    - Anything else (relative paths, bare filenames like ``README.md``,
      etc.)                -> SourceTag.REPO_TEXT
    """
    if path is None or path == "":
        # No path declared — treat as repo text (conservative).
        return SourceTag.REPO_TEXT
    # Env-var indirection, e.g. "env:SECRET_FILE" — the read pulls
    # content through an env indirection, so the result carries the
    # ENV tag (SECRET in confidentiality, UNTRUSTED in integrity).
    if path.startswith("env:") or path.startswith("env."):
        return SourceTag.ENV
    # Absolute system paths. SYSTEM integrity (fully trusted) on read is
    # correct: kernel-reported state is not an injection vector.
    if path.startswith(("/etc/", "/proc/", "/sys/", "/dev/")):
        return SourceTag.SYSTEM
    # Absolute user-owned paths. USER integrity matches the v0.1 model.
    if path.startswith(("/home/", "~/", "$HOME/")) or path == "~":
        return SourceTag.USER
    # Tool output staging. UNTRUSTED integrity because tool output can
    # contain attacker-controlled content.
    if path.startswith("/tmp/"):  # nosec B108 — string classification only, no filesystem access
        return SourceTag.TOOL_RESULT
    # Default: relative path or bare filename inside the repo. This is
    # the prompt-injection surface — UNTRUSTED in integrity.
    return SourceTag.REPO_TEXT


def _step_initial_label(step: PlanStep) -> Label:
    """Initial label of a step, before joining with dependencies.

    `read` steps take the label of their target path (classified by
    ``_classify_read_path``). A read of repo text produces an UNTRUSTED
    integrity label, so a `write` that `depends_on` such a read inherits
    UNTRUSTED through the dependency join — which is the entire point
    of AC-IFC-2 (taint propagation via depends_on).

    `write`/`execute` steps take the label of their value_source.
    """
    if step.action == "read":
        return Label.label_of(_classify_read_path(step.path))
    return Label.label_of(_resolve_source(step.value_source))


def evaluate_plan(
    plan: Plan,
    forbidden_paths: list[str] | None = None,
    public_sinks: frozenset[str] | None = None,
) -> PlanVerdict:
    """Evaluate a Plan and return a `PlanVerdict`.

    Algorithm (per plan.md §3):
    1. Compute each step's effective label = join(initial_label, labels of
       each `depends_on` step). Cycles in `depends_on` are tolerated by
       evaluating in declaration order (idempotent if a cycle exists, since
       a step that depends on itself already includes its own initial label).
    2. Apply IFC rules:
       - `integrity_violation`: step.action in {"write", "execute"} AND
         step.value_source is UNTRUSTED-integrity (i.e. originates from
         REPO_TEXT, TOOL_RESULT, or ENV). A read step is never denied on
         integrity grounds.
       - `confidentiality_violation`: step writes a SECRET value
         (confidentiality == SECRET) to a path in `public_sinks`.
       - `forbidden_path`: step.path matches a glob in `forbidden_paths`.
    3. Cascade: if step S is denied and S appears in any other step's
       `depends_on`, that dependent step is also denied with
       reason "depends_on_denied_step".
    4. Record admitted/denied steps, taint_summary (path -> final label),
       and receipt.

    The IFC reports BOTH axes of the dual-lattice separately; see AC-IFC-1
    test 3 in the spec.
    """
    if not isinstance(plan, Plan):  # type: ignore[unidiomatic-typecheck]
        raise PlanRequiredError(
            "run_admission requires a Plan; pass an instance of "
            "agent_harness_defense.ifc.Plan. The v0.1 `proposed_files` "
            "parameter has been removed; see CHANGELOG.md v0.2.0."
        )

    verdict = PlanVerdict()
    forbidden_paths = forbidden_paths or []
    public_sinks = public_sinks or DEFAULT_PUBLIC_SINKS

    # Map of step id -> its effective label (after joining dependencies).
    step_label: dict[str, Label] = {}
    # Map of step id -> list of reason codes (denial reasons).
    reasons: dict[str, list[str]] = {}

    # Pass 1: compute effective labels and apply per-step rules.
    for step in plan.steps:
        eff = _step_initial_label(step)
        for dep_id in step.depends_on:
            if dep_id in step_label:
                eff = eff.join(step_label[dep_id])
            else:
                # Unknown dependency: treat as REPO_TEXT (conservative).
                eff = eff.join(Label.label_of(SourceTag.REPO_TEXT))
        step_label[step.id] = eff
        denied_reasons: list[str] = []

        # Rule: integrity_violation (no-upgrade).
        # A write/execute step whose value_source is UNTRUSTED tries to drive
        # an action; deny with integrity_violation.
        if step.action in ("write", "execute") and eff.integrity == INTEGRITY_UNTRUSTED:
            denied_reasons.append("integrity_violation")

        # Rule: confidentiality_violation (no-downgrade).
        # A write of a SECRET value to a public sink.
        if (
            step.action in ("write",)
            and eff.confidentiality == CONFIDENTIALITY_SECRET
            and step.path is not None
            and step.path in public_sinks
        ):
            denied_reasons.append("confidentiality_violation")

        # Rule: forbidden_path.
        if step.path is not None and forbidden_paths:
            if any(_glob_match(fp, step.path) for fp in forbidden_paths):
                denied_reasons.append("forbidden_path")

        if denied_reasons:
            reasons[step.id] = denied_reasons
        verdict.taint_summary[step.path or f"<{step.id}>"] = eff

    # Pass 2: cascade (depends_on_denied_step).
    changed = True
    while changed:
        changed = False
        for step in plan.steps:
            if step.id in reasons:
                continue
            for dep_id in step.depends_on:
                if dep_id in reasons:
                    reasons[step.id] = reasons.get(step.id, []) + ["depends_on_denied_step"]
                    changed = True
                    break

    # Final split into admitted/denied.
    for step in plan.steps:
        if step.id in reasons:
            verdict.denied_steps.append(step.id)
        else:
            verdict.admitted_steps.append(step.id)
    verdict.denied_reasons = {sid: rs for sid, rs in reasons.items() if rs}
    # Flag denied paths as "flagged_by_ifc" for diagnostic visibility.
    verdict.flagged_by_ifc = list(verdict.denied_steps)
    return verdict


def plan_from_yaml(text: str) -> Plan:
    """Parse a Plan from a YAML string.

    Schema:
        mission: <str>
        steps:
          - id: <str>
            action: read|write|execute
            path: <str>?
            value_source: <str>?
            depends_on: [<str>, ...]?
    """
    data: Any = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PlanRequiredError("Plan YAML must be a mapping at the top level")
    mission = data.get("mission", "")
    raw_steps = data.get("steps", [])
    if not isinstance(raw_steps, list):
        raise PlanRequiredError("Plan YAML 'steps' must be a list")
    steps: list[PlanStep] = []
    for raw in raw_steps:
        if not isinstance(raw, dict):
            raise PlanRequiredError("Each step must be a mapping")
        steps.append(
            PlanStep(
                id=str(raw["id"]),
                action=raw["action"],
                path=raw.get("path"),
                value_source=raw.get("value_source"),
                depends_on=list(raw.get("depends_on", []) or []),
            )
        )
    return Plan(mission=mission, steps=steps)
