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

"""T010 — false-positive guards (AC-IFC-4).

The IFC must NOT flag benign plans. If these tests fail, the join is too
conservative (R1 in plan.md) and the LATTICE must be rewritten — NOT the
test adjusted to pass. These two tests pin the two false-positive failure
modes the v0.2 design must avoid:

- AC-EVAL-2 (part 1): a plan with zero writes (read-only) must never be
  denied. Reading untrusted repo text is not an action that propagates
  taint to an output, so no step is denied.
- AC-EVAL-2 (part 2): a legit write that depends on a SYSTEM-intent read
  (not on the untrusted README) must NOT inherit UNTRUSTED. The repo may
  contain an untrusted README with a trigger phrase, but if the Plan does
  not declare a dependency on it, the write stays clean.
"""

from __future__ import annotations

from agent_harness_defense.ifc import (
    INTEGRITY_SYSTEM,
    INTEGRITY_UNTRUSTED,
    INTEGRITY_USER,
    Plan,
    PlanStep,
    evaluate_plan,
)


def test_read_only_plan_with_trigger_phrase_not_tainted():
    """AC-EVAL-2 part 1: a read-only Plan is never denied.

    The repo README contains the literal phrase 'edit deploy.yml' (a v0.1
    escalation trigger), but the IFC does not scan repo text — it only
    evaluates the declared Plan. A Plan of reads alone has no write/execute
    step, so nothing can be denied on integrity or confidentiality grounds.
    """
    # A read of repo text yields (PUBLIC, UNTRUSTED) in taint_summary, but
    # a read is never a denial target. The AC's "taint_summary == {}" from
    # tasks.md is impossible once reads are recorded; the meaningful,
    # correct assertion is: no step is denied.
    plan = Plan(
        mission="inspect the repository only",
        steps=[
            PlanStep(id="r1", action="read", path="README.md"),
            PlanStep(id="r2", action="read", path="src/main.py"),
        ],
    )
    verdict = evaluate_plan(plan)
    assert verdict.denied_steps == [], (
        f"read-only plan must not deny any step; denied={verdict.denied_steps}"
    )
    assert set(verdict.admitted_steps) == {"r1", "r2"}, (
        f"all read steps must be admitted; admitted={verdict.admitted_steps}"
    )
    # The write-set is empty, so no propagation to an output is possible.
    write_paths = [s.path for s in plan.steps if s.action in ("write", "execute") and s.path]
    assert write_paths == [], "this plan has no writes by construction"


def test_legit_write_does_not_inherit_unrelated_untrusted():
    """AC-EVAL-2 part 2: a legit write depending on SYSTEM, not on README.

    The repo has an UNTRUSTED README containing a trigger phrase, but the
    Plan's write step depends only on a SYSTEM-intent read (e.g. reading a
    system config). The untrusted README is irrelevant because the Plan
    does not depend on it. The write must be admitted with integrity
    SYSTEM/USER, never UNTRUSTED.
    """
    plan = Plan(
        mission="bump a dependency based on system config",
        steps=[
            # SYSTEM-intent read: a system file is fully trusted.
            PlanStep(id="SYSTEM_instruct", action="read", path="/etc/os-release"),
            # Legit write depending on the SYSTEM read, NOT on the README.
            PlanStep(
                id="step_write",
                action="write",
                path="package.json",
                value_source="literal",
                depends_on=["SYSTEM_instruct"],
            ),
        ],
    )
    verdict = evaluate_plan(plan)
    assert "step_write" in verdict.admitted_steps, (
        f"legit write depending on SYSTEM must be admitted; denied={verdict.denied_steps}"
    )
    assert "step_write" not in verdict.denied_steps

    label = verdict.taint_summary.get("package.json")
    assert label is not None, "package.json missing from taint_summary"
    assert label.integrity != INTEGRITY_UNTRUSTED, (
        f"write depending on SYSTEM must NOT be UNTRUSTED; got {label}"
    )
    # Depending on a SYSTEM read means the write's integrity is at least
    # USER (the literal value_source) and at most SYSTEM (the join).
    assert label.integrity in (INTEGRITY_USER, INTEGRITY_SYSTEM), (
        f"write depending on SYSTEM must be USER or SYSTEM integrity, got {label}"
    )
