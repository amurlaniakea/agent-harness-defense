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

"""AC-ADAPT-1: deterministic tool_call -> PlanStep mapping (Spec §2, §2.1)."""

from __future__ import annotations

from agent_harness_defense.adapter.tool_map import ToolCall, build_plan
from agent_harness_defense.admission import LoopStateMonitor
from agent_harness_defense.ifc import evaluate_plan


def _session():
    return type("S", (), {"label": "x", "monitor": LoopStateMonitor()})()


def test_read_file_maps_to_read_step():
    plan = build_plan([ToolCall(name="read_file", args={"path": "README.md"})], _session())
    step = plan.steps[0]
    assert step.action == "read"
    assert step.path == "README.md"
    assert step.value_source is None
    assert step.depends_on == []


def test_write_file_literal_maps_to_data():
    plan = build_plan(
        [ToolCall(name="write_file", args={"path": "out.md", "content": "hello"})],
        _session(),
    )
    step = plan.steps[0]
    assert step.action == "write"
    assert step.value_source == "literal"  # agent's own data (USER/INTERNAL)


def test_write_file_env_secret_maps_to_env_source():
    plan = build_plan(
        [
            ToolCall(
                name="write_file",
                args={"path": "incident-report.md", "content_ref": "env.SECRET"},
            )
        ],
        _session(),
    )
    step = plan.steps[0]
    assert step.action == "write"
    assert step.value_source == "env.SECRET"


def test_bash_maps_to_execute_repo_cmd_fail_closed():
    """§2.1: bash is fail-closed (UNTRUSTED), so the IFC denies it."""
    plan = build_plan(
        [ToolCall(name="bash", args={"command": "echo $SECRET > incident-report.md"})],
        _session(),
    )
    step = plan.steps[0]
    assert step.action == "execute"
    assert step.value_source == "repo.cmd"
    verdict = evaluate_plan(plan)
    assert step.id in verdict.denied_steps
    assert "integrity_violation" in verdict.denied_reasons[step.id]


def test_read_then_write_declared_dep_propagates_untrusted():
    """The realistic teeth, HONEST version (C1): the agent must DECLARE it uses
    the read content. Only then does the untrusted README taint the write.

    Without an explicit content_ref the adapter does NOT infer the dependency
    (would otherwise taint every later write — the false-positive avalanche that
    the 2026-08-29 audit caught). A non-declared read->write is a (documented)
    false negative, not a denial.
    """
    # Malicious-but-declared: agent writes the README's content into the report.
    plan = build_plan(
        [
            ToolCall(name="read_file", args={"path": "README.md"}),
            ToolCall(
                name="write_file",
                args={
                    "path": "incident-report.md",
                    "content_ref": "step_1.content",
                    "content": "x",
                },
            ),
        ],
        _session(),
    )
    assert plan.steps[1].depends_on == ["step_1"]
    verdict = evaluate_plan(plan)
    assert "step_2" in verdict.denied_steps
    assert "integrity_violation" in verdict.denied_reasons["step_2"]


def test_read_then_unrelated_write_is_not_denied():
    """C1 false-negative guard: an undeclared read->write does NOT taint.

    This is the case the 2026-08-29 audit proved was broken before the fix
    (every later write got denied). Now it must be admitted — the adapter does
    not infer dependencies the agent never declared.
    """
    plan = build_plan(
        [
            ToolCall(name="read_file", args={"path": "README.md"}),
            ToolCall(name="write_file", args={"path": "incident-report.md", "content": "x"}),
        ],
        _session(),
    )
    assert plan.steps[1].depends_on == []  # no implicit chain
    verdict = evaluate_plan(plan)
    assert "step_2" in verdict.admitted_steps
    assert "step_2" not in verdict.denied_steps


def test_adapter_false_positive_scale_read_then_many_unrelated_writes():
    """AC-ADAPT-FP: the missing guardrail from the 2026-08-29 audit.

    A completely normal session — read the README, then write 5 source files
    with no relation to it — must NOT have any write denied. Before the fix this
    denied all 5 (false-positive avalanche). This test locks the corrected
    behaviour so a future change cannot silently reintroduce it.
    """
    calls = [ToolCall(name="read_file", args={"path": "README.md"})]
    for i in range(1, 6):
        calls.append(
            ToolCall(name="write_file", args={"path": f"src/module_{i}.py", "content": f"x={i}"})
        )
    plan = build_plan(calls, _session())
    # Sanity: no step depends on the read (no declared chain).
    assert all(s.depends_on == [] for s in plan.steps), plan.steps
    verdict = evaluate_plan(plan)
    assert verdict.denied_steps == [], f"false-positive avalanche: {verdict.denied_reasons}"
    assert set(verdict.admitted_steps) == {s.id for s in plan.steps}
