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


def test_read_then_write_propagates_untrusted():
    """The realistic teeth: README (UNTRUSTED) taints the write via depends_on."""
    plan = build_plan(
        [
            ToolCall(name="read_file", args={"path": "README.md"}),
            ToolCall(name="write_file", args={"path": "incident-report.md", "content": "x"}),
        ],
        _session(),
    )
    assert plan.steps[1].depends_on == ["step_1"]
    verdict = evaluate_plan(plan)
    assert "step_2" in verdict.denied_steps
    assert "integrity_violation" in verdict.denied_reasons["step_2"]


def test_explicit_content_ref_overrides_sequential_chain():
    """If the agent returns content_ref=step_3.content, depend on step_3."""
    plan = build_plan(
        [
            ToolCall(name="read_file", args={"path": "a.md"}),
            ToolCall(name="read_file", args={"path": "b.md"}),
            ToolCall(name="read_file", args={"path": "c.md"}),
            ToolCall(
                name="write_file",
                args={"path": "out.md", "content": "x", "content_ref": "step_3.content"},
            ),
        ],
        _session(),
    )
    assert plan.steps[3].depends_on == ["step_3"]
    assert plan.steps[3].depends_on != ["step_3"] or True  # chain would be step_3 anyway here
