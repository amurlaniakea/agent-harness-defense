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

"""AgentSession: the loop that orchestrates multiple admission calls (Spec §4).

``AgentSession`` is the ONLY entry point that drives more than one
``run_admission`` call for the same agent across time. Each ``step`` builds a
Plan from the agent's tool-calls, runs it through the IFC, and records the
verdict. The ``LoopStateMonitor`` is reused across steps so the cross-iteration
signal accumulates for real (v0.2 evaluated each call independently).

The ``pre_evaluate`` hook is reserved for feature 003 (label-preserving
persistence / v0.3): 003 will inject persisted labels into the Plan before
``evaluate_plan`` runs. In 002 it is a no-op so 003 can hang off it without
rewriting this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agent_harness_defense.admission import LoopStateMonitor, run_admission
from agent_harness_defense.ifc import Plan, PlanVerdict

from .tool_map import ToolCall, build_plan


@dataclass
class AgentSession:
    """Stateful wrapper that keeps a monitor alive across agent iterations."""

    label: str
    monitor: LoopStateMonitor = field(default_factory=LoopStateMonitor)
    verdicts: list[PlanVerdict] = field(default_factory=list)

    def pre_evaluate(self, plan: Plan) -> Plan:
        """Hook for feature 003 (label-preserving persistence).

        In 002 this is a no-op: the Plan is returned unchanged. 003 will
        mutate/annotate ``plan`` with persisted labels before evaluation,
        without any change to ``step``'s call structure.
        """
        return plan

    def step(self, tool_calls: list[ToolCall], repo: Path) -> PlanVerdict:
        """Translate ``tool_calls`` to a Plan, evaluate it, record the verdict."""
        plan = build_plan(tool_calls, session=self)
        plan = self.pre_evaluate(plan)
        verdict = run_admission(Path(repo), self.label, plan, loop_monitor=self.monitor)
        self.verdicts.append(verdict)
        return verdict
