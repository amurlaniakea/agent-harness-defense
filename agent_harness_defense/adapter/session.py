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

Feature 003 (label-preserving persistence / v0.3): after every ``step`` the
session records any tainted artifact in ``persisted_artifacts`` and re-injects
those labels into the next ``step`` via ``persisted_labels``. The artifact
*content* is never stored — only its IFC ``Label`` plus a content-free hash
``summary`` (Spec 003 §2, C1 honest scope).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agent_harness_defense.admission import LoopStateMonitor, run_admission
from agent_harness_defense.ifc import Plan, PlanVerdict

from .persistence import PersistedArtifact, persisted_labels_from, record_taint
from .tool_map import ToolCall, build_plan


@dataclass
class AgentSession:
    """Stateful wrapper that keeps monitor + persisted labels across iterations."""

    label: str
    monitor: LoopStateMonitor = field(default_factory=LoopStateMonitor)
    verdicts: list[PlanVerdict] = field(default_factory=list)
    # Feature 003: tainted artifacts remembered across iterations. Only the IFC
    # Label is stored (never the artifact content); see persistence.py.
    persisted_artifacts: list[PersistedArtifact] = field(default_factory=list)

    def pre_evaluate(self, plan: Plan) -> Plan:
        """Hook reserved for callers wanting to transform the Plan pre-evaluation.

        Feature 003 does NOT need it for label injection (that goes through
        ``persisted_labels`` in ``step``), but the hook stays available so a
        caller can add plan-level transforms without rewriting this module.
        """
        return plan

    def step(self, tool_calls: list[ToolCall], repo: Path) -> PlanVerdict:
        """Translate ``tool_calls`` to a Plan, evaluate it, record the verdict.

        The persisted labels from previous iterations are re-injected so a taint
        remembered in iteration N survives into iteration N+1 (Spec 003 §4).
        """
        plan = build_plan(tool_calls, session=self)
        plan = self.pre_evaluate(plan)
        iteration = len(self.verdicts) + 1
        verdict = run_admission(
            Path(repo),
            self.label,
            plan,
            loop_monitor=self.monitor,
            persisted_labels=persisted_labels_from(self),
        )
        self.verdicts.append(verdict)
        # Remember any tainted artifact for future iterations (idempotent per path).
        record_taint(
            self,
            verdict.tainted_paths,
            verdict.taint_summary,
            verdict.denied_reasons,
            iteration,
        )
        return verdict
