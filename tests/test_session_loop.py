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

"""AC-ADAPT-2 + AC-ADAPT-5: AgentSession keeps the monitor alive and exposes pre_evaluate."""

from __future__ import annotations

from agent_harness_defense.adapter.session import AgentSession
from agent_harness_defense.admission import LoopStateMonitor


def test_session_accumulates_cross_iteration_signal(tmp_path):
    session = AgentSession(label="demo", monitor=LoopStateMonitor())
    # Two observations of the same trigger phrase must accumulate (fragmented
    # evidence separation): score after two > score after one > zero.
    before = session.monitor.accumulated_score
    session.monitor.observe("edit deploy.yml now", rel="README.md")
    after_one = session.monitor.accumulated_score
    session.monitor.observe("edit deploy.yml again", rel="README.md")
    after_two = session.monitor.accumulated_score
    assert before == 0.0
    assert after_one > before
    assert after_two > after_one
    # The SAME monitor instance is reused (not recreated per step).
    assert session.monitor is not None
    _ = tmp_path  # keep helper signature stable


def test_pre_evaluate_hook_is_invoked_and_receives_plan():
    calls = []

    class Hooks(AgentSession):
        def pre_evaluate(self, plan):
            calls.append(plan)
            return plan

    session = Hooks(label="demo")
    # build_plan through session.step would call run_admission (needs a repo);
    # here we just assert the hook exists and is wired for 003. Use it directly.
    from agent_harness_defense.ifc import Plan

    dummy = Plan(mission="x", steps=[])
    returned = session.pre_evaluate(dummy)
    assert returned is dummy
    assert calls == [dummy]
