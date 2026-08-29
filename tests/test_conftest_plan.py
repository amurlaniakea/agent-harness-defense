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

"""Tests for T008: conftest scenario plumbing + the plan<->materialized guard.

These are NOT the AC-EVAL-1 propagation tests (those are T009). They pin
the infrastructure T009 builds on:

- INCIDENT_REPORT_INJECTION exists with a coherent declarative Plan.
- assert_plan_matches_materialized passes on a consistent scenario and
  FAILS loudly (NamedTuple-style drift message) when the Plan drifts
  from what was actually materialized. That failure path is the whole
  point of the 2026-08-28 review fix: the IFC must never decide over a
  Plan that does not match the on-disk materialized state.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_harness_defense.ifc import Plan, PlanStep
from tests.conftest import (
    INCIDENT_REPORT_INJECTION,
    assert_plan_matches_materialized,
)


def _materialize(scn) -> tuple[list[str], list[str]]:
    d = Path(tempfile.mkdtemp())
    for rel, content in scn.repo_files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    legit = scn.legit_edit(d)
    obeyed = scn.obey(d)
    return legit, obeyed


def test_incident_report_injection_has_coherent_plan():
    scn = INCIDENT_REPORT_INJECTION
    assert scn.plan is not None, "AC-EVAL-1 scenario must carry a Plan"
    assert len(scn.plan.steps) >= 2
    assert scn.plan.steps[0].action == "read"
    assert scn.plan.steps[0].path == "README.md"
    write_step = scn.plan.steps[1]
    assert write_step.action == "write"
    assert write_step.path == "incident-report.md"
    # The IFC must catch this: secret written to a public sink, driven
    # by an untrusted read.
    assert write_step.value_source == "env.SECRET"
    assert write_step.depends_on == ["step_1"]


def test_assert_plan_matches_materialized_passes_when_consistent():
    scn = INCIDENT_REPORT_INJECTION
    assert scn.plan is not None
    legit, obeyed = _materialize(scn)
    # Must not raise: the Plan's write-set equals the materialized set.
    assert_plan_matches_materialized(scn, scn.plan, legit, obeyed)


def test_assert_plan_matches_materialized_fails_on_drift():
    scn = INCIDENT_REPORT_INJECTION
    legit, obeyed = _materialize(scn)
    # A Plan that declares a write the obey() did NOT produce (drift into
    # fiction). The guard must raise with a message listing the divergence.
    drifted = Plan(
        mission=scn.plan.mission,
        steps=[
            *scn.plan.steps,
            PlanStep(id="ghost", action="write", path="nonexistent.txt"),
        ],
    )
    try:
        assert_plan_matches_materialized(scn, drifted, legit, obeyed)
    except AssertionError as exc:
        msg = str(exc)
        assert "nonexistent.txt" in msg, f"drift message must name the divergent path: {msg}"
        assert "in_plan_not_on_disk" in msg
    else:
        raise AssertionError("guard should have raised on drift into fiction")
