# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martínez
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

"""Regression guard: prove the IPI eval is NOT vacuous (adapted to v0.2, T012).

If the admission layer stopped quarantining forbidden artifacts (e.g. a future
change that admits everything), the eval criterion must FAIL. We simulate that
regression by monkey-patching `evaluate_plan` to return a verdict that admits
every step (a broken IFC), and assert the criterion flags it: the attack step
ends up in `admitted_steps` (not `denied_steps`) and `cross_iteration_signal`
is still available for the monitor second-signal.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import agent_harness_defense.admission as _adm
from agent_harness_defense.admission import run_admission
from agent_harness_defense.ifc import PlanVerdict, evaluate_plan
from tests.conftest import README_INJECTION


def _materialize(scn, work: Path) -> tuple[list[str], list[str]]:
    for rel, content in scn.repo_files.items():
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.email", "eval@ahd"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.name", "ahd"], cwd=work, check=True)
    subprocess.run(["git", "add", "-A"], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=work, check=True)
    legit = scn.legit_edit(work)
    obeyed = scn.obey(work)
    return legit, obeyed


def _fake_admit_everything(*args, **kwargs) -> PlanVerdict:
    """Monkey-patched `evaluate_plan`: a BROKEN IFC that admits every step."""
    real = evaluate_plan(*args, **kwargs)
    # Admit everything: move all denied steps back into admitted.
    broken = PlanVerdict()
    broken.admitted_steps = list(real.admitted_steps) + list(real.denied_steps)
    broken.denied_steps = []
    broken.denied_reasons = {}
    broken.taint_summary = dict(real.taint_summary)
    broken.tainted_paths = []
    broken.flagged_by_keyword = list(real.flagged_by_keyword)
    broken.flagged_by_ifc = []
    broken.cross_iteration_signal = real.cross_iteration_signal
    broken.receipt = dict(real.receipt)
    return broken


def test_eval_detects_a_broken_defense():
    scn = README_INJECTION
    tmp = Path(tempfile.mkdtemp(prefix="ahd-regr-"))
    work = tmp / "repo"
    work.mkdir(parents=True)
    try:
        legit, obeyed = _materialize(scn, work)
        assert scn.plan is not None
        # Teeth: the Plan must match what was materialized.
        from tests.conftest import assert_plan_matches_materialized

        assert_plan_matches_materialized(scn, scn.plan, legit, obeyed)

        # Simulate a broken IFC that admits everything.
        with _patch_evaluate_plan(_fake_admit_everything):
            verdict = run_admission(work, label="acme/app", plan=scn.plan)

        attack_step_ids = {
            step.id for step in scn.plan.steps if step.path in set(scn.attack_markers)
        }
        # The broken defense admits the attack step -> the eval criterion
        # must observe it as ADMITTED (not denied). This proves the
        # criterion is non-vacuous: it would catch a regression.
        attack_in_admitted = bool(attack_step_ids & set(verdict.admitted_steps))
        assert attack_in_admitted is True, (
            "regression guard misconfigured: attack not admitted by fake"
        )
        assert verdict.denied_steps == [], (
            f"broken defense must leave denied_steps empty; got {verdict.denied_steps}"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# Helpers to monkey-patch admission.evaluate_plan without import gymnastics.
class _patch_evaluate_plan:
    """Minimal context-manager monkey-patch for admission.evaluate_plan."""

    def __init__(self, replacement):
        self.replacement = replacement
        self.original = None

    def __enter__(self):
        self.original = _adm.evaluate_plan
        _adm.evaluate_plan = self.replacement
        return self

    def __exit__(self, *exc):
        _adm.evaluate_plan = self.original
        return False
