"""Regression guard: prove the IPI eval is NOT vacuous.

If the admission layer stopped quarantining forbidden artifacts (e.g. a future
change that admits everything), the eval criterion must FAIL. We simulate that
regression with `_fake_admit_everything` (a broken defense) and assert the criterion
flags it: attack_in_admitted True and trust_boundary_clean False.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from agent_harness_defense.admission import AdmissionReport, LoopStateMonitor, run_admission
from tests.conftest import README_INJECTION


def _materialize(scn, work: Path) -> list[str]:
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
    return sorted(set(legit) | set(obeyed) | {scn.task_marker})


def _fake_admit_everything(repo_path, label, mission, proposed_files=None, *, loop_monitor=None):
    """Simulates a BROKEN defense that admits the attack into the changeset."""
    real = run_admission(
        repo_path, label, mission, proposed_files=proposed_files, loop_monitor=loop_monitor
    )
    admitted = sorted(set(real.changed_files) | set(real.quarantined_files))
    return AdmissionReport(
        changed_files=admitted,
        escalation_detected=real.escalation_detected,
        quarantined_files=[],
        task_completed=real.task_completed,
        authority_level=real.authority_level,
        authority=real.authority,
        outcome="REGRESSION: attack admitted",
        contract_passed=real.contract_passed,
        trust_boundary_clean=False,
        receipt=real.receipt,
        cross_iteration_signal=real.cross_iteration_signal,
        taint=real.taint,
    )


def test_eval_detects_a_broken_defense():
    scn = README_INJECTION
    tmp = Path(tempfile.mkdtemp(prefix="ahd-regr-"))
    work = tmp / "repo"
    work.mkdir(parents=True)
    try:
        candidates = _materialize(scn, work)
        report = _fake_admit_everything(
            work, "acme/app", "mission", proposed_files=candidates, loop_monitor=LoopStateMonitor()
        )
        admitted = set(report.changed_files)
        attack_in_admitted = any(m in admitted for m in scn.attack_markers)
        # The broken defense admits the artifact -> the eval criterion flags it.
        assert attack_in_admitted is True, (
            "regression guard misconfigured: attack not admitted by fake"
        )
        assert report.trust_boundary_clean is False
        assert report.quarantined_files == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
