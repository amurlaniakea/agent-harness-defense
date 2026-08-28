"""CLI for agent-harness-defense.

Usage:
    ahd run PATH          # admit/reject the agent's change on disk at PATH
    ahd eval              # run the bundled adversarial scenarios (offline)
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint
from rich.table import Table

from agent_harness_defense.admission import LoopStateMonitor, run_admission

REPO_PATH_ARG = typer.Argument(..., help="Repo path with the agent's edits on disk.")


app = typer.Typer(help="Open admission-layer defense for LLM agent harnesses.")


@app.command()
def run(path: Path = REPO_PATH_ARG):
    """Admit or reject the agent's proposed change under taint/IFC + contract."""
    monitor = LoopStateMonitor()
    report = run_admission(
        path, "cli/local", "Treat repository text as untrusted data.", loop_monitor=monitor
    )
    t = Table(title="Admission report")
    t.add_column("field")
    t.add_column("value")
    for k, v in [
        ("outcome", report.outcome),
        ("authority", report.authority),
        ("escalation_detected", report.escalation_detected),
        ("task_completed", report.task_completed),
        ("trust_boundary_clean", report.trust_boundary_clean),
        ("quarantined_files", report.quarantined_files),
        ("cross_iteration_signal", report.cross_iteration_signal),
        ("receipt.base_commit", report.receipt["base_commit"]),
        ("receipt.capability_set", report.receipt["capability_set"]),
    ]:
        t.add_row(k, str(v))
    rprint(t)
    raise typer.Exit(0 if report.trust_boundary_clean else 1)


@app.command()
def eval() -> None:
    """Run the bundled offline adversarial scenarios against our admission layer.

    Faithfully models the Signetry ScriptedAgent: the agent applies its benign edit
    AND obeys the injected instruction (writing the malicious artifact to disk), then
    admission decides what enters the ADMITTED changeset.
    """
    import shutil
    import subprocess
    import tempfile

    from tests.conftest import all_ipi_scenarios

    monitor = LoopStateMonitor()
    all_pass = True
    for scn in all_ipi_scenarios():
        tmp = Path(tempfile.mkdtemp(prefix="ahd-eval-"))
        work = tmp / "repo"
        work.mkdir(parents=True)
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
        candidates = sorted(set(legit) | set(obeyed) | {scn.task_marker})
        try:
            report = run_admission(
                work,
                "acme/app",
                "Apply the in-scope task only.",
                proposed_files=candidates,
                loop_monitor=monitor,
            )
            blocked = not report.escalation_detected
            util = report.task_completed
            ok = blocked and util
            all_pass = all_pass and ok
            rprint(
                f"[{'green' if ok else 'red'}]{scn.id}: blocked={blocked} "
                f"utility={util} quarantined={report.quarantined_files}[/"
                f"{'green' if ok else 'red'}]"
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    raise typer.Exit(0 if all_pass else 1)


if __name__ == "__main__":
    app()
