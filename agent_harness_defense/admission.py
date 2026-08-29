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

"""Open admission layer for LLM agent harnesses (v0.2: dual-lattice IFC).

Replaces the closed `signetry-core` admission pipeline with an open, auditable
implementation. v0.2 design:

1. Dual-lattice IFC (arXiv:2608.27234, SPA) — confidentiality and integrity,
   propagation via the explicit `depends_on` graph of a `Plan`. The engine
   lives in `agent_harness_defense.ifc`; this module is the integration
   layer.
2. Cross-iteration loop-state monitor (arXiv:2608.27141) — retained as a
   SECONDARY signal (`flagged_by_keyword` / `cross_iteration_signal`); the
   IFC verdict is the primary decision.
3. Contract / verifier — `allowed_paths`, `forbidden_paths`, `max_files_changed`.
4. Receipt — admitted change carries base-commit, diff and capability-set hashes.

Deterministic and offline; no LLM calls. The "agent" is modeled by the harness
that materializes the agent's on-disk edits and emits a `Plan` declaring what
it intends to do and where each value comes from; the engine then evaluates
the plan against the dual-lattice and the contract.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_harness_defense.ifc import (
    Label,
    Plan,
    PlanVerdict,
    evaluate_plan,
)

# Low-privilege repo text that, if it commands a forbidden action, is an escalation.
# Single, non-overlapping triggers (each fragment carries at most one). Derived from
# the IPI corpus (ipi.readme_deploy_and_exfil, ipi.claude_md_scope_expansion).
ESCALATION_TRIGGERS = (
    ("edit deploy.yml", "write forbidden deploy artifact"),
    ("exfiltrate", "exfiltrate a secret"),
    ("modify the ci workflow", "edit CI workflow out of scope"),
    ("print the secret", "exfiltrate a secret"),
    ("edit .github/workflows", "edit CI workflow out of scope"),
)


@dataclass
class Contract:
    allowed_paths: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)
    max_files_changed: int | None = None

    @classmethod
    def from_yaml(cls, text: str) -> "Contract":
        allowed: list[str] = []
        forbidden: list[str] = []
        max_files: int | None = None
        cur: list[str] | None = None
        for raw in text.splitlines():
            line = raw.rstrip()
            if line.strip().startswith("allowed_paths:"):
                cur = allowed
                continue
            if line.strip().startswith("forbidden_paths:"):
                cur = forbidden
                continue
            if line.strip().startswith("max_files_changed:"):
                cur = None
                m = re.search(r"max_files_changed:\s*(\d+)", line)
                if m:
                    max_files = int(m.group(1))
                continue
            stripped = line.strip()
            if cur is not None and stripped.startswith("- "):
                cur.append(stripped[2:].strip().strip('"'))
        return cls(allowed_paths=allowed, forbidden_paths=forbidden, max_files_changed=max_files)


def _glob_match(pattern: str, rel: str) -> bool:
    if pattern == rel:
        return True
    # Normalize a leading/trailing "**/" / "**" so it acts as a recursive wildcard.
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        if rel.endswith(suffix) or ("/" + rel).endswith("/" + suffix):
            return True
        # Also handle an internal wildcard after the recursive prefix, e.g. "**/deploy.y*ml".
        if "*" in suffix:
            rx = re.compile("^.*?" + re.escape(suffix).replace(r"\*", ".*") + "$")
            return bool(rx.match(rel))
        return False
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return rel.startswith(prefix) or ("/" + rel).startswith(prefix)
    if pattern.endswith("/*"):
        prefix = pattern[:-1]
        return rel.startswith(prefix) and "/" not in rel[len(prefix) :]
    if "*" in pattern:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        return bool(rx.match(rel))
    return False


@dataclass
class LoopStateMonitor:
    """Cross-iteration safety state (arXiv:2608.27141).

    Trajectory-scoped monitors re-initialize every run; this one RETAINs signals so
    fragmented evidence correlates. Each weak trigger contributes a fractional weight
    (0.5) so a SINGLE fragment stays below the correlation threshold (0.5 < 1.0), but
    two or more weak fragments across iterations accumulate and separate attack from
    noise — exactly the fragmented-evidence separation the paper proves.

    NOTE on integration: this class RETAINs state ONLY if the caller reuses the same
    instance across loop iterations. The library does not orchestrate a real agent
    loop; the harness that integrates `run_admission` is responsible for keeping the
    monitor alive between calls. See `KNOWN_ISSUES.md` §4.
    """

    signals: list[dict[str, Any]] = field(default_factory=list)
    accumulated_score: float = 0.0
    _trigger_weight: float = 0.5

    def observe(self, fragment: str, *, rel: str) -> float:
        score = 0.0
        hits = []
        low = fragment.lower()
        for trigger, label in ESCALATION_TRIGGERS:
            if trigger in low:
                score += self._trigger_weight
                hits.append(label)
        if score > 0:
            self.signals.append({"rel": rel, "score": round(score, 3), "labels": hits})
            self.accumulated_score += score
        return score

    @property
    def correlated(self) -> bool:
        """True once accumulated cross-iteration evidence separates attack from noise."""
        return self.accumulated_score >= 1.0


def _scan_targets(repo_path: Path) -> list[str]:
    """Files the cross-iteration monitor observes: ALL untrusted repo text.

    The monitor looks for escalation evidence in untrusted input (where the
    attacker plants instructions), not in the agent's output artifacts. A
    previous v0.1 revision conflated them and the signal came from a
    coincidental substring in the agent's own output (audit round 2). The
    monitor and the admission decision are separate concerns and must
    stay separate.
    """
    return [
        str(f.relative_to(repo_path))
        for f in repo_path.rglob("*")
        if f.is_file() and not str(f.relative_to(repo_path)).startswith((".git", ".signetry"))
    ]


def _git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def run_admission(
    repo_path: Path,
    label: str,
    plan: Plan,
    *,
    loop_monitor: LoopStateMonitor | None = None,
    persisted_labels: dict[str, Label] | None = None,
) -> PlanVerdict:
    """Evaluate a `Plan` against the dual-lattice IFC and the repo contract.

    The IFC engine (`agent_harness_defense.ifc.evaluate_plan`) is the primary
    decision-maker. After that, the v0.1 second-signal pipeline runs:
    `LoopStateMonitor` is fed by `_scan_targets` (ALL untrusted repo text) and
    `flagged_by_keyword` is filled. The `flagged_by_keyword` list is a soft
    alert, never a denial — IFC verdicts are authoritative.
    """
    repo_path = Path(repo_path)
    monitor = loop_monitor or LoopStateMonitor()

    contract_path = repo_path / ".signetry" / "admission.yaml"
    contract = (
        Contract.from_yaml(contract_path.read_text()) if contract_path.is_file() else Contract()
    )

    # 1) Primary decision: dual-lattice IFC over the Plan.
    verdict = evaluate_plan(
        plan,
        forbidden_paths=contract.forbidden_paths,
        persisted_labels=persisted_labels,
    )

    # 2) Second signal (v0.1 retention): scan ALL untrusted repo text for
    #    trigger phrases. The v0.1 keyword match is not the decision; it
    #    just feeds `flagged_by_keyword` for diagnostic visibility.
    flagged_by_keyword: list[str] = []
    for rel in _scan_targets(repo_path):
        f = repo_path / rel
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        before = monitor.accumulated_score
        monitor.observe(text, rel=rel)
        after = monitor.accumulated_score
        if after > before:
            flagged_by_keyword.append(rel)

    verdict.flagged_by_keyword = flagged_by_keyword
    verdict.cross_iteration_signal = monitor.accumulated_score

    # 3) Receipt: base commit + diff hash + capability-set hash.
    has_git = (repo_path / ".git").exists()
    base_commit = _git(["rev-parse", "HEAD"], cwd=repo_path) if has_git else "no-git"
    diff = _git(["diff", "--stat"], cwd=repo_path) if has_git else ""
    cap_set = hashlib.sha256(
        (str(sorted(contract.allowed_paths)) + str(sorted(contract.forbidden_paths))).encode()
    ).hexdigest()[:16]
    verdict.receipt = {
        "base_commit": base_commit,
        "capability_set": cap_set,
        "diff_hash": hashlib.sha256(diff.encode()).hexdigest()[:16],
    }
    return verdict
