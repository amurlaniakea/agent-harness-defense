"""Open admission layer for LLM agent harnesses.

Replaces the closed `signetry-core` admission pipeline with an open, auditable
implementation. v0.1 design (HONEST scope):

1. Taint / instruction-level labeling — every file the agent reads from the repo
   is labeled LOW-privilege (untrusted data). We do NOT yet propagate labels across
   arbitrary data/control flows (that is future work); we use the label to record
   provenance of an escalation decision. The escalation decision itself is a
   forbidden-path quarantine gated by a cross-iteration escalation signal.
2. Cross-iteration loop-state monitor (arXiv:2608.27141) — retains a safety signal
   across iterations instead of re-initializing per trajectory.
3. Contract / verifier — allowed_paths / forbidden_paths / max_files_changed.
4. Receipt — admitted change carries base-commit, diff and capability-set hashes.

Deterministic and offline; no LLM calls. The "agent" is modeled by the harness that
materializes the agent's on-disk edits (including any it produced by obeying an
injected instruction) and then calls `run_admission` to compute the ADMITTED subset.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class InstructionLevel(IntEnum):
    """Privilege level of a content fragment (higher = more authority over behavior)."""

    SYSTEM = 40
    USER = 30
    TOOL_RESULT = 20
    REPO_TEXT = 10
    DATA = 0


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


def _level_of_file(rel: str) -> InstructionLevel:
    """Repo text the agent reads is untrusted data, not instructions.

    This is the taint label used for provenance of the escalation decision. Full
    label propagation across data/control flows is future work (see README).
    """
    return InstructionLevel.REPO_TEXT


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


@dataclass
class AdmissionReport:
    changed_files: list[str]
    escalation_detected: bool
    quarantined_files: list[str]
    task_completed: bool
    authority_level: int
    authority: str
    outcome: str
    contract_passed: bool
    trust_boundary_clean: bool
    receipt: dict[str, str]
    cross_iteration_signal: float
    taint: dict[str, int]


def _git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def _candidate_files(repo_path: Path, proposed_files: list[str] | None) -> list[str]:
    if proposed_files is not None:
        return list(proposed_files)
    return [
        str(f.relative_to(repo_path))
        for f in repo_path.rglob("*")
        if f.is_file() and not str(f.relative_to(repo_path)).startswith((".git", ".signetry"))
    ]


def run_admission(
    repo_path: Path,
    label: str,
    mission: str,
    proposed_files: list[str] | None = None,
    *,
    loop_monitor: LoopStateMonitor | None = None,
) -> AdmissionReport:
    """Compute the ADMITTED subset of the agent's on-disk edits.

    The repo at ``repo_path`` already contains the agent's edits, including any
    artifacts it produced by obeying injected repo text. We label each file's
    privilege level, scan LOW-privilege repo text for escalation triggers (feeding
    the cross-iteration monitor), and QUARANTINE forbidden-path artifacts out of the
    admitted changeset.
    """
    repo_path = Path(repo_path)
    monitor = loop_monitor or LoopStateMonitor()

    contract_path = repo_path / ".signetry" / "admission.yaml"
    contract = (
        Contract.from_yaml(contract_path.read_text()) if contract_path.is_file() else Contract()
    )

    candidates = _candidate_files(repo_path, proposed_files)

    # 1) Taint labeling: every candidate file carries an instruction level.
    taint: dict[str, int] = {rel: int(_level_of_file(rel)) for rel in candidates}

    # 2) Scan LOW-privilege repo text for escalation triggers -> feed loop monitor.
    for rel in candidates:
        f = repo_path / rel
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        monitor.observe(text, rel=rel)

    # 3) Forbidden-path hits (the artifacts the agent may have written by obeying).
    forbidden_hits = [
        c for c in candidates if any(_glob_match(fp, c) for fp in contract.forbidden_paths)
    ]

    # 4) QUARANTINE: admitted excludes forbidden hits (admission-time defense).
    admitted = [c for c in candidates if c not in forbidden_hits]

    # Escalation detected = forbidden artifact present AND cross-iteration signal fired.
    escalation_detected = bool(forbidden_hits) and monitor.correlated

    # Benign task completion: a non-forbidden, allowed file is in the admitted set.
    task_completed = any(
        c in admitted
        and (not contract.allowed_paths or any(_glob_match(a, c) for a in contract.allowed_paths))
        for c in admitted
    )

    contract_passed = True
    if contract.max_files_changed is not None:
        contract_passed = len(admitted) <= contract.max_files_changed

    has_git = (repo_path / ".git").exists()
    base_commit = _git(["rev-parse", "HEAD"], cwd=repo_path) if has_git else "no-git"
    diff = _git(["diff", "--stat"], cwd=repo_path) if has_git else ""
    cap_set = hashlib.sha256(
        (str(sorted(contract.allowed_paths)) + str(sorted(contract.forbidden_paths))).encode()
    ).hexdigest()[:16]

    # trust_boundary_clean = the attack did NOT enter the admitted changeset.
    attack_in_admitted = any(m in admitted for m in forbidden_hits)
    trust_boundary_clean = not attack_in_admitted

    authority_level = 0 if escalation_detected else 1
    authority = "denied" if escalation_detected else "admitted"
    if escalation_detected and task_completed:
        outcome = "ATTACK BOUNDED: artifact quarantined, benign task admitted"
    elif escalation_detected:
        outcome = "ATTACK DETECTED: artifact quarantined (benign task unclear)"
    else:
        outcome = "ADMITTED"

    return AdmissionReport(
        changed_files=sorted(admitted),
        escalation_detected=escalation_detected,
        quarantined_files=sorted(forbidden_hits),
        task_completed=task_completed,
        authority_level=authority_level,
        authority=authority,
        outcome=outcome,
        contract_passed=contract_passed,
        trust_boundary_clean=trust_boundary_clean,
        receipt={
            "base_commit": base_commit,
            "capability_set": cap_set,
            "diff_hash": hashlib.sha256(diff.encode()).hexdigest()[:16],
        },
        cross_iteration_signal=monitor.accumulated_score,
        taint=taint,
    )
