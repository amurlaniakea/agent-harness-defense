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

"""Mechanical tool_call -> PlanStep mapping (Spec 002 §2, §2.1).

The adapter translates a sequence of Anthropic tool-calls into a declarative
``Plan`` for the IFC engine. The mapping is MECHANICAL and declarative (C1):
it does NOT read file contents to infer dependencies. ``depends_on`` is derived
only from the TEMPORAL ORDER of the agent's calls (or an explicit
``step_<k>.content`` reference the agent returns).

Verified consequence (Spec §2.1, 2026-08-29): a ``bash`` / ``execute`` call is
mapped to ``value_source="repo.cmd"`` (UNTRUSTED, fail-closed). The original
mapping (``value_source=None`` -> DATA/USER) left shell-borne exfiltration
ADMITTED, because the secret travels through the shell and never appears in any
``value_source`` of the Plan. Fail-closed is correct: the adapter cannot see
what the shell does, so it assumes the worst.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent_harness_defense.ifc import Plan, PlanStep

# Pattern the agent may use to reference a previous step's output, e.g.
# content_ref="step_3.content". Mechanical only — we do not resolve semantics.
_CONTENT_REF_RE = re.compile(r"step_(\d+)\.content")


@dataclass
class ToolCall:
    """A single Anthropic tool-call emitted by the agent."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)


def _normalize_name(name: str) -> str:
    """Lower-case and strip a tool name for matching."""
    return name.strip().lower()


def _depends_on_for(index: int, args: dict[str, Any]) -> list[str]:
    """Decide ``depends_on`` for step at ``index``.

    DEFAULT (C1, fail-safe against false positives): a step depends on NOTHING
    by default. The adapter is mechanical (Spec §2) and does NOT infer
    cross-step dependencies the agent never declared. Temporal order alone is
    NOT a dependency — chaining every step to its predecessor would mean a
    single untrusted read at the start of a session transitively taints every
    later write (verified 2026-08-29: a README read + 5 unrelated writes all
    got denied). That is a false-positive avalanche and contradicts the
    Constitution's C1 ("NO reconstruye dependencias transversales que el agente
    no declaró").

    The ONLY way a step acquires a ``depends_on`` is an EXPLICIT reference the
    agent returns that matches ``step_<k>.content`` (a ``content_ref`` /
    ``value_ref``). If the agent did not declare it, the step stands alone.
    This means the adapter can miss undeclared dependencies (a false negative) —
    that is the honest, documented trade-off of C1/C6, and is far safer than
    denying every normal agent session.
    """
    ref = args.get("content_ref") or args.get("value_ref") or ""
    if isinstance(ref, str):
        m = _CONTENT_REF_RE.search(ref)
        if m:
            return [f"step_{m.group(1)}"]
    # NO implicit temporal chaining. Default is [] (no dependency).
    return []


def build_plan(tool_calls: list[ToolCall], session: Any | None = None) -> Plan:
    """Translate ``tool_calls`` into a declarative ``Plan`` (Spec §2).

    ``step_<n>`` ids use a per-call global index (1-based). ``depends_on`` is
    ONLY derived from an EXPLICIT ``content_ref``/``value_ref`` the agent returns
    (mechanical, C1) — there is NO implicit temporal chaining (see
    ``_depends_on_for``). The adapter does not infer dependencies the agent did
    not declare; that is the honest, false-positive-free trade-off of C1/C6.
    """
    steps: list[PlanStep] = []
    for n, tc in enumerate(tool_calls, start=1):
        step_id = f"step_{n}"
        name = _normalize_name(tc.name)
        args = tc.args or {}

        if name in ("read_file", "read", "open_file"):
            path = args.get("path") or args.get("file_path") or args.get("filename")
            steps.append(
                PlanStep(
                    id=step_id,
                    action="read",
                    path=path,
                    value_source=None,
                    depends_on=_depends_on_for(n, args),
                )
            )
        elif name in ("write_file", "write", "create_file"):
            path = args.get("path") or args.get("file_path")
            content_ref = args.get("content_ref") or args.get("value_ref")
            if content_ref and str(content_ref).startswith("env."):
                value_source = str(content_ref)
            else:
                # A literal content string is the agent's own data (USER/INTERNAL).
                value_source = "literal"
            steps.append(
                PlanStep(
                    id=step_id,
                    action="write",
                    path=path,
                    value_source=value_source,
                    depends_on=_depends_on_for(n, args),
                )
            )
        elif name in ("bash", "execute", "shell", "run_command"):
            # FAIL-CLOSED (Spec §2.1): the shell can read/write anything without
            # the Plan seeing it, so mark it UNTRUSTED by default. The caller may
            # override by declaring an explicit source (C6).
            steps.append(
                PlanStep(
                    id=step_id,
                    action="execute",
                    path=None,
                    value_source="repo.cmd",
                    depends_on=_depends_on_for(n, args),
                )
            )
        else:
            # Unknown tool: treat as an opaque execute action, fail-closed.
            steps.append(
                PlanStep(
                    id=step_id,
                    action="execute",
                    path=None,
                    value_source="repo.cmd",
                    depends_on=_depends_on_for(n, args),
                )
            )

    return Plan(mission="Anthropic tool-call translation (adapter 002).", steps=steps)
