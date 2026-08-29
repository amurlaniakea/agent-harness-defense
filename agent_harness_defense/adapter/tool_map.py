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


def _depends_on_for(index: int, args: dict[str, Any], prev_id: str | None) -> list[str]:
    """Decide ``depends_on`` for step at ``index``.

    Default: chain to the previous step (temporal order). Exception: if the
    agent returns an explicit ``content_ref`` matching ``step_<k>.content``,
    depend on that step instead.
    """
    ref = args.get("content_ref") or args.get("value_ref") or ""
    if isinstance(ref, str):
        m = _CONTENT_REF_RE.search(ref)
        if m:
            return [f"step_{m.group(1)}"]
    if prev_id is not None:
        return [prev_id]
    return []


def build_plan(tool_calls: list[ToolCall], session: Any | None = None) -> Plan:
    """Translate ``tool_calls`` into a declarative ``Plan`` (Spec §2).

    ``step_<n>`` ids use a per-call global index (1-based) so that chaining
    across multiple ``AgentSession.step`` calls stays temporally ordered. The
    index is reset per ``build_plan`` call; ``AgentSession`` is responsible for
    carrying inter-step order if needed (the 002 adapter chains within a single
    ``build_plan`` invocation, which matches the example's single agent turn).
    """
    steps: list[PlanStep] = []
    prev_id: str | None = None
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
                    depends_on=_depends_on_for(n, args, prev_id),
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
                    depends_on=_depends_on_for(n, args, prev_id),
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
                    depends_on=_depends_on_for(n, args, prev_id),
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
                    depends_on=_depends_on_for(n, args, prev_id),
                )
            )
        prev_id = step_id

    return Plan(mission="Anthropic tool-call translation (adapter 002).", steps=steps)
