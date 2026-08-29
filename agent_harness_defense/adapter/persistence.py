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

"""Label-preserving persistence between agent iterations (Spec 003 §2/§3).

When the IFC flags an artifact as tainted (UNTRUSTED integrity) in iteration N,
that *label* — NOT the artifact's content — persists into iteration N+1 so the
planner cannot be re-fed a tainted source as if it were clean (arXiv:2608.27234
§label-preserving). The `summary` field is a hash of the path + reason code; the
raw content is never stored or re-exposed (Spec §2 decision #1, C1 honest scope).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_harness_defense.ifc import Label

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_harness_defense.adapter.session import AgentSession


@dataclass(frozen=True)
class PersistedArtifact:
    """A tainted artifact remembered across iterations (Spec §2).

    Only the IFC *result* is stored, never the artifact content.
    """

    path_or_id: str
    label: Label
    summary: str  # hash(path + reason); NEVER the artifact text
    iteration: int

    @classmethod
    def make_summary(cls, path_or_id: str, reason: str) -> str:
        """Short, content-free fingerprint of a taint event."""
        blob = f"{path_or_id}|{reason}".encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:16]


def persisted_labels_from(session: "AgentSession") -> dict[str, Label]:
    """Extract ``path -> Label`` map from a session's persisted artifacts.

    Used by ``AgentSession.step`` to re-inject taint into the next iteration
    via ``run_admission(..., persisted_labels=...)``.
    """
    return {a.path_or_id: a.label for a in session.persisted_artifacts}


def record_taint(
    session: "AgentSession",
    tainted_paths: list[str],
    taint_summary: dict[str, Label],
    denied_reasons: dict[str, list[str]],
    iteration: int,
) -> None:
    """Append a ``PersistedArtifact`` for each tainted path not already recorded.

    Idempotent per path: re-tainting the same path does not duplicate the entry.
    """
    seen = {a.path_or_id for a in session.persisted_artifacts}
    for path in tainted_paths:
        if path in seen:
            continue
        label = taint_summary.get(path)
        if label is None:
            continue
        # Prefer a concrete reason code for the summary; fall back to "tainted".
        reason = (denied_reasons.get(path) or ["tainted"])[0]
        session.persisted_artifacts.append(
            PersistedArtifact(
                path_or_id=path,
                label=label,
                summary=PersistedArtifact.make_summary(path, reason),
                iteration=iteration,
            )
        )
        seen.add(path)
