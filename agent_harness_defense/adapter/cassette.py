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

"""Cassette player for offline-deterministic Anthropic tool-calling (Spec §3, C3).

The example connects to the real Anthropic API only when ``AHD_RECORD=1`` AND
``ANTHROPIC_API_KEY`` is set — a manual, out-of-CI step that freezes a response
into ``fixtures/<name>.json``. The normal ``pytest`` run (and CI) never imports
``anthropic`` and never touches the network: it replays the frozen cassette.

The ``anthropic`` SDK is imported lazily INSIDE the record branch only, so a
plain ``import agent_harness_defense.adapter.cassette`` (as tests do) never pulls
it in. This keeps the core install light and the suite offline (C3).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


class CassettePlayer:
    """Replay or (manually) record Anthropic API responses as frozen cassettes."""

    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = Path(fixture_dir)
        self.fixture_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _fixture_name(request: dict[str, Any], name: str | None) -> str:
        if name:
            return name
        blob = json.dumps(request, sort_keys=True, default=str).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()[:16]
        return f"cassette_{digest}.json"

    def call(self, request: dict[str, Any], name: str | None = None) -> dict[str, Any]:
        """Return an API response.

        Recording mode (``AHD_RECORD=1`` + ``ANTHROPIC_API_KEY``): performs the
        real call via the Anthropic SDK and freezes ``{request, response}``.
        Replay mode (default): reads the frozen cassette and returns ``response``.
        """
        fname = self._fixture_name(request, name)
        fpath = self.fixture_dir / fname

        recording = os.environ.get("AHD_RECORD") == "1"
        if recording and os.environ.get("ANTHROPIC_API_KEY"):
            return self._record(request, fpath)

        # Replay (or fall back to replay if record was requested but no key).
        if not fpath.is_file():
            raise FileNotFoundError(
                f"Cassette fixture not found: {fpath}. "
                f"Record it once with AHD_RECORD=1 ANTHROPIC_API_KEY=... "
                f"python examples/anthropic_incident_report/run.py"
            )
        with fpath.open("r", encoding="utf-8") as fh:
            cassette = json.load(fh)
        return cassette["response"]

    def _record(self, request: dict[str, Any], fpath: Path) -> dict[str, Any]:
        # Lazy import: only reached in manual record mode, never in CI/replay.
        import anthropic  # noqa: WPS433 (intentional lazy import, C3)

        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        response = client.messages.create(**request)
        # Serialize the SDK response to a JSON-safe structure.
        serialized = _serialize_response(response)
        with fpath.open("w", encoding="utf-8") as fh:
            json.dump(
                {"request": request, "response": serialized},
                fh,
                indent=2,
                ensure_ascii=False,
            )
        return serialized


def _serialize_response(response: Any) -> dict[str, Any]:
    """Best-effort JSON-safe serialization of an Anthropic SDK response."""
    try:
        return json.loads(json.dumps(response, default=str))
    except (TypeError, ValueError):
        # Fallback: keep only the textual content blocks.
        text = ""
        for block in getattr(response, "content", []) or []:
            text += getattr(block, "text", "") or ""
        return {"content": [{"type": "text", "text": text}]}
