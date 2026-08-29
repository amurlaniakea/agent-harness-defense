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

"""AC-ADAPT-3 (offline half): CassettePlayer replays without importing anthropic.

Verifies the C3 guarantee: in replay mode (no AHD_RECORD, no API key) the player
returns the frozen response and NEVER imports the ``anthropic`` SDK, so the suite
stays offline and credential-free in CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_harness_defense.adapter.cassette import CassettePlayer


def test_replay_returns_frozen_response_without_importing_anthropic(tmp_path: Path):
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    request = {"model": "claude-3-5-haiku", "messages": [{"role": "user", "content": "hi"}]}
    response = {"content": [{"type": "text", "text": "hello"}]}
    (fixture_dir / "canned.json").write_text(
        json.dumps({"request": request, "response": response}), encoding="utf-8"
    )

    # Ensure anthropic is not already imported from elsewhere.
    saved = sys.modules.pop("anthropic", None)
    try:
        player = CassettePlayer(fixture_dir)
        got = player.call(request, name="canned.json")
        assert got == response
        assert "anthropic" not in sys.modules, "replay mode must not import anthropic"
    finally:
        if saved is not None:
            sys.modules["anthropic"] = saved


def test_record_env_without_key_falls_back_to_replay(tmp_path: Path, monkeypatch):
    """If AHD_RECORD=1 but no key, we must not crash trying to import anthropic —
    behaviour is undefined for recording, but at minimum we must not import the SDK
    in a way that breaks offline CI. We assert replay path is taken (fixture exists)."""
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    request = {"model": "x"}
    response = {"content": [{"type": "text", "text": "y"}]}
    (fixture_dir / "canned.json").write_text(
        json.dumps({"request": request, "response": response}), encoding="utf-8"
    )
    monkeypatch.setenv("AHD_RECORD", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    saved = sys.modules.pop("anthropic", None)
    try:
        player = CassettePlayer(fixture_dir)
        got = player.call(request, name="canned.json")
        assert got == response
        assert "anthropic" not in sys.modules
    finally:
        if saved is not None:
            sys.modules["anthropic"] = saved
