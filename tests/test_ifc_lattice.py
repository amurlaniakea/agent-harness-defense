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

"""AC-IFC-1: dual-lattice enforcement (no-upgrade AND no-downgrade, reported
separately).

Each test exercises ONE axis of the dual-lattice. The third test combines both
axes in the same plan and asserts that the IFC reports them as separate
reasons in `denied_reasons`, not as a single combined booleano — the same
"defined but not used" anti-pattern that bit `InstructionLevel` in v0.1 is
what this test prevents for the dual-lattice.
"""

from __future__ import annotations

from agent_harness_defense.ifc import (
    CONFIDENTIALITY_SECRET,
    INTEGRITY_UNTRUSTED,
    Label,
    Plan,
    PlanStep,
    evaluate_plan,
)


def test_join_no_upgrade_blocks_untrusted_to_system():
    """A write whose effective integrity is UNTRUSTED is denied with
    `integrity_violation` (the no-upgrade rule). The value_source is REPO_TEXT
    (UNTRUSTED), and writing a SYSTEM-intent path is not allowed.

    CRITICAL (FIX 2026-08-28): this test also verifies the "taint does not
    wash" property. The step has `depends_on=[step_1]` where step_1 is a
    SYSTEM read. With the buggy `max` join on integrity, the result would
    be SYSTEM and the step would be ADMITTED — defeating the no-upgrade
    rule. The `min` join keeps the integrity UNTRUSTED, and the step is
    denied. If the join is ever changed back to `max`, this test breaks.
    """
    plan = Plan(
        mission="Apply the in-scope task only.",
        steps=[
            PlanStep(id="step_1", action="read", path="README.md"),
            PlanStep(
                id="step_2",
                action="write",
                path="deploy.yml",
                value_source="repo.DEPLOY_YML",
                depends_on=["step_1"],
            ),
        ],
    )
    verdict = evaluate_plan(plan)
    assert "step_2" in verdict.denied_steps, (
        f"step_2 should be denied (no-upgrade); the value_source is REPO_TEXT "
        f"(UNTRUSTED) and the step writes a path; the depends_on chain to a "
        f"SYSTEM read must NOT elevate integrity. admitted={verdict.admitted_steps}, "
        f"denied={verdict.denied_steps}, reasons={verdict.denied_reasons}"
    )
    assert "integrity_violation" in verdict.denied_reasons["step_2"], (
        f"denied_reasons for step_2 must include 'integrity_violation'; "
        f"got {verdict.denied_reasons['step_2']}"
    )
    assert "confidentiality_violation" not in verdict.denied_reasons["step_2"], (
        "step_2 is REPO_TEXT -> PUBLIC; confidentiality axis should NOT fire"
    )
    # Belt-and-suspenders: the taint_summary must show integrity=UNTRUSTED
    # on the path, not SYSTEM. If the join were `max`, this would fail.
    label = verdict.taint_summary["deploy.yml"]
    assert label.integrity == INTEGRITY_UNTRUSTED, (
        f"taint_summary.integrity should remain UNTRUSTED after joining with "
        f"a SYSTEM read; got {label.integrity}. This proves the join is MIN."
    )


def test_join_no_downgrade_does_not_fire_when_sink_is_not_public():
    """A write of a SECRET value to a NON-public sink is denied with
    `integrity_violation` (the no-upgrade rule fires because env values are
    also UNTRUSTED), but the confidentiality_violation rule does NOT fire
    because the path is not a public sink.

    This test isolates the confidentiality axis from the OPPOSITE direction:
    the no-downgrade rule must NOT fire when the sink is not public. Without
    this test, an implementation that always denies SECRET writes (regardless
    of the sink) would pass a "no-downgrade" check. The rule is "SECRET to
    PUBLIC sink", not "SECRET anywhere".
    """
    plan = Plan(
        mission="Apply the in-scope task only.",
        steps=[
            PlanStep(
                id="step_1",
                action="write",
                path="secrets-vault.txt",  # NOT in DEFAULT_PUBLIC_SINKS
                value_source="env.SECRET",
            ),
        ],
    )
    verdict = evaluate_plan(plan)
    assert "step_1" in verdict.denied_steps, (
        f"step_1 should be denied (no-upgrade on env.SECRET, which is "
        f"UNTRUSTED); admitted={verdict.admitted_steps}, "
        f"denied={verdict.denied_steps}, reasons={verdict.denied_reasons}"
    )
    reasons = verdict.denied_reasons["step_1"]
    assert "integrity_violation" in reasons, (
        f"integrity_violation should fire (env.SECRET is UNTRUSTED); got {reasons}"
    )
    assert "confidentiality_violation" not in reasons, (
        f"confidentiality_violation must NOT fire when the sink is not a "
        f"public sink; got {reasons}. The no-downgrade rule is path-specific."
    )


def test_join_both_violations_reported_separately():
    """A plan that triggers BOTH axes in the same step must report them as
    SEPARATE entries in `denied_reasons[step_id]`, not as a single combined
    booleano. The dual-lattice is 2D; flattening it loses information.

    Scenario (this is the AC-EVAL-1 pattern, lifted into the lattice-level
    test): step_1 writes `env.SECRET` (confidentiality=SECRET, integrity=
    UNTRUSTED) to `incident-report.md` (a PUBLIC sink). The step violates
    BOTH axes: no-upgrade (UNTRUSTED integrity tries to drive an action)
    AND no-downgrade (SECRET going to a PUBLIC sink).
    """
    plan = Plan(
        mission="Apply the in-scope task only.",
        steps=[
            PlanStep(
                id="step_1",
                action="write",
                path="incident-report.md",
                value_source="env.SECRET",
            ),
        ],
    )
    verdict = evaluate_plan(plan)
    assert "step_1" in verdict.denied_steps
    reasons = verdict.denied_reasons["step_1"]
    assert "integrity_violation" in reasons, (
        f"denied_reasons must include 'integrity_violation' separately; got {reasons}"
    )
    assert "confidentiality_violation" in reasons, (
        f"denied_reasons must include 'confidentiality_violation' separately; got {reasons}"
    )
    # The taint_summary must record BOTH axes on the path, with the actual
    # values that drove each rule.
    assert "incident-report.md" in verdict.taint_summary
    label = verdict.taint_summary["incident-report.md"]
    assert label.integrity == INTEGRITY_UNTRUSTED, (
        f"taint_summary.integrity should be UNTRUSTED; got {label.integrity}"
    )
    assert label.confidentiality == CONFIDENTIALITY_SECRET, (
        f"taint_summary.confidentiality should be SECRET; got {label.confidentiality}"
    )


def test_join_no_downgrade_fires_when_sink_is_public():
    """A write of a SECRET value to a PUBLIC sink triggers BOTH rules
    (no-upgrade because env is UNTRUSTED, AND no-downgrade because SECRET
    goes to a public sink). This is the scenario AC-EVAL-1 in the spec
    and is the case where the dual-lattice is most clearly justified:
    the engine reports two distinct reasons for one denied step.
    """
    plan = Plan(
        mission="Apply the in-scope task only.",
        steps=[
            PlanStep(
                id="step_1",
                action="write",
                path="incident-report.md",  # IS in DEFAULT_PUBLIC_SINKS
                value_source="env.SECRET",
            ),
        ],
    )
    verdict = evaluate_plan(plan)
    assert "step_1" in verdict.denied_steps
    reasons = verdict.denied_reasons["step_1"]
    assert "integrity_violation" in reasons
    assert "confidentiality_violation" in reasons


def test_label_join_is_componentwise():
    """Sanity check for the lattice join.

    - Confidentiality: `max` (the more sensitive wins).
    - Integrity: `min` (the less trusted wins — "taint does not wash").

    This is the algebra the rules rest on; if it breaks, all three AC-IFC-1
    tests above break in confusing ways. Test it directly. Note: an earlier
    draft had `max` on both axes; that was the bug that let UNTRUSTED
    elevate to SYSTEM through a SYSTEM-intent read (the privilege-escalation
    attack the no-upgrade rule is meant to block).
    """
    a = Label(confidentiality=1, integrity=0)  # INTERNAL, UNTRUSTED
    b = Label(confidentiality=0, integrity=2)  # PUBLIC, SYSTEM
    j = a.join(b)
    # Confidentiality: max(1, 0) = 1
    assert j.confidentiality == 1
    # Integrity: min(0, 2) = 0  <-- the critical bit
    assert j.integrity == 0, (
        f"integrity join should be MIN (taint does not wash); "
        f"got {j.integrity} from a.integrity={a.integrity}, b.integrity={b.integrity}"
    )


def test_source_label_of_has_unique_source_tags():
    """Regression guard for the 2026-08-28 review: `SourceTag.DATA` was
    originally `= 4`, aliasing `USER = 4`. The IntEnum silently routes
    `SourceTag(4)` to `USER`, which would have been a silent-bug.

    This test asserts the table covers every SourceTag exactly once.
    """
    from agent_harness_defense.ifc import Label, SourceTag

    for tag in SourceTag:
        label = Label.label_of(tag)
        # No crash + a non-trivial label assigned.
        assert isinstance(label.confidentiality, int)
        assert isinstance(label.integrity, int)
        assert 0 <= label.confidentiality <= 2
        assert 0 <= label.integrity <= 2
    # And the explicit alias check the review asked for.
    assert SourceTag(4) is SourceTag.USER
    assert SourceTag(0) is SourceTag.DATA
    assert SourceTag(5) is SourceTag.SYSTEM
