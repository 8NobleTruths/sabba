"""The Reflex / Resident / Teacher router: keep work at the cheapest tier that can do it,
escalate only when the cheaper tier comes up empty."""
from sabba.water.cascade import Cascade, Tier, choose_tier


def test_execution_tasks_are_always_reflex():
    for kind in ("verify", "solve", "rank"):
        assert choose_tier(kind, 0.9, have_resident=True, have_teacher=True) is Tier.REFLEX


def test_reasoning_with_no_models_degrades_to_reflex():
    assert choose_tier("hunt", 0.5, have_resident=False, have_teacher=False) is Tier.REFLEX


def test_hard_task_prefers_the_teacher():
    assert choose_tier("hunt", 0.9, have_resident=True, have_teacher=True) is Tier.TEACHER


def test_easy_task_stays_resident():
    assert choose_tier("hunt", 0.2, have_resident=True, have_teacher=True) is Tier.RESIDENT


def test_hard_task_with_only_resident_stays_local():
    assert choose_tier("hunt", 0.9, have_resident=True, have_teacher=False) is Tier.RESIDENT


def test_resident_escalates_to_teacher_on_empty():
    c = Cascade(have_resident=True, have_teacher=True)
    tier, out = c.run("hunt", 0.2, reflex=lambda: ["r"], resident=lambda: [], teacher=lambda: ["t"])
    assert tier is Tier.TEACHER and out == ["t"]


def test_resident_keeps_its_result_when_nonempty():
    c = Cascade(have_resident=True, have_teacher=True)
    tier, out = c.run("hunt", 0.2, reflex=lambda: [], resident=lambda: ["found"], teacher=lambda: ["t"])
    assert tier is Tier.RESIDENT and out == ["found"]


def test_verify_runs_reflex_even_with_models_present():
    c = Cascade(have_resident=True, have_teacher=True)
    tier, out = c.run("verify", 0.9, reflex=lambda: "v", resident=lambda: "r", teacher=lambda: "t")
    assert tier is Tier.REFLEX and out == "v"
