"""Projected loss + certainty (Overview, Status summary) and the Fund flow timeline view."""

from __future__ import annotations

import math
import pathlib
import subprocess

import pytest
from test_recovery_plan import case, no_ai  # noqa: F401 - fixtures (a traced demo case)

from app.blocks import recovery as rp


def test_projected_loss_is_the_loss_less_secured_and_expected_recovery(db, case):  # noqa: F811
    t = rp.build(db, case).totals
    loss = float(case.loss_usd)
    assert t["projected_recovery_usd"] == pytest.approx(min(loss, t["secured_usd"] + t["expected_usd"]), abs=0.02)
    assert t["projected_loss_usd"] == pytest.approx(loss - t["projected_recovery_usd"], abs=0.02)
    assert 0 <= t["projected_loss_low_usd"] <= t["projected_loss_usd"] <= t["projected_loss_high_usd"] <= loss
    assert 0 <= t["projection_certainty_pct"] <= 100
    assert t["projected_recovery_pct"] == pytest.approx(100 * t["projected_recovery_usd"] / loss, abs=0.1)


def test_certainty_is_one_minus_the_outcome_spread_over_the_loss():
    c = type("C", (), {"loss_usd": 1000})()
    plan = type("P", (), {"secured": [{"usd": 100}]})()
    p = rp._projection(c, {"expected": 200.0, "variance": 100.0 ** 2}, plan)  # sigma = 100
    assert p["projected_loss_usd"] == 700 and p["projected_recovery_usd"] == 300
    assert p["projection_certainty_pct"] == 90.0 and (p["projected_loss_low_usd"], p["projected_loss_high_usd"]) == (600, 800)
    settled = rp._projection(c, {"expected": 0.0, "variance": 0.0}, plan)
    assert settled["projection_certainty_pct"] == 100.0 and settled["projected_loss_usd"] == 900
    assert rp._projection(type("C", (), {"loss_usd": 0})(), {"expected": 5.0}, plan)["projected_loss_usd"] is None
    assert math.isclose(rp._projection(c, {"expected": 0, "variance": 5000.0 ** 2}, plan)["projection_certainty_pct"], 0)


def test_overview_and_status_summary_show_the_projection_row_and_fund_flow_offers_the_timeline(db, case, client_for):  # noqa: F811
    adm = client_for("admin", case=case)
    for page in (f"/cases/{case.id}?tab=overview", f"/cases/{case.id}?tab=assistant&sub=summary"):
        html = adm.get(page).text
        assert 'id="projection"' in html and "Projected loss" in html and "Certainty" in html, page
    flow = adm.get(f"/cases/{case.id}?tab=fund_flow").text
    assert 'data-ff-cmd="timeline"' in flow and 'id="ff-timeline-note"' in flow


def test_graph_js_parses_and_has_the_timeline_view():
    js = pathlib.Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "graph.js"
    src = js.read_text()
    assert "function setTimeline" in src and '"timeline": (btn) => setTimeline' in src
    node = "/opt/homebrew/bin/node"
    if pathlib.Path(node).exists():
        assert subprocess.run([node, "--check", str(js)], capture_output=True, check=False).returncode == 0
