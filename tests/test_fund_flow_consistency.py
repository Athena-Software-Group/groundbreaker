"""The Fund flow tab says what the Recovery plan says (app/tracing/annotate.py align_with_plan, hover.py, graph.py,
static/graph.js): an issuer lever whose stablecoin moved on is no stop-order target (Circle on the demo: the USDC was
swapped to ETH within minutes), every recommended action carries the plan's value and next step, outflow counts and
traced figures agree between the hover card and the details panel and never exceed what reached the wallet, an
asserted hub remainder is marked as an upper bound, and no raw code or placeholder id reaches the reader. The masked
demo case; offline."""

import json
import re

import pytest

from app import services
from app.ai import providers
from app.core.permissions import CaseAccess
from app.db.models import CaseRole
from app.tracing import annotate as an
from app.tracing.freeze import freeze_candidates
from app.tracing.graph import build_graph, summary, to_cytoscape
from app.tracing.hover import display_labels, hover_data

CIRCLE_WALLETS = {"0x57de1021a507d46272d386995d5b58667ac1f8df", "0xe9449ba33c8dcf6f859c9bc476b8debab64a4b1b"}
TRON_USDT = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"
HUB = "0x54453e25e38b11009963361a123bde2b4457becb"
RAINBET_DEPOSIT = "0x74e697c26f0ce168849411c53707ae689de10d5b"
PEEL_4TX = "0xdc1c8934a6b700ea7db72184bd7a29676e33b2dc"
LOSS = 399247.92


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _tab(db, case, role=CaseRole.INVESTIGATOR):
    """(recommended actions, node data by address, edges) as the Fund flow tab builds them on the latest run."""
    db.expire_all()
    run = services.latest_run(db, case)
    elements = to_cytoscape(build_graph(db, run))
    recs = an.annotate_elements(db, case, run, elements, can_act=True, owners=False)
    hover_data(db, case, run, elements, CaseAccess(case=case, user=None, role=role, member=None), current=True,
               recs=recs)
    return recs, {n["data"]["address"].lower(): n["data"] for n in elements["nodes"]}, elements["edges"]


# --------------------------------------------------------------------------- moved on: no issuer lever
def test_the_trace_marks_the_circle_wallets_moved_on(db, case):
    run = services.latest_run(db, case)
    idents = {i.address.lower(): i for c in freeze_candidates(db, run) for i in c.identifiers}
    assert all(idents[a].moved_on for a in CIRCLE_WALLETS)
    assert not idents[TRON_USDT.lower()].moved_on  # dormant: the USDT is still there
    assert not idents[RAINBET_DEPOSIT].moved_on  # a deposit address: credited to the account behind it


def test_recommendations_keep_a_moved_on_issuer_listed_with_nothing_held():
    cands = [an.CandidateRef("Circle (USDC issuer)", "issuer_blacklist", 60, [("0xaaa", 1000.0), ("0xbbb", 1000.0)],
                             moved_on=frozenset({"0xaaa", "0xbbb"})),
             an.CandidateRef("Tether (USDT issuer)", "issuer_blacklist", 60, [("Tccc", 500.0)])]
    recs = an.recommendations(cands, [])
    circle, tether = recs[1], recs[0]
    assert circle["short"] == "Circle" and circle["nothing_held"] and circle["held"] == [] and circle["value_usd"] == 0
    assert "moved on" in circle["reason"] and "can blacklist" not in circle["reason"]
    assert tether["held"] == ["Tccc"] and not tether["nothing_held"]
    assert set(an.recommendation_by_address(recs)) == {"tccc"}  # no ring on a wallet the funds left


def test_a_wallet_partly_moved_on_keeps_only_what_is_held():
    c = an.CandidateRef("Tether (USDT issuer)", "issuer_blacklist", 60, [("Ta", 900.0), ("Tb", 400.0)],
                        moved_on=frozenset({"ta"}))
    (r,) = an.recommendations([c], [])
    assert r["held"] == ["Tb"] and r["value_usd"] == 400.0 and r["addresses"] == ["Ta", "Tb"]


def test_align_with_plan_takes_the_plans_value_next_step_and_order():
    recs = an.recommendations([
        an.CandidateRef("Circle (USDC issuer)", "issuer_blacklist", 60, [("0xaaa", 399247.92)]),
        an.CandidateRef("Tether (USDT issuer)", "issuer_blacklist", 60, [("Tccc", 1359.9)]),
    ], [])
    assert recs[0]["short"] == "Circle" and not recs[0]["nothing_held"]  # no moved-on mark: the plan decides
    moves = [
        {"rank": 3, "key": "entity-4", "title": "Brief LE about Tether", "authority": {"key": "entity-4",
         "name": "Tether (USDT issuer)"}, "value": 1359.9, "value_fmt": "$1,360", "basis": "up to $1,360 traced"},
        {"rank": 7, "key": "entity-5", "title": "Get a US case agent on Circle", "authority": {"key": "entity-5",
         "name": "Circle (USDC issuer)"}, "value": 0.0, "value_fmt": "—", "basis": "0x57de… moved on"},
        {"rank": 1, "key": "ethereum:0xccc", "title": "Watch it", "authority": None, "value": 5.0},
    ]
    an.align_with_plan(recs, moves, case_id=9)
    tether, circle = recs
    assert tether["short"] == "Tether" and tether["plan"]["rank"] == 3 and tether["plan"]["title"] == "Brief LE about Tether"
    assert tether["plan"]["url"] == "/cases/9/recovery-plan#m-entity-4" and tether["value_usd"] == 1359.9
    assert circle["nothing_held"] and circle["held"] == [] and circle["value_usd"] == 0
    assert circle["reason"] == "Nothing at stake by the Recovery plan: 0x57de… moved on."
    els = {"nodes": [{"data": {"address": "0xAAA"}}, {"data": {"address": "Tccc"}}]}
    an.apply_recommended(els, recs)
    assert els["nodes"][0]["data"]["recommended"] is None
    assert els["nodes"][1]["data"]["recommended"]["next"] == "Brief LE about Tether"
    assert els["nodes"][1]["data"]["recommended"]["plan_rank"] == 3


def test_demo_tab_agrees_with_the_recovery_plan_on_circle_and_tether(db, case):
    from app.blocks import recovery as rp

    recs, by, _ = _tab(db, case)
    v = rp.view(rp.build(db, case), CaseAccess(case=case, user=None, role=CaseRole.INVESTIGATOR, member=None))
    plan = {m["authority"]["name"]: m for m in v["moves"] + v["waiting"] if m.get("authority")}
    for r in recs:
        m = plan[r["entity"]]
        assert r["plan"]["title"] == m["title"] and r["plan"]["rank"] == m["rank"]
        assert r["value_usd"] == pytest.approx(m["value"] or 0)
    circle = next(r for r in recs if r["short"] == "Circle")
    assert circle["nothing_held"] and recs[-1] is circle
    # no ring, no callout tag, no "issuer-freezable" claim on the wallets the USDC left
    for a in CIRCLE_WALLETS:
        d = by[a]
        assert d["recommended"] is None and d["moved_on"]
        tags = [t["t"] for t in d["hover"]["status"]["tags"]]
        assert "received USDC, moved on" in tags and "issuer-freezable" not in tags
        assert not any(t.startswith("recommended") for t in tags)
    tron = by[TRON_USDT.lower()]
    assert tron["recommended"]["short"] == "Tether" and tron["recommended"]["next"] == plan["Tether (USDT issuer)"]["title"]
    assert "recommended: issuer blacklist → Tether" in [t["t"] for t in tron["hover"]["status"]["tags"]]


# --------------------------------------------------------------------------- counts and figures
def test_parallel_transfers_are_one_link_listing_every_movement(db, case):
    run = services.latest_run(db, case)
    edges = [e["data"] for e in to_cytoscape(build_graph(db, run))["edges"]]
    by_id = {n["data"]["id"]: n["data"]["address"].lower() for n in to_cytoscape(build_graph(db, run))["nodes"]}
    (peel,) = [e for e in edges if by_id[e["target"]] == PEEL_4TX]
    assert peel["n"] == 4 and len(peel["transfers"]) == 4
    assert peel["taint_usd"] == pytest.approx(sum(t["taint_usd"] for t in peel["transfers"]))
    assert peel["amount_label"].endswith("ETH (4 txs)") and not peel["asserted"]
    assert [t["timestamp"] for t in peel["transfers"]] == sorted(t["timestamp"] for t in peel["transfers"])
    # every movement of the run between two drawn addresses is on exactly one link
    moved = sum(e.get("n", 1) for e in edges if not e.get("virtual"))
    drawn = {int(i) for i in by_id}
    assert moved == sum(1 for e in run.edges if {e.transfer.from_address_id, e.transfer.to_address_id} <= drawn)


def test_the_hub_counts_twelve_outflows_and_never_traces_more_than_reached_it(db, case):
    _, by, edges = _tab(db, case)
    hub = by[HUB]["hover"]["flows"]["out"]
    assert hub["n"] == 12 and hub["asserted_n"] == 4
    assert hub["taint_usd"] == pytest.approx(LOSS) and hub["capped"] and hub["taint_sum"] > LOSS
    links = [e["data"] for e in edges if e["data"]["source"] == by[HUB]["id"]]
    assert len(links) == 11 and sum(e.get("n", 1) for e in links) == 12  # the panel: 12 transfers drawn as 11 links
    for d in by.values():  # no traced figure above the loss, anywhere
        f = (d.get("hover") or {}).get("flows")
        if f:
            assert f["in"]["taint_usd"] <= LOSS + 0.01 and f["out"]["taint_usd"] <= LOSS + 0.01, d["address"]


def test_an_asserted_hub_remainder_is_an_upper_bound_shared_by_its_destinations(db, case):
    _, by, _ = _tab(db, case)
    rainbet = by[RAINBET_DEPOSIT]
    assert rainbet["upper_bound"] and rainbet["asserted_peers"] == 3 and rainbet["value_label"].startswith("≤")
    t = rainbet["hover"]["status"]["taint"]
    assert t["upper"] and t["peers"] == 3
    shared = [d for d in by.values() if d.get("upper_bound")]
    assert len(shared) == 4 and {round(d["taint_usd"], 2) for d in shared} == {63761.69}
    assert not by[HUB]["upper_bound"] and not by[TRON_USDT.lower()]["upper_bound"]


def test_footer_names_services_apart_from_the_non_custodial_router(db, case):
    s = summary(build_graph(db, services.latest_run(db, case)))
    assert s["services"] == ["KuCoin", "Rainbet", "SWFT / Bridgers"]
    assert s["non_custodial"] == ["Uniswap (Universal Router)"]


# --------------------------------------------------------------------------- plain words
def test_every_flag_terminal_reason_and_type_has_plain_words(db, case):
    labels = display_labels()
    _, by, _ = _tab(db, case)
    for d in by.values():
        assert all(f in labels["flags"] for f in d.get("flags") or []), d["flags"]
        assert d["type"] in labels["types"]
        assert not d.get("terminal_reason") or d["terminal_reason"] in labels["terminal"]
        for t in d["hover"]["status"]["tags"]:
            assert "_" not in t["t"], t


def test_fund_flow_page_shows_the_plan_and_no_raw_ids(client_for, db, case):
    page = client_for("investigator", case=case).get(f"/cases/{case.id}?tab=fund_flow").text
    recs = re.search(r'<details class="ff-recs".*?</details>', page, re.DOTALL).group(0)
    assert "Stop order → Tether" in recs and "Circle: nothing held to blacklist" in recs
    assert "Stop order → Circle" not in recs and "priority 60" not in recs and "Recovery plan #" in recs
    assert "services: KuCoin, Rainbet, SWFT / Bridgers" in page and "non-custodial: Uniswap (Universal Router)" in page
    assert "VASP touchpoints" not in page and " nodes · " not in page
    labels = json.loads(re.search(r'<script id="graph-labels" type="application/json">(.*?)</script>', page,
                                  re.DOTALL).group(1))
    assert labels["flags"]["rapid_forward"] == "Swept fast" and labels["terminal"]["vasp_omnibus"]
    assert "tokentx" not in page and "fetch exact wei" not in page


def test_graph_js_never_prints_raw_codes_or_synthetic_ids():
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "graph.js").read_text()
    assert "${esc(f)}" not in js and "esc(d.terminal_reason)" not in js and "esc(d.type)" not in js
    assert "esc(e.data_source)" not in js and "syntheticTx" in js and "addrText" in js
