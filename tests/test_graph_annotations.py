"""Fund-flow graph annotations (app/tracing/annotate.py): coin, value size, freeze status from the
case's stop orders, recommended stop-order targets, and how the Fund flow tab renders them."""

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import shifted

from app import services
from app.db.models import StopOrderOrigin, StopOrderStatus
from app.tracing import annotate as an
from app.tracing.graph import build_graph, to_cytoscape

KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"
TRON_USDT = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"
CIRCLE_WALLETS = {"0x57de1021a507d46272d386995d5b58667ac1f8df", "0xe9449ba33c8dcf6f859c9bc476b8debab64a4b1b"}


def order(oid=1, recipient="KuCoin", status="requested", cited=(), **kw) -> an.OrderRef:
    return an.OrderRef(id=oid, recipient=recipient, status=status, cited=frozenset(a.lower() for a in cited), **kw)


# --------------------------------------------------------------------------- address matching
def test_cited_addresses_match_full_address_case_insensitively():
    mixed = "0x45300136662dD4e58fc0DF61E6290DFfD992B785"
    cited = an.cited_addresses({"addresses": [mixed]}, "", imported=True)
    status, linked = an.node_freeze(mixed.lower(), None, [order(cited=cited)])
    assert status == "requested" and linked[0]["match"] == "address" and linked[0]["recipient"] == "KuCoin"
    assert an.node_freeze(mixed.upper().replace("0X", "0x"), None, [order(cited=cited)])[0] == "requested"


def test_truncated_and_embedded_forms_never_match():
    body = ("Deposits to 0x0a17ed…a758e2 and 0x0a17ed3e…58e2; tx "
            "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2ffffffffffffffffffffffff; see TWdZZh…eL77.")
    cited = an.cited_addresses({}, body, imported=True)
    assert KUCOIN_DEPOSIT not in cited and TRON_USDT.lower() not in cited
    assert an.node_freeze(KUCOIN_DEPOSIT, None, [order(cited=cited)]) == (None, [])
    # the full form in the body text of an imported letter does match
    cited = an.cited_addresses({}, f"Deposit address: `{KUCOIN_DEPOSIT.upper()[2:]}` / {TRON_USDT}.", imported=True)
    assert TRON_USDT.lower() in cited


def test_generated_orders_cite_their_identifiers_not_the_senders_in_tx_details():
    ids = {"entity": "KuCoin", "addresses": [{"address": KUCOIN_DEPOSIT, "inbound": [{"from": TRON_USDT}]}]}
    cited = an.cited_addresses(ids, f"body mentions {TRON_USDT}", imported=False)
    assert cited == {KUCOIN_DEPOSIT}


def test_imported_letters_only_cite_wallets_they_are_not_addressed_to():
    """An imported letter quotes every full address in its body (peel wallets, prior depositors): a
    wallet it is not addressed to is `cited`, not `requested`; an entity match, a generated order and
    an imported issuer request keep their status."""
    peel = "0x2501aa00000000000000000000000000000000aa"
    letter = order(1, recipient="SWFT / Bridgers", cited=[peel, TRON_USDT], imported=True, kind="preservation")
    status, linked = an.node_freeze(peel, None, [letter])
    assert status == "cited" and linked[0]["match"] == "address" and linked[0]["status"] == "requested"
    assert an.node_freeze("TJ4KeiGTvTZXa6mW8uL1hb2uwYbvUrmVkdZ", "SWFT / Bridgers", [letter])[0] == "requested"
    issuer = order(2, recipient="Tether", cited=[TRON_USDT], imported=True, kind="issuer_blacklist")
    assert an.node_freeze(TRON_USDT, None, [letter, issuer])[0] == "requested"
    generated = order(3, recipient="Tether", cited=[TRON_USDT], kind="issuer_blacklist")
    assert an.node_freeze(TRON_USDT, None, [letter, generated])[0] == "requested"
    draft = order(4, recipient="Tether", status="draft", cited=[TRON_USDT])
    assert an.node_freeze(TRON_USDT, None, [letter, draft])[0] == "draft"  # cited is the weakest status
    assert "cited" in an.FREEZE_STATUS_LABELS


def test_entity_level_match_covers_the_entitys_wallets():
    o = order(recipient="SWFT / Bridgers", cited=())
    status, linked = an.node_freeze("TJ4KeiGTvTZXa6mW8uL1hb2uwYbvUrmVkdZ", "SWFT / Bridgers", [o])
    assert status == "requested" and linked[0]["match"] == "entity"
    assert an.node_freeze("TJ4KeiGTvTZXa6mW8uL1hb2uwYbvUrmVkdZ", "KuCoin", [o]) == (None, [])


def test_strongest_status_wins_and_superseded_orders_are_ignored():
    orders = [order(1, status="declined", cited=[KUCOIN_DEPOSIT]),
              order(2, status="frozen", cited=[KUCOIN_DEPOSIT], amount_held="0.05", asset_held="ETH"),
              order(3, status="requested", cited=[KUCOIN_DEPOSIT])]
    status, linked = an.node_freeze(KUCOIN_DEPOSIT, None, orders)
    assert status == "frozen" and [o["id"] for o in linked] == [2, 3, 1]
    assert linked[0]["amount_held"] == "0.05" and linked[0]["asset_held"] == "ETH"
    assert an.freeze_status_of("sent") == "requested" and an.freeze_status_of("superseded") is None
    assert {an.freeze_status_of(s) for s in ("draft", "acknowledged", "frozen", "declined", "released")} == {
        "draft", "acknowledged", "frozen", "declined", "released"}


# --------------------------------------------------------------------------- recommendations
def cand(entity="Tether (USDT issuer)", kind="issuer_blacklist", taint=1359.9, address=TRON_USDT, priority=60,
         category="stablecoin_issuer"):
    return an.CandidateRef(entity=entity, kind=kind, priority=priority, addresses=[(address, taint)], entity_id=4,
                           category=category)


def test_recommendation_until_a_stop_order_is_sent_to_that_entity():
    recs = an.recommendations([cand()], [])
    assert len(recs) == 1 and recs[0]["short"] == "Tether" and recs[0]["addresses"] == [TRON_USDT]
    assert "blacklist" in recs[0]["reason"]
    # a draft does not suppress it, but is reported
    recs = an.recommendations([cand()], [order(7, recipient="Tether (USDT issuer)", status="draft", url="/x")])
    assert recs[0]["draft_id"] == 7 and recs[0]["draft_url"] == "/x"
    # sent (or any later state) to that entity: no recommendation, even when the order cites nothing
    for st in ("requested", "acknowledged", "frozen", "released"):
        assert an.recommendations([cand()], [order(8, recipient="tether (usdt issuer)", status=st)]) == []
    # a request that was only declined leaves it recommended (as the assistant's /stop-orders plan does)
    recs = an.recommendations([cand()], [order(8, recipient="tether (usdt issuer)", status="declined")])
    assert recs[0]["declined"] and "declined" in recs[0]["reason"]
    assert an.recommendations([cand()], [order(8, recipient="Tether (USDT issuer)", status="declined"),
                                         order(9, recipient="Tether (USDT issuer)", status="requested")]) == []
    # non-custodial services (mixers) get no stop-order recommendation
    assert an.recommendations([cand(entity="Mixer X", kind="preservation", category="mixer")], []) == []
    # a stop order to another entity that cites the wallet does not count
    assert an.recommendations([cand()], [order(9, recipient="SWFT / Bridgers", cited=[TRON_USDT])])


def test_recommendation_threshold_and_order():
    assert an.recommendations([cand(taint=12.0)], []) == []
    recs = an.recommendations([cand(entity="KuCoin", kind="freeze", priority=16, address=KUCOIN_DEPOSIT, taint=145),
                               cand(priority=60)], [])
    assert [r["entity"] for r in recs] == ["Tether (USDT issuer)", "KuCoin"]
    assert an.letter_url(1, recs[0]) == "/cases/1/authorities/entity-4?template=stop_order#generate"


# --------------------------------------------------------------------------- coin, size
def test_coin_is_the_largest_tainted_inflow():
    assert an.node_coin([("ETH", 2807.7), ("USDC", 399247.9)], "ethereum") == "USDC"
    assert an.node_coin([("ETH", 0.0), ("USDT", 0)], "ethereum", [("USDC", 10)]) == "USDC"  # victim: outflow
    assert an.node_coin([], "tron") == "TRX" and an.node_coin([], "bitcoin") == "BTC"
    assert an.node_coin([], "solana") == "OTHER"
    assert an.coin_of("ETH→USDT") == "USDT" and an.coin_of("weth") == "ETH" and an.coin_of("DAI") == "OTHER"
    assert an.coin_color("USDC") == "#2775CA" and an.coin_color("USDT") == "#26A17B"
    assert an.chain_shape("tron") == "diamond" and an.chain_shape("bitcoin") == "hexagon"
    assert an.chain_shape("ethereum") == an.chain_shape("arbitrum") == "ellipse"


def test_node_size_is_sqrt_scaled_and_clamped():
    assert an.node_size(0, 1000) == an.NODE_MIN_PX == 18
    assert an.node_size(1000, 1000) == an.NODE_MAX_PX == 80
    assert an.node_size(5000, 1000) == 80 and an.node_size(-5, 1000) == 18 and an.node_size(10, 0) == 18
    assert an.node_size(250, 1000) == pytest.approx(18 + 62 * 0.5)
    assert an.node_size(1, 1_000_000) >= 18
    assert an.short_usd(53_940) == "$54k" and an.short_usd(5_394) == "$5.4k" and an.short_usd(399_248) == "$399k"


# --------------------------------------------------------------------------- the demo run
@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


@pytest.fixture
def imported_only(monkeypatch):
    """Only the demo's six imported letters (other tests generate and send stop orders on the shared case)."""
    real = an.order_refs

    def refs(case, *, case_id):
        kept = [o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED or o.id >= 9000]
        return real(SimpleNamespace(stop_orders=kept), case_id=case_id)

    monkeypatch.setattr(an, "order_refs", refs)


def _nodes(elements) -> dict[str, dict]:
    return {n["data"]["address"].lower(): n["data"] for n in elements["nodes"]}


def test_demo_graph_marks_imported_stop_orders_and_recommends_the_issuers(db, case, run, imported_only):
    elements = to_cytoscape(build_graph(db, run))
    recs = an.annotate_elements(db, case, run, elements, can_act=True)
    by = _nodes(elements)
    # the six imported letters are sent; Circle and Tether have none
    assert {r["short"] for r in recs} == {"Circle", "Tether"}
    assert all(r["url"].endswith("?template=stop_order#generate") for r in recs)
    assert {a.lower() for r in recs if r["short"] == "Circle" for a in r["addresses"]} == CIRCLE_WALLETS
    assert by[TRON_USDT.lower()]["recommended"]["short"] == "Tether"
    # the USDC left both Circle wallets (swapped to ETH): Circle stays listed, nothing held, no ring on either wallet
    circle = next(r for r in recs if r["short"] == "Circle")
    assert circle["nothing_held"] and circle["held"] == [] and circle["value_usd"] == 0 and "moved on" in circle["reason"]
    assert recs[-1] is circle
    assert all(by[a]["recommended"] is None for a in CIRCLE_WALLETS)
    tether = next(r for r in recs if r["short"] == "Tether")
    assert not tether["nothing_held"] and tether["value_usd"] == pytest.approx(1359.9)
    # KuCoin deposit: covered by KuCoin's letter; SWFT's TRON hot wallet: by entity
    kucoin = by[KUCOIN_DEPOSIT]
    assert kucoin["freeze_status"] == "requested" and kucoin["recommended"] is None
    assert any(o["recipient"] == "KuCoin" and o["match"] == "entity"
               and o["sent_at"] == f"{shifted('2026-10-18T22:27:06Z'):%Y-%m-%d}"
               for o in kucoin["stop_orders"])
    swft_hot = next(d for d in by.values() if d["entity"] == "SWFT / Bridgers" and d["chain"] == "tron")
    assert swft_hot["freeze_status"] == "requested" and swft_hot["stop_orders"][0]["match"] == "entity"
    # Rainbet's deposit, cited in its letter, is not a recommendation (already sent)
    rainbet = next(d for d in by.values() if d["entity"] == "Rainbet")
    assert rainbet["freeze_status"] == "requested" and rainbet["recommended"] is None
    # coin, shape and size
    assert by[TRON_USDT.lower()]["coin"] == "USDT" and by[TRON_USDT.lower()]["shape"] == "diamond"
    assert all(by[a]["coin"] == "USDC" for a in CIRCLE_WALLETS)
    assert all(an.NODE_MIN_PX <= d["size"] <= an.NODE_MAX_PX for d in by.values())
    assert max(d["size"] for d in by.values()) == an.NODE_MAX_PX
    assert {e["data"]["coin"] for e in elements["edges"]} >= {"USDC", "ETH", "USDT", "BTC"}
    # nodes without a stop order carry no freeze_status key (Cytoscape's `node[freeze_status]` matches null too,
    # which gave every node the freeze-node minimum size and flattened the value scale)
    unfrozen = [d for d in by.values() if not d.get("freeze_status")]
    assert unfrozen and all("freeze_status" not in d for d in unfrozen)
    # no contact data: recipient organisation only
    blob = json.dumps(elements)
    assert "@" not in blob and "recipient_email" not in blob


def test_demo_letters_mark_cited_wallets_as_cited(db, case, run, imported_only):
    elements = to_cytoscape(build_graph(db, run))
    an.annotate_elements(db, case, run, elements, can_act=True)
    by = _nodes(elements)
    tron = by[TRON_USDT.lower()]
    assert tron["freeze_status"] == "cited" and tron["recommended"]["short"] == "Tether"
    assert all(o["match"] == "address" for o in tron["stop_orders"])
    assert by[KUCOIN_DEPOSIT]["freeze_status"] == "requested"


def _fake_order(oid, entity, status, *, origin=StopOrderOrigin.GENERATED, addresses=(), hold=None,
                kind="issuer_blacklist"):
    return SimpleNamespace(
        id=oid, entity=entity, status=StopOrderStatus(status), origin=origin, body_markdown="", correspondence=[],
        kind=kind,
        sent_at=datetime(2026, 10, 19, tzinfo=UTC) if status != "draft" else None,
        identifiers={"entity": entity.name, "addresses": [{"address": a} for a in addresses],
                     **({"hold": hold} if hold else {})})


def test_draft_then_sent_then_frozen_to_tether(db, case, run, imported_only):
    tether = next(c.entity for c in services.freeze_candidates(db, run) if c.entity_name.startswith("Tether"))

    def annotate_with(*extra):
        fake_case = SimpleNamespace(id=case.id, stop_orders=list(case.stop_orders) + list(extra))
        elements = to_cytoscape(build_graph(db, run))
        return an.annotate_elements(db, fake_case, run, elements, can_act=True), _nodes(elements)

    recs, by = annotate_with(_fake_order(9001, tether, "draft", addresses=[TRON_USDT]))
    rec = next(r for r in recs if r["short"] == "Tether")
    assert rec["draft_id"] == 9001 and rec["url"] == f"/cases/{case.id}/stop-orders/9001"
    # the draft is listed after SWFT's sent letter (which only cites the wallet): the draft to the issuer is the
    # stronger status, since the SWFT letter asked no freeze of this self-custody wallet
    assert [o["id"] for o in by[TRON_USDT.lower()]["stop_orders"]][-1] == 9001
    assert by[TRON_USDT.lower()]["freeze_status"] == "draft"

    recs, by = annotate_with(_fake_order(9002, tether, "sent", addresses=[TRON_USDT]))
    assert "Tether" not in {r["short"] for r in recs} and by[TRON_USDT.lower()]["recommended"] is None
    assert {o["id"] for o in by[TRON_USDT.lower()]["stop_orders"]} >= {9002}

    recs, by = annotate_with(_fake_order(9003, tether, "frozen", addresses=[TRON_USDT],
                                         hold={"state": "frozen", "amount": "1359.9", "asset": "USDT"}))
    node = by[TRON_USDT.lower()]
    assert node["freeze_status"] == "frozen"
    assert node["stop_orders"][0] == {"id": 9003, "recipient": tether.name, "status": "frozen", "sent_at": "2026-10-19",
                                      "url": f"/cases/{case.id}/stop-orders/9003", "match": "address",
                                      "amount_held": "1359.9", "asset_held": "USDT"}


# --------------------------------------------------------------------------- the Fund flow tab
def _graph_json(html: str) -> dict:
    m = re.search(r'<script id="graph-data" type="application/json">(.*?)</script>', html, re.DOTALL)
    assert m
    return json.loads(m.group(1))


@pytest.fixture
def fresh(db, tmp_path):
    """A fresh copy of the demo case, traced: the tab follows the Recovery plan, which reads the case's on-chain
    readings and requests (other tests add both to the shared demo case)."""
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def test_tab_shows_recommended_actions_with_letter_links_for_investigators(client_for, fresh):
    case = fresh
    page = client_for("investigator", case=case).get(f"/cases/{case.id}?tab=fund_flow").text
    assert 'id="ff-recs"' in page and "Stop order → Tether" in page
    # the USDC moved on: Circle is listed with the Recovery plan's value (—) and next step, never as a stop order
    assert "Stop order → Circle" not in page and "Circle: nothing held to blacklist" in page
    assert "Next (Recovery plan #" in page and f'href="/cases/{case.id}/recovery-plan#m-entity-' in page
    assert re.search(rf'href="/cases/{case.id}/authorities/entity-\d+\?template=stop_order#generate"', page)
    assert "Legend &amp; filters" in page and 'data-ff-show="nodust"' in page
    nodes = _graph_json(page)["nodes"]
    assert any(n["data"]["recommended"] and n["data"]["recommended"]["url"] for n in nodes)
    assert sum(1 for n in nodes if n["data"].get("freeze_status")) >= 6


def test_read_only_sees_the_list_without_buttons(client_for, fresh):
    page = client_for("read_only", case=fresh).get(f"/cases/{fresh.id}?tab=fund_flow").text
    assert "Stop order → Tether" in page and "Generate letter" not in page and "template=stop_order" not in page
    nodes = _graph_json(page)["nodes"]
    recs = [n["data"]["recommended"] for n in nodes if n["data"]["recommended"]]
    assert recs and all(r["url"] is None for r in recs)


def test_read_only_graph_json_has_no_letter_links(client_for, case, run, imported_only):
    r = client_for("read_only", case=case).get(f"/api/cases/{case.id}/trace/{run.id}/graph")
    assert r.status_code == 200, r.text
    recs = r.json()["recommendations"]
    assert recs and all(x["url"] is None and x["draft_url"] is None and x["entity_id"] is None
                        and x["draft_id"] is None and "drafted" in x for x in recs)
    nodes = r.json()["elements"]["nodes"]
    assert all(n["data"]["recommended"]["draft_id"] is None for n in nodes if n["data"].get("recommended"))


def test_graph_and_assistant_recommend_the_same_services(db, case, run):
    """The Fund flow callouts and the assistant's /stop-orders plan name the same services, whatever
    stop orders other tests have generated or sent on the shared demo case."""
    from app.ai.skills import stop_order_plan

    elements = to_cytoscape(build_graph(db, run))
    graph = {r["entity"] for r in an.annotate_elements(db, case, run, elements, can_act=True)}
    plan = {r["entity"] for r in stop_order_plan(db, case, run)["rows"]
            if r["status"] in ("recommended", "declined", "draft")
            and any(w["taint_usd"] >= an.RECOMMEND_MIN_USD for w in r["wallets"])}
    assert graph == plan


def test_graph_js_freeze_selectors_match_only_real_statuses():
    js = (Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "graph.js").read_text()
    assert "[?freeze_status]" in js
    assert not re.search(r"\[freeze_status\]", js)


def test_demo_freeze_styling_reaches_only_nodes_with_a_stop_order(client_for, case, run, imported_only):
    """The demo's six imported letters: 6 nodes requested, 9 cited; the other 21 carry no freeze_status key,
    so none of graph.js's freeze rules can style them."""
    from collections import Counter

    nodes = _graph_json(client_for("investigator", case=case).get(f"/cases/{case.id}?tab=fund_flow").text)["nodes"]
    counts = Counter(n["data"].get("freeze_status") for n in nodes)
    assert len(nodes) == 36 and counts == {None: 21, "cited": 9, "requested": 6}, counts
    assert sum("freeze_status" in n["data"] for n in nodes) == 15


NODE = shutil.which("node")
CYTOSCAPE = Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "vendor" / "cytoscape.min.js"


@pytest.mark.skipif(NODE is None, reason="needs Node.js to evaluate the Cytoscape selectors")
def test_graph_js_freeze_selectors_on_the_demo_graph(client_for, case, run, imported_only, tmp_path):
    """Every freeze-status selector in graph.js, evaluated by the vendored Cytoscape (headless) on the demo
    graph: the generic rule matches exactly the 15 nodes with a stop order, a per-status rule exactly its own
    nodes, and a node with freeze_status null (the old payload) matches none."""
    js = (Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "graph.js").read_text()
    selectors = sorted(set(re.findall(r'selector: "(node\[[^"]*freeze_status[^"]*\])"', js)))
    assert "node[?freeze_status]" in selectors and "node[freeze_status = 'requested']" in selectors
    elements = _graph_json(client_for("investigator", case=case).get(f"/cases/{case.id}?tab=fund_flow").text)
    nodes = [{"data": {k: v for k, v in n["data"].items() if k in ("id", "freeze_status")}} for n in elements["nodes"]]
    nodes.append({"data": {"id": "legacy-null", "freeze_status": None}})
    script = tmp_path / "selectors.js"
    script.write_text(
        f"const cytoscape = require({json.dumps(str(CYTOSCAPE))});\n"
        f"const cy = cytoscape({{ headless: true, elements: {json.dumps(nodes)} }});\n"
        f"const out = {{}};\n"
        f"for (const s of {json.dumps(selectors)}) out[s] = cy.nodes(s).map(n => n.id());\n"
        "console.log(JSON.stringify(out));\n")
    res = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=60, check=True)
    matched = json.loads(res.stdout)
    status = {n["data"]["id"]: n["data"].get("freeze_status") for n in nodes}
    assert len(matched["node[?freeze_status]"]) == 15
    assert set(matched["node[?freeze_status]"]) == {i for i, s in status.items() if s}
    assert len(matched["node[freeze_status = 'requested']"]) == 6
    assert len(matched["node[freeze_status = 'cited']"]) == 9
    for sel, ids in matched.items():
        assert "legacy-null" not in ids, sel
        assert all(status[i] for i in ids), sel
