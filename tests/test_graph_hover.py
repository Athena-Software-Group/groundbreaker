"""Fund-flow hover cards (app/tracing/hover.py, static/graph.js): what went through each wallet and when, its current
status (the latest good on-chain reading, a later failed check apart, watch alerts, flags), its owner (a service's
float, a possible hot wallet), the authority that can act with its request status and the Recovery plan's next move,
role redactions, and the Fund flow page embedding `data.hover`. The demo case plus synthetic readings and
replies (every number is made up). Offline: no model, no mail, no chain."""

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import select

from app import services
from app.ai import providers
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.core.permissions import CaseAccess
from app.db.models import CaseRole, Entity, FreezeCheck, StopOrder, StopOrderStatus
from app.tracing.annotate import annotate_elements
from app.tracing.graph import build_graph, to_cytoscape
from app.tracing.hover import TOP_TRANSFERS, amount_text, hover_data, short_tx

TRON_USDT = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"
KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"
VICTIM = "0x7ac32c"
NOW = datetime.now(tz=UTC)
TETHER_ACK = ("Thank you for contacting Tether Compliance.\n\nThis is an automated response. Your request has been "
              "received and ticket #482913 has been created. Tether will only act upon appropriate legal process "
              "submitted by a law enforcement agency.\n\nTether Compliance")
GRAPH_JS = Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "graph.js"


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


def _access(case, role=CaseRole.INVESTIGATOR):
    return CaseAccess(case=case, user=None, role=role, member=None)


def _hover(db, case, role=CaseRole.INVESTIGATOR, **kw) -> dict[str, dict]:
    db.expire_all()
    run = services.latest_run(db, case)
    elements = to_cytoscape(build_graph(db, run))
    annotate_elements(db, case, run, elements, can_act=True)
    hover_data(db, case, run, elements, _access(case, role), **kw)
    return {n["data"]["address"].lower(): n["data"] for n in elements["nodes"]} | {"_edges": elements["edges"]}


def _traced_at(db, case) -> datetime:
    """When the case's latest trace ran: a reading or alert "after the trace" is timed from it, never from the module's
    NOW (read at import: in a long run the trace starts minutes later, and NOW + 1 min falls before it)."""
    run = services.latest_run(db, case)
    at = run.finished_at or run.started_at
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def _node(by, start: str) -> dict:
    return next(d for k, d in by.items() if k != "_edges" and k.startswith(start.lower()))


def _reading(db, case, address, balance, *, at, status="ok", blacklisted=False, error=None):
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=address, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status=status, error=error,
                       blacklisted=blacklisted if status == "ok" else None,
                       balance=Decimal(balance) if balance is not None else None, checked_at=at,
                       block_number=71_000_000 if status == "ok" else None, raw_sha256="ab" * 32,
                       meta={"balance_raw": str(int(Decimal(balance) * 10**6))} if balance is not None else {}))
    db.commit()


# --------------------------------------------------------------------------- what went through, and when
def test_flows_totals_times_and_top_transfers(db, case):
    by = _hover(db, case)
    victim = _node(by, VICTIM)["hover"]["flows"]
    assert victim["in"]["n"] == 0 and victim["out"]["n"] == 1
    assert victim["out"]["usd"] == pytest.approx(399247.92) and victim["out"]["assets"] == ["399,247.92 USDC"]
    assert victim["first"] == victim["last"] == "12 Oct 2026 10:49 UTC"
    t = victim["top"][0]
    assert t["dir"] == "out" and t["amount"] == "399,247.92 USDC" and t["party"].startswith("Perpetrator")
    assert t["tx"].startswith("0x70ab") and "…" in t["tx"]
    kucoin = by[KUCOIN_DEPOSIT]["hover"]["flows"]
    # four inflows: the case's one (priced) and three asserted pre-fraud deposits without an amount, counted apart and
    # never in the totals (no "+"); one sweep out to the KuCoin hot wallet
    assert kucoin["in"]["n"] == 1 and kucoin["in"]["usd"] == pytest.approx(144.94) and not kucoin["in"]["partial"]
    assert not kucoin["in"]["asserted"] and kucoin["out"]["n"] == 1
    # the first / last *case* transfer: the pre-fraud context deposits apart, an asserted date without a time of day
    assert kucoin["first"] == "14 Oct 2026 10:07 UTC" and kucoin["last"] == "14 Oct 2026 10:14 UTC"
    assert kucoin["context"] == 3
    assert any(x["dir"] == "out" and x["party"] == "KuCoin" for x in kucoin["top"])
    assert any(x["asserted"] and x["tx"] == "asserted" for x in kucoin["top"])
    assert {x["at"] for x in kucoin["top"] if x["asserted"]} >= {"12 Sep 2026, asserted"}
    assert all(x["context"] for x in kucoin["top"] if x["asserted"]) and "00:00" not in json.dumps(kucoin)
    # the case's transfers come first, the pre-fraud context after them
    ctx = [x["context"] for x in kucoin["top"]]
    assert ctx == sorted(ctx) and not ctx[0]
    assert all(len(d["hover"]["flows"]["top"]) <= TOP_TRANSFERS for k, d in by.items() if k != "_edges")
    # the top transfers are listed oldest first
    hub = _node(by, "0x54453e")["hover"]["flows"]
    assert hub["out"]["n"] > TOP_TRANSFERS >= len(hub["top"])
    stamps = [datetime.strptime(x["at"][:11], "%d %b %Y") for x in hub["top"]]  # an asserted one: its date alone
    assert stamps == sorted(stamps)
    # every drawn link of a traced movement has its own card
    edges = [e["data"] for e in by["_edges"] if not e["data"].get("virtual")]
    assert edges and all(e["hover"]["n"] >= 1 and e["hover"]["transfers"] for e in edges)
    # a link runs source -> target: its transfers carry no in / out direction
    assert all(t["dir"] is None for e in by["_edges"] for t in e["data"]["hover"]["transfers"])
    assert amount_text(Decimal("0.0568388100"), "ETH") == "0.0568 ETH" and short_tx("ASSERTED:x") == "asserted"


# --------------------------------------------------------------------------- current status
def test_a_failed_check_after_a_good_reading_never_hides_it(db, case):
    _reading(db, case, TRON_USDT, "1359.9", at=NOW - timedelta(hours=3))
    _reading(db, case, TRON_USDT, None, at=NOW - timedelta(minutes=10), status="error", error="timeout")
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    (c,) = st["onchain"]
    assert c["issuer"] == "Tether" and c["balance"] == "1,359.90 USDT" and c["usd"] == pytest.approx(1359.9, rel=0.01)
    assert c["blacklisted"] is False and c["checked"] is not None
    assert c["failed"] and c["failed"]["error"] == "timeout" and c["failed"]["at"] != c["checked"]
    assert st["tags"] and any(t["t"] == "issuer-freezable" for t in st["tags"])
    # a later good reading clears the failure; a blacklisted one says so
    _reading(db, case, TRON_USDT, "1359.9", at=NOW - timedelta(minutes=1), blacklisted=True)
    (c,) = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]["onchain"]
    assert c["blacklisted"] is True and c["failed"] is None


def test_watch_alerts_after_the_trace_show_as_movement(db, case):
    from app.db.models import Address, Alert, WatchItem

    addr = db.scalar(select(Address).where(Address.address == TRON_USDT))
    w = db.scalar(select(WatchItem).where(WatchItem.case_id == case.id, WatchItem.address_id == addr.id))
    if w is None:
        w = WatchItem(case_id=case.id, address_id=addr.id, active=True)
        db.add(w)
        db.flush()
    db.add(Alert(watch_item_id=w.id, message="Outgoing transfer (synthetic)",
                 created_at=_traced_at(db, case) + timedelta(minutes=1)))
    db.commit()
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    assert st["watched"] and st["alerts"]["n"] == 1 and st["alerts"]["last"]


# --------------------------------------------------------------------------- owner
def test_owner_of_a_service_wallet_and_of_unhosted_ones(db, case):
    by = _hover(db, case)
    o = by[KUCOIN_DEPOSIT]["hover"]["owner"]
    assert o["name"] == "KuCoin" and o["category"] == "exchange" and o["known"] and o["source"] == "trace"
    unhosted = _node(by, "0x9cf838")["hover"]["owner"]
    assert not unhosted["known"] and unhosted["name"] is None and unhosted["category_label"] == "unhosted wallet"
    assert not unhosted["self_custody"]
    # the victim's and the perpetrator's own wallets: no "unknown" owner
    v = _node(by, VICTIM)["hover"]["owner"]
    assert v["self_custody"] and v["category_label"] == "the victim"
    assert _node(by, "0x57de10")["hover"]["owner"]["self_custody"]
    # the SWFT TRON payout wallet holds USDT: that is SWFT's float, not the case's balance
    swft = next(d for k, d in by.items() if k != "_edges" and d["entity"] == "SWFT / Bridgers" and d["chain"] == "tron")
    _reading(db, case, swft["address"], "1030000", at=NOW - timedelta(minutes=5))
    o = _hover(db, case)[swft["address"].lower()]["hover"]["owner"]
    assert "SWFT / Bridgers's float" in o["float"] and "not the case's balance" in o["float"] and o["pooled"] is None
    # an unattributed wallet holding far more than was traced in: possibly a service hot wallet
    _reading(db, case, TRON_USDT, "1030000", at=NOW - timedelta(minutes=5))
    o = _hover(db, case)[TRON_USDT.lower()]["hover"]["owner"]
    assert o["float"] is None and "possibly an exchange / service hot wallet" in o["pooled"]


# --------------------------------------------------------------------------- authority
def test_authority_request_status_and_next_move(db, case):
    by = _hover(db, case)
    (k,) = by[KUCOIN_DEPOSIT]["hover"]["authorities"]
    assert k["name"] == "KuCoin" and k["role"] == "account holder"
    assert re.fullmatch(r"Sent \d\d \w{3} — awaiting reply, (due|overdue since) \d\d \w{3}", k["status"]), k["status"]
    assert k["next"] is None and k["cited"] is True  # only waiting: no "Next" repeating the status
    # the TRON USDT wallet: Tether can blacklist it, nobody asked yet; the plan's move says so
    (t,) = by[TRON_USDT.lower()]["hover"]["authorities"]
    assert t["name"] == "Tether" and t["role"] == "issuer blacklist" and t["status"] == "No request sent yet"
    # Tether acts on LE process only: the plan's move is the board row's LE step (freeze_board.provider_target)
    assert "Tether" in t["next"] and ("Brief" in t["next"] or "LE" in t["next"]), t["next"]
    # the plan is the latest run's: an older run's card shows no moves
    assert _hover(db, case, current=False)[TRON_USDT.lower()]["hover"]["authorities"][0]["next"] is None
    # a stop order sent to Tether citing the wallet, then Tether's automatic acknowledgement with a ticket
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    sent = NOW - timedelta(days=2)
    order = StopOrder(case=case, entity=tether, kind="issuer_blacklist", status=StopOrderStatus.SENT,
                      subject="Blacklist request", body_markdown=f"Please blacklist {TRON_USDT}.", sent_at=sent,
                      sent_via="email", recipient_email="desk@issuer-demo.example",
                      identifiers={"chain": "tron", "addresses": [{"chain": "tron", "address": TRON_USDT}]})
    db.add(order)
    db.commit()
    (t,) = _hover(db, case)[TRON_USDT.lower()]["hover"]["authorities"]
    assert t["status"].startswith(f"Sent {sent:%d %b} — awaiting reply") and t["tone"] == "blue"
    from test_block_status import _reply

    _reply(db, case, order, TETHER_ACK, at=sent + timedelta(hours=2), mailbox=True)
    (t,) = _hover(db, case)[TRON_USDT.lower()]["hover"]["authorities"]
    assert "ticket #482913" in t["status"] and f"sent {sent:%d %b}" in t["status"]
    assert t["status"] != "No request sent yet" and t["step"]


# --------------------------------------------------------------------------- roles
def test_read_only_members_get_the_masked_texts_and_no_reply_moves(db, case):
    rows = bs.case_blocks(db, case)
    row = next(r for r in rows if r.authority.name == "KuCoin")
    ref = "DEMO-IT-0000000000"  # the demo's complaint reference, quoted back as the provider's ticket
    row.ticket = ref
    plan = rp.build(db, case, rows=rows)
    plan.moves.append(rp.Move(key=f"fwatch:ethereum:{KUCOIN_DEPOSIT}", kind="watch", title="Watch the wallet the reply "
                              "names", text="A reply names this wallet.", sensitive=True))
    inv = _hover(db, case, rows=rows, plan=plan)[KUCOIN_DEPOSIT]["hover"]
    ro = _hover(db, case, CaseRole.READ_ONLY, rows=rows, plan=plan)[KUCOIN_DEPOSIT]["hover"]
    assert ref in inv["authorities"][0]["status"] and inv["move"] == "Watch the wallet the reply names"
    assert ref not in ro["authorities"][0]["status"] and "ticket #" in ro["authorities"][0]["status"]
    assert ro["move"] is None
    assert ro["flows"] == inv["flows"] and ro["owner"] == inv["owner"]


# --------------------------------------------------------------------------- the page
def _graph_json(html: str) -> dict:
    m = re.search(r'<script id="graph-data" type="application/json">(.*?)</script>', html, re.DOTALL)
    assert m
    return json.loads(m.group(1))


@pytest.mark.parametrize("role", ["investigator", "read_only"])
def test_fund_flow_page_embeds_the_hover_data(client_for, db, case, role):
    from test_block_status import CIRCLE_LIKE, _order, _reply

    _reply(db, case, _order(case, "KuCoin"), CIRCLE_LIKE)  # a redirect naming the addresses to resend to
    page = client_for(role, case=case).get(f"/cases/{case.id}?tab=fund_flow")
    assert page.status_code == 200
    g = _graph_json(page.text)
    assert all({"flows", "status", "owner", "authorities"} <= set(n["data"]["hover"]) for n in g["nodes"])
    assert all(e["data"].get("hover") for e in g["edges"])
    k = next(n["data"]["hover"] for n in g["nodes"] if n["data"]["address"].lower() == KUCOIN_DEPOSIT)
    assert k["authorities"][0]["status"].startswith("Redirected")
    blob = json.dumps([n["data"]["hover"] for n in g["nodes"]] + [e["data"]["hover"] for e in g["edges"]])
    assert "@" not in blob and "http" not in blob and "/cases/" not in blob  # no contact data, no links
    assert "<script" not in blob.lower()


def test_an_older_run_shows_no_plan_moves(client_for, db, case):
    old = services.latest_run(db, case)
    services.run_trace(db, case, provider_mode="fixture")
    c = client_for("investigator", case=case)
    tron = {}
    for q in ("", f"&run_id={old.id}"):
        g = _graph_json(c.get(f"/cases/{case.id}?tab=fund_flow{q}").text)
        tron[q] = next(n["data"]["hover"] for n in g["nodes"] if n["data"]["address"] == TRON_USDT)
    assert tron[""]["authorities"][0]["next"] and tron[f"&run_id={old.id}"]["authorities"][0]["next"] is None


def test_graph_js_hover_card_is_text_only_and_desktop_only():
    src = GRAPH_JS.read_text(encoding="utf-8")
    hover = src[src.index("hover cards (data.hover"):src.index("focus (find, recommended actions)")]
    assert "innerHTML" not in hover and "textContent" in hover
    assert '"(hover: hover) and (pointer: fine)"' in hover and 'cy.on("viewport tapstart grab", hideTip)' in hover
    node = shutil.which("node")
    if node:
        r = subprocess.run([node, "--check", str(GRAPH_JS)], check=False, capture_output=True, text=True,
                           timeout=60)
        assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------- review fixes
def test_swap_legs_count_on_the_swap_contract_and_the_payout_wallets(db, case):
    by = _hover(db, case)
    swft = {d["chain"]: d for k, d in by.items() if k != "_edges" and d.get("entity") == "SWFT / Bridgers"}
    out = swft["ethereum"]["hover"]["flows"]["out"]
    assert out["n"] == 2 and out["swaps"] == ["ETH→BTC", "ETH→USDT"] and out["taint_usd"] == pytest.approx(2617.02)
    assert not out["partial"]  # a swap leg has no price of its own: not an unpriced transfer
    assert {t["party"] for t in swft["ethereum"]["hover"]["flows"]["top"] if t["swap"]} == {
        "SWFT / Bridgers (bitcoin)", "SWFT / Bridgers (tron)"}
    for chain, asset in (("tron", "ETH→USDT"), ("bitcoin", "ETH→BTC")):
        i = swft[chain]["hover"]["flows"]["in"]
        assert i["n"] == 1 and i["swaps"] == [asset] and i["taint_usd"] > 0
    virtual = [e["data"] for e in by["_edges"] if e["data"].get("virtual")]
    assert len(virtual) == 2 and all(e["hover"]["swaps"] and e["hover"]["transfers"][0]["swap"] for e in virtual)
    assert all("→" in e["hover"]["transfers"][0]["tx"] for e in virtual)


def test_records_only_services_and_wallets_nobody_can_freeze(db, case):
    by = _hover(db, case)
    (u,) = _node(by, "0x23617e")["hover"]["authorities"]  # Uniswap: a DEX
    assert u["tone"] == "neutral" and "records request optional" in u["status"]
    btc = next(d for k, d in by.items() if k.startswith("bc1p"))["hover"]
    # an unhosted wallet whose owner is not identified: maybe an unlabelled service wallet, never "self-custody"
    assert btc["authorities"] == [] and btc["no_authority"] == (
        "No known custodian or token issuer: identify the owner, watch, or trace further")
    perp = [d["hover"] for k, d in by.items() if k != "_edges" and d["type"] == "perpetrator"
            and d["hover"]["authorities"] == []]
    assert all(h["no_authority"].startswith("No one can freeze this: self-custody") for h in perp)
    pending = next(d for k, d in by.items() if k.startswith("usdt_dest"))["hover"]
    assert pending["no_authority"] == "Resolve the placeholder address first"
    assert _node(by, VICTIM)["hover"]["no_authority"] is None
    # the KuCoin hot wallet: the stop order names the deposit address only
    from app.db.models import StopOrder

    kucoin = next(o for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))
                  if o.entity is not None and o.entity.name == "KuCoin")
    kucoin.identifiers = {"addresses": [{"chain": "ethereum", "address": KUCOIN_DEPOSIT}]}
    kucoin.body_markdown = f"Please freeze {KUCOIN_DEPOSIT}."
    db.commit()
    by = _hover(db, case)
    hot = next(d for k, d in by.items() if k != "_edges" and d.get("entity") == "KuCoin" and d["type"] == "hot_wallet")
    assert hot["hover"]["authorities"][0]["cited"] is False and by[KUCOIN_DEPOSIT]["hover"]["authorities"][0]["cited"]


def test_an_acknowledged_request_has_no_next_line_repeating_it(db, case):
    by = _hover(db, case)
    (r,) = next(d for k, d in by.items() if k != "_edges" and d.get("entity") == "Rainbet")["hover"]["authorities"]
    assert r["status"].startswith("Acknowledged — ticket #") and r["next"] is None


def test_a_redirect_never_puts_the_address_it_names_in_the_card(db, case):
    from test_block_status import CIRCLE_LIKE, _order, _reply

    _reply(db, case, _order(case, "KuCoin"), CIRCLE_LIKE)
    for role in (CaseRole.INVESTIGATOR, CaseRole.READ_ONLY):
        by = _hover(db, case, role)
        (k,) = by[KUCOIN_DEPOSIT]["hover"]["authorities"]
        assert k["status"].startswith("Redirected: resend to the address their reply names"), k["status"]
        blob = json.dumps([d["hover"] for key, d in by.items() if key != "_edges"])
        assert "@" not in blob and "http" not in blob


def test_scrub_removes_e_mail_addresses_and_urls():
    from app.tracing.hover import scrub

    assert scrub("Resend to a.b+c@x-demo.example or https://portal.example/x?y=1 now") == (
        "Resend to [address withheld] or [address withheld] now")
    assert scrub(None) is None and scrub("Sent 18 Oct — awaiting reply") == "Sent 18 Oct — awaiting reply"


def test_a_failing_part_says_unavailable_never_the_no_data_defaults(db, case, monkeypatch, caplog):
    from sqlalchemy import text

    from app.tracing import hover

    def broken(db_, run):
        db_.execute(text("SELECT secret_param FROM no_such_table WHERE x = :x"), {"x": KUCOIN_DEPOSIT})

    monkeypatch.setattr(hover, "_movements", broken)
    monkeypatch.setattr(bs, "case_blocks", lambda *a, **k: 1 / 0)
    monkeypatch.setattr(hover, "_readings", lambda *a, **k: 1 / 0)
    with caplog.at_level("WARNING", logger="app.tracing.hover"):
        by = _hover(db, case)
    h = by[KUCOIN_DEPOSIT]["hover"]
    assert h["flows"] is None and h["authorities"] is None and h["status"]["onchain"] is None
    assert h["no_authority"] is None and h["owner"]["name"] == "KuCoin"
    # the watch list still read after the failed statement (its savepoint rolled back, the session usable)
    assert h["status"]["watched"] is not None
    assert all(e["data"].get("hover") is None for e in by["_edges"] if not e["data"].get("virtual"))
    msgs = [r for r in caplog.records if r.name == "app.tracing.hover"]
    assert {"OperationalError", "ZeroDivisionError"} <= {m.getMessage().rsplit("(", 1)[-1].rstrip(")") for m in msgs}
    assert all(r.exc_info is None and KUCOIN_DEPOSIT not in r.getMessage() for r in msgs)


def test_one_failing_element_loses_its_card_only(db, case, monkeypatch):
    from app.tracing import hover

    real = hover._authorities

    def flaky(d, *a, **k):
        if d.get("address") == KUCOIN_DEPOSIT:
            raise AttributeError("unexpected row shape")
        return real(d, *a, **k)

    monkeypatch.setattr(hover, "_authorities", flaky)
    by = _hover(db, case)
    assert "hover" not in by[KUCOIN_DEPOSIT] and by[TRON_USDT.lower()]["hover"]["authorities"]


# --------------------------------------------------------------------------- second review
def test_the_pass_never_runs_one_query_per_node(db, case):
    """desk.case_authorities and the plan's wallet moves read the run's addresses in one query, not one per node."""
    from collections import Counter

    from sqlalchemy import event

    db.expire_all()
    run = services.latest_run(db, case)
    elements = to_cytoscape(build_graph(db, run))
    annotate_elements(db, case, run, elements, can_act=True)
    stmts: list[str] = []

    def seen(conn, cursor, statement, *a):
        stmts.append(statement)

    event.listen(db.get_bind(), "before_cursor_execute", seen)
    try:
        hover_data(db, case, run, elements, _access(case))
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", seen)
    nodes = len(elements["nodes"])
    assert nodes > 30 and all(n["data"].get("hover") for n in elements["nodes"] if not n["data"].get("callout"))
    per_node = [s for s in stmts if re.match(r"\s*SELECT (addresses|trace_nodes|entities)\.", s)]
    # a handful of passes over the run (candidates, holdings, wallet moves), each one query: never one per node
    assert per_node and len(per_node) < nodes and max(Counter(per_node).values()) <= 6


def test_an_unpriced_on_chain_transfer_is_not_called_asserted(db, case):
    from app.db.models import Address, Transfer

    addr = db.scalar(select(Address).where(Address.address == TRON_USDT))
    t = db.scalar(select(Transfer).where(Transfer.to_address_id == addr.id))
    assert t.amount is not None and not t.tx_hash.startswith("ASSERTED")
    usd, t.amount_usd = t.amount_usd, None  # transfers are shared by every case of the test database: put it back
    db.commit()
    try:
        i = _hover(db, case)[TRON_USDT.lower()]["hover"]["flows"]["in"]
    finally:
        t = db.get(Transfer, t.id)
        t.amount_usd = usd
        db.commit()
    assert i["partial"] and i["unpriced"] and not i["asserted"] and i["assets"] == ["1,359.9 USDT"]
    src = GRAPH_JS.read_text(encoding="utf-8")
    assert 'if (s.asserted) p.push("amount not on-chain (asserted)")' in src and '"no USD price"' in src


def test_a_failed_recovery_plan_says_the_next_move_is_unavailable(db, case, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("plan")

    monkeypatch.setattr(rp, "build", broken)
    h = _hover(db, case)[TRON_USDT.lower()]["hover"]
    assert h["next_unavailable"] is True and h["move"] is None and h["authorities"][0]["status"]
    assert "Next move unavailable (could not be read)" in GRAPH_JS.read_text(encoding="utf-8")
    monkeypatch.undo()
    assert _hover(db, case)[TRON_USDT.lower()]["hover"]["next_unavailable"] is False
    # an older run shows no moves by design: not "unavailable", and the plan is not built for it
    monkeypatch.setattr(rp, "build", broken)
    assert _hover(db, case, current=False)[TRON_USDT.lower()]["hover"]["next_unavailable"] is False


def test_an_acknowledged_movement_alert_is_still_movement(db, case):
    from app.db.models import Address, Alert, WatchItem

    addr = db.scalar(select(Address).where(Address.address == TRON_USDT))
    w = db.scalar(select(WatchItem).where(WatchItem.case_id == case.id, WatchItem.address_id == addr.id))
    if w is None:
        w = WatchItem(case_id=case.id, address_id=addr.id, active=True)
        db.add(w)
        db.flush()
    w.last_checked_at = None
    db.commit()
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    assert st["watched"] and st["alerts"] is None and st["checked"] is None  # not checked since: no "no movement"
    traced = _traced_at(db, case)
    w.last_checked_at = traced + timedelta(minutes=2)
    db.add(Alert(watch_item_id=w.id, message="Outgoing transfer (synthetic)", created_at=traced + timedelta(minutes=1),
                 acknowledged=True))
    db.commit()
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    assert st["alerts"] == {"n": 1, "unacknowledged": 0, "last": st["alerts"]["last"]} and st["alerts"]["last"]
    assert st["checked"]
    src = GRAPH_JS.read_text(encoding="utf-8")
    assert "if (al && al.n)" in src and "not checked since the trace" in src


def test_a_swap_payout_wallet_shows_what_was_traced_through_it(db, case):
    by = _hover(db, case)
    swft = next(d for k, d in by.items() if k != "_edges" and d.get("entity") == "SWFT / Bridgers"
                and d["chain"] == "tron")
    assert swft["taint_usd"] == 0
    t = swft["hover"]["status"]["taint"]
    assert t["through"] and t["usd"] == pytest.approx(swft["hover"]["flows"]["in"]["taint_usd"]) and t["usd"] > 1000
    assert 0 < t["share"] < 0.01
    k = by[KUCOIN_DEPOSIT]["hover"]["status"]["taint"]
    assert not k["through"] and 0 < k["share"] < 0.001
    assert '"<0.1"' in GRAPH_JS.read_text(encoding="utf-8")


def test_an_issuer_freezable_wallet_never_checked_says_so(db, case):
    (c,) = _node(_hover(db, case), "0x57de10")["hover"]["status"]["onchain"]
    assert c["unchecked"] and c["issuer"] == "Circle" and c["symbol"] == "USDC" and c["checked"] is None
    _reading(db, case, TRON_USDT, "1359.9", at=NOW - timedelta(minutes=5))
    (c,) = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]["onchain"]
    assert not c["unchecked"] and "_at" not in c


def test_a_balance_that_dropped_after_the_trace_says_funds_left(db, case):
    traced = _traced_at(db, case)
    _reading(db, case, TRON_USDT, "1359.9", at=traced)
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    assert not st["dropped"] and "dormant" in {t["t"] for t in st["tags"]}
    _reading(db, case, TRON_USDT, "0", at=traced + timedelta(minutes=1))
    st = _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]
    tags = {t["t"] for t in st["tags"]}
    assert st["dropped"] and "dormant" not in tags and "dormant at the trace" in tags
    assert "funds left this wallet" in GRAPH_JS.read_text(encoding="utf-8")
    # blacklisted with nothing left: not a drop to chase
    _reading(db, case, TRON_USDT, "0", at=traced + timedelta(minutes=2), blacklisted=True)
    assert not _hover(db, case)[TRON_USDT.lower()]["hover"]["status"]["dropped"]


def test_request_status_says_when_they_replied_and_whose_move_it_is(db, case):
    from test_block_status import CIRCLE_LIKE, _order, _reply

    order = _order(case, "KuCoin")
    at = order.sent_at.replace(tzinfo=UTC) + timedelta(days=1)
    _reply(db, case, order, CIRCLE_LIKE, at=at)
    (k,) = _hover(db, case)[KUCOIN_DEPOSIT]["hover"]["authorities"]
    assert f"replied {at:%d %b}" in k["status"] and k["status"].endswith("— our move") and "due" not in k["status"]
    (r,) = next(d for key, d in _hover(db, case).items() if key != "_edges" and d.get("entity") == "Rainbet")[
        "hover"]["authorities"]
    assert re.search(r"· sent \d\d \w{3}, replied \d\d \w{3}", r["status"]), r["status"]


def test_edge_cards_list_their_transfers_oldest_first_and_say_how_many_are_left_out(db, case):
    from app.tracing.hover import EDGE_TRANSFERS

    by = _hover(db, case)
    big = [e["data"]["hover"] for e in by["_edges"] if e["data"]["hover"]["n"] > EDGE_TRANSFERS]
    assert big
    for h in big:
        assert len(h["transfers"]) == EDGE_TRANSFERS
        stamps = [datetime.strptime(t["at"][:11], "%d %b %Y") for t in h["transfers"] if t["at"]]
        assert stamps == sorted(stamps)
    assert "by value of ${x.n}; click for all" in GRAPH_JS.read_text(encoding="utf-8")
