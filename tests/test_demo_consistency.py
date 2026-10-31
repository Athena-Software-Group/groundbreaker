"""One number, one name, one status across the pages (the demo's consistency pass): the Recovery plan's KPI strip, its
moves and the Overview's tiles share their figures (in play, the issuers' lever, owner unknown, the overdue replies);
a request's status reads the same on Overview, Authorities, the plan and Block status (bs.BlockRow.status_text);
"requires <instrument>" only where the reply or the playbook says the provider acts on LE process only
(app.blocks.path.le_only); the LE cover letter's "where the funds sit" and the LE brief pack follow the plan. The
demo case, offline: no model, no mail, no chain."""

import io
import re
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from app import services
from app.ai import providers
from app.blocks import path as pathmod
from app.blocks import recovery as rp
from app.blocks import report
from app.blocks import status as bs
from app.domain import correspondence as desk
from app.domain import todo

TETHER_ACK = ("Thank you for contacting Tether Compliance.\n\nThis is an automated response. Your request has been "
              "received and ticket #482913 has been created. Tether will only act upon appropriate legal process "
              "submitted by a law enforcement agency.\n\nTether Compliance")


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


def _late(case) -> datetime:
    """A moment after every demo reply fell due (the replies are due three days after the letters went out)."""
    due = max(o.sent_at for o in case.stop_orders if o.sent_at).replace(tzinfo=UTC) + timedelta(days=4)
    return max(due, datetime.now(tz=UTC))


def _row(db, case, name: str, now=None) -> bs.BlockRow:
    return next(r for r in bs.case_blocks(db, case, now=now) if r.authority.name == name and r.kind == "stop_order")


# --------------------------------------------------------------------------- the plan's figures
def test_overdue_replies_are_the_clocks_that_ran_out(db, case):
    later = _late(case)
    plan = rp.build(db, case, now=later)
    overdue = bs.summary(bs.case_blocks(db, case, now=later))["overdue"]
    assert overdue and plan.totals["replies_overdue"] == overdue  # Block status's "overdue" tile
    chases = [m for m in plan.moves if m.kind == "chase"]
    assert chases
    for m in chases:  # one phrase for one fact, never "reply due passed · reply overdue"
        assert "reply due passed" not in m.urgency_why and m.urgency_why.count("reply overdue") == 1
        assert "reply due passed · reply overdue" not in m.reason


def test_owner_unknown_is_one_figure(db, case):
    plan = rp.build(db, case)
    ident = plan.find("identify")
    uo = plan.totals["unknown_owner"]
    assert ident is not None and uo["n"] == len(ident.wallets) and uo["usd"] == pytest.approx(ident.value)
    assert uo["threshold_usd"] == pytest.approx(max(1000.0, float(case.loss_usd) * 0.01), abs=0.01)
    further = plan.find("trace_next")
    if further is not None and set(further.wallets) <= set(ident.wallets):
        assert "the same wallets" in further.basis


def test_an_issuer_wallet_that_moved_on_counts_nothing(db, case):
    plan = rp.build(db, case)
    circle = next(m for m in plan.moves + plan.waiting
                  if m.authority is not None and m.authority.name == "Circle (USDC issuer)" and ":" not in m.key)
    assert not circle.value and circle.moved_on
    assert "Circle (USDC issuer)" in {x["name"] for x in plan.totals["issuer_moved_on"]}
    assert plan.totals["issuer_usd"] < float(case.loss_usd) / 2  # never the full loss as a "lever"
    assert plan.totals["in_play_usd"] <= float(case.loss_usd)


def test_overview_tiles_are_the_plans(db, case, client_for):
    adm = client_for("admin", case=case, email="adm-cons1@tests.example")
    html = adm.get(f"/cases/{case.id}").text
    funds = html.split('id="funds"')[1].split("ov-strip")[0]
    plan = rp.build(db, case)
    assert "At freezable services" in funds and f"${plan.totals['freezable_usd']:,.2f}" in funds
    assert f"${plan.totals['in_play_usd']:,.0f} in play" in funds  # the one-line reconciliation with the plan
    rain_kucoin = [m.value for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                   and m.authority.name in ("Rainbet", "KuCoin")]
    assert plan.totals["freezable_usd"] == pytest.approx(sum(rain_kucoin), abs=0.01)
    assert "Issuer blacklist lever" in funds and f"${plan.totals['issuer_usd']:,.2f}" in funds
    assert "$399,247.92</div><div class=\"l\">Issuer" not in funds and "moved on" in funds
    assert "Owner unknown" in funds and f"${plan.totals['unknown_owner']['usd']:,.2f}" in funds
    assert "399,247.92 USDC" in funds  # the loss's own amount, thousands separated


# --------------------------------------------------------------------------- one status everywhere
def test_a_requests_status_reads_the_same_on_every_page(db, case, client_for):
    adm = client_for("admin", case=case, email="adm-cons2@tests.example")
    rain = _row(db, case, "Rainbet")
    text = rain.status_text
    assert text == "Acknowledged"
    overview = adm.get(f"/cases/{case.id}").text
    orders = overview.split('id="open-orders"')[1].split("</table>")[0]
    assert f">{text}<" in orders and '<span class="tag blue">sent</span>' not in orders
    auth = adm.get(f"/cases/{case.id}?tab=authorities").text
    table = auth.split('id="authorities"')[1].split("</table>")[0]
    assert f">{text}<" in table and '<span class="tag blue">sent</span>' not in table
    plan_html = adm.get(f"/cases/{case.id}/recovery-plan").text
    move = plan_html.split(f'id="m-{rain.key}"')[1].split("</li>")[0]
    assert f">{text}</span>" in move and "Provider acknowledged" not in re.sub(r'title="[^"]*"', "", move)
    blocks = adm.get(f"/cases/{case.id}/blocks").text
    assert 'class="case-tabs"' in blocks  # the case tab bar, as on the Recovery plan


def test_a_suggested_outcome_says_confirm_once(db, case):
    from test_block_status import FROZEN, _reply

    order = next(o for o in case.stop_orders if o.entity is not None and o.entity.name == "SWFT / Bridgers")
    _reply(db, case, order, FROZEN)
    row = _row(db, case, "SWFT / Bridgers")
    assert row.suggestion is not None and row.status_text.endswith(": confirm") and row.confirm_in_text
    v = report.row_view(row, _access(db, case), case)
    assert v["needs_confirmation"] and not v["confirm_tag"]  # no "to confirm" tag beside a text that says it
    assert "needs confirmation" not in v["status_text"]


def _access(db, case):
    from conftest import ensure_user

    from app.core.permissions import CaseAccess
    from app.db.models import CaseRole

    return CaseAccess(case=case, user=ensure_user(db, "adm-cons3@tests.example"), role=CaseRole.ADMIN, member=None)


# --------------------------------------------------------------------------- "requires" only where it is so
def test_requires_only_where_the_reply_or_the_playbook_says_le_only(db, case):
    for name in ("Rainbet", "KuCoin", "SWFT / Bridgers"):
        row = _row(db, case, name)
        assert row.path is not None and not pathmod.le_only(row.path, row.playbook), name
    access = _access(db, case)
    md = report.export(db, access, "md")[0].decode()
    paths = [ln for ln in md.splitlines() if ln.startswith("- Path:")]
    assert paths and not any("requires" in ln for ln in paths), paths
    # a reply saying it acts only on legal process from law enforcement: now it requires it
    from test_recovery_plan import _cand, _ent, _sent

    tether = _ent(db, "Tether (USDT issuer)")
    order = _sent(db, case, tether, _cand(db, case, "Tether (USDT issuer)").identifiers[0].address, chain="tron")
    from test_block_status import _reply

    _reply(db, case, order, TETHER_ACK)
    row = next(r for r in bs.case_blocks(db, case) if r.key == f"o{order.id}")
    assert pathmod.le_only(row.path, row.playbook)
    md = report.export(db, access, "md")[0].decode()
    block = md.split(f"Tether (USDT issuer) — Stop order #{order.id}")[1].split("\n\n")[0]
    assert "; requires " in block


def test_the_le_brief_of_a_provider_that_may_act_names_the_formal_route(db, case):
    from test_block_path import _le

    rain = _row(db, case, "Rainbet")
    _s, body, _r = desk.build_letter(db, case, _le(db, case, "Carabinieri"), "le_brief", ref=rain.key,
                                     run=services.latest_run(db, case))
    assert "Rainbet requires" not in body and "acts only on" not in body
    assert "### 2. The formal route" in body and "Rainbet has not acted on it yet" in body


# --------------------------------------------------------------------------- the LE cover letter and the pack
def test_the_cover_letter_cites_the_plans_values(db, case):
    from test_block_path import _le

    _s, body, _r = desk.build_letter(db, case, _le(db, case, "Carabinieri"), "le_cover",
                                     run=services.latest_run(db, case))
    where = body.split("### 2. Where the funds sit")[1].split("###")[0]
    circle = next(ln for ln in where.splitlines() if ln.startswith("- **Circle (USDC issuer)**"))
    assert "no amount is counted here" in circle and "up to USD 399,247.92 traced" not in circle
    assert where.index("**Rainbet**") < where.index("**Circle (USDC issuer)**")  # most money first
    plan = rp.build(db, case)
    assert f"up to USD {plan.totals['in_play_usd']:,.2f}" in where and "each traced dollar once" in where


def test_the_pack_reads_its_evidence_as_the_plan_does(db, case, client_for):
    inv = client_for("investigator", case=case, email="inv-cons1@tests.example")
    plan = rp.build(db, case)
    m = next(x for x in plan.moves + plan.waiting if x.authority is not None and x.authority.name == "Rainbet"
             and x.row is not None)
    z = zipfile.ZipFile(io.BytesIO(inv.get(f"/cases/{case.id}/recovery-plan/pack/{m.key}.zip").content))
    import json

    man = json.loads(z.read("manifest.json"))
    states = {e["key"]: e["state"] for e in man["checklist"]}
    assert states == {e["key"]: e["state"] for e in m.evidence}  # one evaluator: the plan's
    loa = [e for e in case.evidence_items if e.source_type == "authority_instrument"]
    assert loa and {e.id for e in loa} <= {e["id"] for e in man["evidence"]}  # the brief lists it as attached
    rows = z.read("movements.csv").decode().splitlines()
    assert not any(",ASSERTED:" in r for r in rows) and any("hash pending (asserted link)" in r for r in rows)


# --------------------------------------------------------------------------- the page's wording
def test_the_kpi_strip_speaks_plainly(db, case, client_for):
    ro = client_for("read_only", case=case, email="ro-cons1@tests.example")
    html = ro.get(f"/cases/{case.id}/recovery-plan").text
    assert "letters from us count as <b>a private investigator" in html and "count as <b>pi</b>" not in html
    assert ">why this rank</a>" in html
    visible = re.sub(r'title="[^"]*"', "", html)
    assert "· score " not in visible and "urgency ×" not in visible.split('id="method"')[0]
    assert "waiting on others" in html and "owner unknown" in html


def test_the_to_do_list_orders_overdue_chases_by_money_as_the_plan_does():
    now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
    due = now - timedelta(hours=11)
    tasks = [todo.Task(key="a", title="Chase Hostinger", source=todo.PLAN, priority=todo.P1, due=due - timedelta(minutes=3)),
             todo.Task(key="b", title="Chase Rainbet", source=todo.PLAN, priority=todo.P1, due=due, value=63_762.0),
             todo.Task(key="c", title="Chase KuCoin", source=todo.PLAN, priority=todo.P1, due=due, value=145.0),
             todo.Task(key="d", title="Reply due soon", source=todo.PLAN, priority=todo.P1,
                       due=now + timedelta(hours=2), value=1_000_000.0)]
    assert [t.key for t in todo.open_tasks(tasks, now)] == ["b", "c", "a", "d"]
