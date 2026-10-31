"""Wallet owner identification (app.attribution, migration 0011): the sources (a person, the trace's entity map, the
catalogue, public explorer tags, the behaviour profile) and how they combine, the per-case lookup consent (no request
without it), the explorer parsers over a mocked Blockscout / Tronscan (httpx.MockTransport), a failed lookup never
hiding a good one, the Recovery plan using the attribution (an exchange deposit -> a freeze request to that exchange,
the address prefilled; a service hot wallet -> the service, not the issuer; an "Identify the owner" move), the pages,
the graph, roles and audit. The demo case plus synthetic tags: every tag, note and lookup here is made up."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import csrf_token
from sqlalchemy import select

from app import services
from app.ai import providers
from app.attribution import explorer
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.core.config import get_settings
from app.db.models import AuditEvent, Entity, FreezeCheck, TraceNode, WalletAttribution
from app.freeze import transport as tp
from app.freeze.transport import FreezeHttp

NOW = datetime.now(tz=UTC)
KEY = "T" * 32  # synthetic Tronscan key
TEST_SETTINGS = get_settings().model_copy(update={
    "aegis_owner_lookups_disabled": "", "aegis_owner_lookups_auto": "0", "tronscan_api_key": "",
    "aegis_freeze_min_interval": 0.0,
    "aegis_freeze_cache_minutes": 0.0, "aegis_freeze_retries": 1, "aegis_owner_cache_hours": 168.0,
    "aegis_owner_max_wallets": 25, "aegis_owner_metadata_url": "https://metadata.services.blockscout.com",
    "aegis_owner_tronscan_url": "https://apilist.tronscanapi.com",
})


def _tag(name, *, type_="name", entity=None, url=None) -> dict:
    meta = {k: v for k, v in (("main_entity", entity), ("tooltipUrl", url)) if v}
    return {"slug": name.lower().replace(" ", "-"), "name": name, "tagType": type_, "ordinal": 10,
            "meta": json.dumps(meta) if meta else "{}"}


class Explorers:
    """Blockscout's metadata service and instances plus Tronscan's account API. `tags` / `info` / `counters` keyed by
    lower-case EVM address, `tron` by base58."""

    def __init__(self):
        self.tags: dict[str, list[dict]] = {}
        self.info: dict[str, dict] = {}
        self.counters: dict[str, dict] = {}
        self.tron: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.headers: list[dict] = []
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        host, path = url.hostname, url.path
        self.calls.append((host, path))
        self.headers.append(dict(request.headers))
        if self.down:
            return httpx.Response(503)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if host == "metadata.services.blockscout.com" and path == "/api/v1/metadata":
            a = q["addresses"]
            tags = self.tags.get(a.lower())
            return httpx.Response(200, json={"addresses": {a: {"tags": tags}} if tags else {}})
        if host.endswith(".blockscout.com") and path.startswith("/api/v2/addresses/"):
            a = path.split("/")[4].lower()
            if a not in self.info:
                return httpx.Response(404, json={"message": "Not found"})
            if path.endswith("/counters"):
                return httpx.Response(200, json=self.counters.get(a, {"transactions_count": "3"}))
            return httpx.Response(200, json={"hash": a, "is_contract": False, "is_scam": False, "name": None,
                                             "public_tags": [], "metadata": None, "token": None, **self.info[a]})
        if host == "apilist.tronscanapi.com" and path == "/api/accountv2":
            if request.headers.get("TRON-PRO-API-KEY") != KEY:
                return httpx.Response(401)
            return httpx.Response(200, json=self.tron.get(q["address"], {}))
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def ex():
    return Explorers()


@pytest.fixture(autouse=True)
def _offline(monkeypatch, ex):
    """Every client the lookups build talks to the mock; the service's settings are TEST_SETTINGS."""
    tp.clear_cache()
    real = FreezeHttp

    def factory(settings=None, **kw):
        kw["transport"] = httpx.MockTransport(ex.handler)
        return real(settings or TEST_SETTINGS, sleep=lambda s: None, **kw)

    monkeypatch.setattr(attr, "FreezeHttp", factory)
    monkeypatch.setattr(attr, "_settings", lambda settings=None: settings or TEST_SETTINGS)
    yield
    tp.clear_cache()


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _node(db, case, label_prefix: str) -> TraceNode:
    run = services.latest_run(db, case)
    return next(n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id))
                if (n.address.label or "").startswith(label_prefix))


def _addr(db, case, label_prefix: str) -> tuple[str, str]:
    a = _node(db, case, label_prefix).address
    return attr.key_of(a.chain.value, a.address)


def _consent(db, case):
    attr.set_enabled(db, case, None, True)


def _plan(db, case) -> rp.Plan:
    db.expire_all()
    return rp.build(db, case)


def _ent(db, name) -> Entity:
    return db.scalar(select(Entity).where(Entity.name == name))


def _reading(db, case, address, balance, *, chain="tron"):
    db.add(FreezeCheck(case_id=case.id, chain=chain, address=address, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=False,
                       balance=Decimal(balance), checked_at=NOW - timedelta(minutes=5), block_number=71_000_000,
                       raw_sha256="ab" * 32, meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


# --------------------------------------------------------------------------- parsers
def test_public_tags_classify_owner_kind_and_confidence():
    hot = [_tag("KuCoin: Hot Wallet", entity="KuCoin"), _tag("Exchange", type_="generic")]
    assert explorer.classify([{"name": t["name"], "type": t["tagType"], "main_entity": "KuCoin"} for t in hot]) == (
        "KuCoin", "exchange_hot_wallet", "M")
    assert explorer.classify([{"name": "Demo Hot Wallet 14", "type": "name"}])[:2] == ("Demo", "exchange_hot_wallet")
    assert explorer.classify([{"name": "Demo Casino: Deposit", "type": "name"}])[1] == "casino"
    assert explorer.classify([{"name": "SWFT Bridge Router", "type": "name"}])[1] == "swap_bridge"
    assert explorer.classify([{"name": "Fake_Phishing123", "type": "name"}]) == (None, "unhosted", "L")
    assert explorer.classify([], is_scam=True) == (None, "unhosted", "L")
    assert explorer.classify([], token_symbol="USDT", is_contract=True)[1] == "issuer"
    assert explorer.classify([]) == (None, None, "M")
    assert explorer.owner_from("Demo-Hot 3") == "Demo" and explorer.owner_from("KuCoin 17") == "KuCoin"


def test_blockscout_lookup_reads_tags_counters_and_hashes(ex):
    a = "0x" + "c1" * 20
    ex.tags[a] = [_tag("KuCoin: Deposit", entity="KuCoin"), _tag("KuCoin", type_="protocol")]
    ex.info[a] = {}
    ex.counters[a] = {"transactions_count": "42", "token_transfers_count": "7"}
    with FreezeHttp(TEST_SETTINGS, transport=httpx.MockTransport(ex.handler), sleep=lambda s: None,
                    allowed_domains=explorer.ALLOWED_DOMAINS) as http:
        got = explorer.lookup(http, TEST_SETTINGS, "ethereum", a)
    assert (got.owner, got.kind, got.confidence) == ("KuCoin", "exchange_deposit", "M")
    assert got.profile["tx_count"] == 42 and got.profile["token_transfers"] == 7 and len(got.sha256) == 3
    assert {"metadata.services.blockscout.com", "eth.blockscout.com"} == set(got.hosts) and got.ok
    unseen = "0x" + "c2" * 20  # never seen by Blockscout: 404, no activity, still a lookup
    tp.clear_cache()
    with FreezeHttp(TEST_SETTINGS, transport=httpx.MockTransport(ex.handler), sleep=lambda s: None,
                    allowed_domains=explorer.ALLOWED_DOMAINS) as http:
        got = explorer.lookup(http, TEST_SETTINGS, "base", unseen)
    assert got.profile.get("unseen") and got.kind is None and got.ok and ("base.blockscout.com",
                                                                           f"/api/v2/addresses/{unseen}") in ex.calls


def test_tronscan_needs_its_key_in_a_header_and_reads_the_red_tag(ex):
    t = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"
    ex.tron[t] = {"redTag": "Scam", "totalTransactionCount": 12, "date_created": 1760000000000}
    with FreezeHttp(TEST_SETTINGS, transport=httpx.MockTransport(ex.handler), sleep=lambda s: None,
                    allowed_domains=explorer.ALLOWED_DOMAINS) as http:
        got = explorer.lookup(http, TEST_SETTINGS, "tron", t)
    assert got.errors == ["no_api_key"] and ex.calls == []  # no key: nothing sent
    keyed = TEST_SETTINGS.model_copy(update={"tronscan_api_key": KEY})
    with FreezeHttp(keyed, transport=httpx.MockTransport(ex.handler), sleep=lambda s: None,
                    allowed_domains=explorer.ALLOWED_DOMAINS) as http:
        got = explorer.lookup(http, keyed, "tron", t)
    assert (got.kind, got.confidence) == ("unhosted", "L") and got.profile["tx_count"] == 12
    assert ex.headers[-1].get("tron-pro-api-key") == KEY and KEY not in str(ex.calls)


def test_the_client_refuses_a_host_outside_the_allow_list(ex):
    with FreezeHttp(TEST_SETTINGS, transport=httpx.MockTransport(ex.handler), sleep=lambda s: None,
                    allowed_domains=explorer.ALLOWED_DOMAINS) as http:
        with pytest.raises(tp.FreezeHttpError) as err:
            http.get("https://api.explorer-demo.example/x")
        assert err.value.reason == "host_not_allowed"
        with pytest.raises(tp.FreezeHttpError):  # the freeze checks' own hosts are not the lookups'
            http.get("https://api.trongrid.io/v1/accounts/x")
    assert ex.calls == []


# --------------------------------------------------------------------------- consent
def test_no_lookup_without_the_case_admins_consent(db, case, ex):
    case.owner_lookup_consent = None  # never set: ON by default
    db.commit()
    st = attr.status(case)
    assert st["enabled"] and st["default"] and attr.new_hosts(case) == []
    attr.set_enabled(db, case, None, False)  # a case admin's explicit off stays off
    with pytest.raises(attr.OwnerLookupsDisabled) as err:
        attr.run_lookups(db, case)
    assert err.value.reason == "case_setting_off" and ex.calls == []
    assert attr.auto_lookups(db, case, settings=TEST_SETTINGS.model_copy(update={"aegis_owner_lookups_auto": "1"})) \
        is None and ex.calls == []  # nor automatically
    _consent(db, case)
    off = TEST_SETTINGS.model_copy(update={"aegis_owner_lookups_disabled": "1"})
    with pytest.raises(attr.OwnerLookupsDisabled) as err:
        attr.run_lookups(db, case, settings=off)
    assert err.value.reason == "deployment_disabled" and ex.calls == []
    keyed = TEST_SETTINGS.model_copy(update={"tronscan_api_key": KEY})  # a key set later adds Tronscan's host
    assert attr.new_hosts(case, keyed) == ["apilist.tronscanapi.com"]
    with pytest.raises(attr.OwnerLookupsDisabled) as err:
        attr.run_lookups(db, case, settings=keyed)
    assert err.value.reason == "consent_outdated" and ex.calls == []
    rep = attr.run_lookups(db, case)
    assert rep.looked_up > 0 and rep.skipped >= 1  # TRON / Bitcoin wallets: no explorer without a key
    assert {h for h, _ in ex.calls} <= {"metadata.services.blockscout.com", "eth.blockscout.com"}
    assert not any(h == "apilist.tronscanapi.com" for h, _ in ex.calls)
    victim = _addr(db, case, "Victim")
    assert not any(victim[1] in p for _, p in ex.calls)  # the victim's own wallet is never looked up


def test_lookups_are_cached_a_failed_one_never_hides_a_good_one_and_force_asks_again(db, case, ex):
    _consent(db, case)
    k = _addr(db, case, "Hub outflow #3")
    ex.tags[k[1]] = [_tag("KuCoin: Deposit", entity="KuCoin")]
    ex.info[k[1]] = {}
    rep = attr.run_lookups(db, case, only={k})
    assert rep.looked_up == 1 and rep.tagged == 1
    n = len(ex.calls)
    rep = attr.run_lookups(db, case, only={k})
    assert rep.cached == 1 and rep.looked_up == 0 and len(ex.calls) == n  # within AEGIS_OWNER_CACHE_HOURS
    ex.down = True
    tp.clear_cache()
    rep = attr.run_lookups(db, case, only={k}, force=True)
    assert rep.errors == 1 and rep.looked_up == 0
    att = attr.attribute(db, case)[k]
    assert (att.owner, att.kind, att.source) == ("KuCoin", "exchange_deposit", "explorer")
    rows = db.scalars(select(WalletAttribution).where(WalletAttribution.case_id == case.id)).all()
    assert len(rows) == 1 and rows[0].detail["sha256"] and rows[0].detail["org_key"] == "kucoin"


# --------------------------------------------------------------------------- combining the sources
def test_a_persons_attribution_wins_and_can_be_withdrawn(db, case, ex):
    _consent(db, case)
    k = _addr(db, case, "Hub outflow #2")
    ex.tags[k[1]] = [_tag("Rainbet: Hot Wallet", entity="Rainbet")]
    ex.info[k[1]] = {}
    attr.run_lookups(db, case, only={k})
    assert attr.attribute(db, case)[k].owner == "Rainbet"
    attr.mark(db, case, None, chain=k[0], address=k[1], owner="KuCoin", kind="exchange_deposit",
              note="the account statement the victim's bank obtained")
    db.commit()
    att = attr.attribute(db, case)[k]
    assert (att.owner, att.kind, att.confidence, att.source) == ("KuCoin", "exchange_deposit", "H", "manual")
    assert any("conflicting: public explorer tag says Rainbet (a person's attribution wins)" in x for x in att.lines)
    assert "account statement" in " ".join(att.lines)
    assert "account statement" not in json.dumps(att.as_dict(show_notes=False))  # the note: view_restricted only
    attr.mark(db, case, None, chain=k[0], address=k[1], owner=None, kind="unknown", clear=True)
    db.commit()
    assert attr.attribute(db, case)[k].source == "explorer"  # withdrawn: the explorer's tag again
    with pytest.raises(ValueError):
        attr.mark(db, case, None, chain="ethereum", address="0x1234", owner="KuCoin", kind="exchange_deposit")
    with pytest.raises(ValueError):
        attr.mark(db, case, None, chain=k[0], address=k[1], owner=None, kind="unknown")


def test_trace_entity_map_and_behaviour_profile(db, case):
    atts = attr.attribute(db, case)
    dep = atts[_addr(db, case, "KuCoin deposit")]
    assert (dep.owner, dep.kind, dep.source, dep.confidence) == ("KuCoin", "exchange_deposit", "trace", "H")
    assert any("swept 100% of its funds" in x and "a deposit address of KuCoin" in x for x in dep.lines)
    assert "corroborated by behaviour profile" in dep.notes
    assert atts[_addr(db, case, "KuCoin 17")].kind == "exchange_hot_wallet"
    assert atts[_addr(db, case, "SWFT payout wallet (TRON)")].kind == "swap_bridge"
    hub = atts[_addr(db, case, "Distribution hub")]
    assert (hub.owner, hub.kind, hub.source) == (None, "unhosted", "trace")
    # a wallet paying INTO a deposit address is the customer's own, never the exchange's
    payer = atts[_addr(db, case, "Laundering chain wallet")]
    assert payer.owner is None and payer.kind != "exchange_deposit"
    # funds swept within minutes to one wallet a person attributes to an exchange's hot wallet: its deposit address
    # (synthetic: the person re-types the trace's deposit address as a hot wallet)
    dep_k = _addr(db, case, "KuCoin deposit")
    attr.mark(db, case, None, chain=dep_k[0], address=dep_k[1], owner="KuCoin", kind="exchange_hot_wallet")
    db.commit()
    att = attr.attribute(db, case)[_addr(db, case, "Laundering chain wallet")]
    assert (att.owner, att.kind, att.source, att.confidence) == ("KuCoin", "exchange_deposit", "behaviour", "M")
    assert any("within 1 min of arrival" in x for x in att.lines)


def test_a_pooled_balance_reads_as_a_service_wallet(db, case):
    t = _addr(db, case, "USDT-TRON destination")
    _reading(db, case, t[1], "1030000")
    att = attr.attribute(db, case)[t]
    assert (att.owner, att.kind, att.source) == (None, "exchange_hot_wallet", "behaviour")
    assert "not the issuer" in att.ask["text"]


def test_catalogue_addresses_name_the_owner(db, case, monkeypatch):
    from test_playbook import _catalogue_with, _pb

    k = _addr(db, case, "Hub outflow #3")
    prov = {"source_ids": ["s1"], "basis": "D", "confidence": "H", "retrieved_at": "2026-10-20"}
    cat = _catalogue_with(_pb(addresses=[{"chain": "ethereum", "address": k[1], "kind": "exchange_hot_wallet",
                                          "label": "published cold-to-hot wallet", **prov}]))
    monkeypatch.setattr(attr, "_catalogue", lambda: cat)
    att = attr.attribute(db, case)[k]
    assert (att.owner, att.kind, att.confidence, att.source, att.org_key) == (
        "KuCoin", "exchange_hot_wallet", "H", "catalogue", "kucoin")
    from test_playbook import _parse

    from app.domain import playbook as pbm

    with pytest.raises(pbm.PlaybookError, match="never an observed fact"):
        _parse(_pb(addresses=[{"chain": "ethereum", "address": k[1], "kind": "exchange_deposit", "source_ids": ["o1"],
                               "basis": "O", "confidence": "M", "retrieved_at": "2026-10"}], sources=[
            {"id": "s1", "title": "Synthetic LE guidelines", "url": "https://kucoin.example/legal",
             "retrieved_at": "2026-10-20"},
            {"id": "o1", "title": "A reply we received", "url": None, "retrieved_at": "2026-10", "observed": True}]))
    with pytest.raises(pbm.PlaybookError, match="kind must be"):
        _parse(_pb(addresses=[{"chain": "ethereum", "address": k[1], "kind": "person", **prov}]))


# --------------------------------------------------------------------------- the Recovery plan uses it
def test_a_known_exchange_deposit_gets_a_freeze_request_to_that_exchange(db, case, ex):
    k = _addr(db, case, "Hub outflow #3")
    before = _plan(db, case)
    assert before.find("identify") is not None and k[1][:6] in " ".join(before.find("identify").related)
    _consent(db, case)
    ex.tags[k[1]] = [_tag("KuCoin: Deposit", entity="KuCoin")]
    ex.info[k[1]] = {}
    attr.run_lookups(db, case, only={k})
    plan = _plan(db, case)
    m = plan.find(f"owner:{k[0]}:{k[1]}")
    assert m is not None and "KuCoin" in m.title and m.value == pytest.approx(137552.23, rel=0.01)
    kucoin = _ent(db, "KuCoin")
    if m.kind == "request":
        # KuCoin already has a request on file: the freeze request for the new deposit quotes it (&ref=)
        assert m.href.startswith(f"/cases/{case.id}/authorities/entity-{kucoin.id}?template=info_request&freeze="
                                 f"ethereum:{k[1]}&ref=") and m.href.endswith("#generate")
    else:  # KuCoin's playbook takes LE requests only from us: the LE brief leads
        assert m.kind == "le" and "LE" in m.title
    assert m.owners and m.owners[0]["owner"] == "KuCoin" and m.counts
    # counted once, by its owner move (the Circle wallets it came from moved everything on: no upper bound there)
    assert plan.totals["in_play_sum_usd"] == pytest.approx(before.totals["in_play_sum_usd"] + m.value, abs=1)
    for x in plan.moves:  # no longer an unhosted wallet to watch / trace further / identify
        if x.key in ("watch", "trace_next", "identify"):
            assert k not in x.wallets
    v = rp.owners_view(plan, _Access())
    assert any(o["address"] == k[1] and o["owner"] == "KuCoin" for o in v["owners"])


def test_a_service_hot_wallet_is_asked_of_the_service_not_the_issuer(db, case):
    t = _addr(db, case, "USDT-TRON destination")
    _reading(db, case, t[1], "1030000")
    attr.mark(db, case, None, chain=t[0], address=t[1], owner="KuCoin", kind="exchange_hot_wallet")
    db.commit()
    plan = _plan(db, case)
    tether = plan.find(f"entity-{_ent(db, 'Tether (USDT issuer)').id}")
    assert tether.value is None or tether.value < 1030000
    assert "ask KuCoin" in tether.basis and "its owner is asked first" in tether.likelihood_why
    assert any(o["owner"] == "KuCoin" for o in tether.owners)
    m = plan.find(f"owner:{t[0]}:{t[1]}")
    assert m is not None and "Ask KuCoin which account received the funds" in m.title and "not the issuer" in m.title
    # round 12: both keep their values (the traced share), on the same funds: counted once in the totals
    assert m.value <= 1400 and m.counts and tether.value <= 1400 and "same funds as" in tether.basis
    assert "same funds as" in m.basis


def test_identify_move_offers_the_lookups_only_once_consented(db, case):
    attr.set_enabled(db, case, None, False)  # a case admin switched them off: the move offers turning them on
    m = _plan(db, case).find("identify")
    assert m is not None and m.actions[0]["perm"] == "manage_case" and "/owners/" not in str(m.actions[0])
    _consent(db, case)
    m = _plan(db, case).find("identify")
    assert m.actions[0]["post"] == f"/cases/{case.id}/owners/lookup" and m.actions[0]["perm"] == "poll_watch"


class _Access:
    case = None

    def can(self, perm):
        return True


# --------------------------------------------------------------------------- pages, graph, roles, audit
def test_pages_roles_and_audit(db, case, client_for, ex):
    attr.set_enabled(db, case, None, False)  # switched off by a case admin (they are on by default)
    ro = client_for("read_only", case=case)
    inv = client_for("investigator", case=case)
    adm = client_for("admin", case=case)
    k = _addr(db, case, "Hub outflow #3")
    page = ro.get(f"/cases/{case.id}/recovery-plan").text
    assert "Who owns these wallets" in page and "Owner:" in page and "Turn owner lookups on" not in page
    assert ro.get(f"/api/cases/{case.id}/owners").status_code == 200
    tok = csrf_token(ro, f"/cases/{case.id}/recovery-plan")
    assert ro.post(f"/cases/{case.id}/owners/mark", data={"csrf_token": tok, "chain": k[0], "address": k[1],
                                                         "owner": "KuCoin", "kind": "exchange_deposit"}
                   ).status_code == 403
    tok = csrf_token(inv, f"/cases/{case.id}/recovery-plan")
    r = inv.post(f"/cases/{case.id}/owners/lookup", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 409 and ex.calls == []  # off: nothing sent
    assert inv.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1"}
                    ).status_code == 403
    r = inv.post(f"/cases/{case.id}/owners/mark", data={"csrf_token": tok, "chain": k[0], "address": k[1],
                                                        "owner": "KuCoin", "kind": "exchange_deposit",
                                                        "note": "synthetic note"}, follow_redirects=False)
    assert r.status_code == 303 and "#owners" in r.headers["location"]
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "CREATE", AuditEvent.object_type ==
                                            "wallet_attributions").order_by(AuditEvent.id.desc()).limit(1))
    assert ev is not None and ev.detail.get("kind") == "exchange_deposit"
    assert "KuCoin" not in json.dumps(ev.detail) and "synthetic note" not in json.dumps(ev.detail)
    assert k[1] not in json.dumps(ev.detail)
    api = ro.get(f"/api/cases/{case.id}/owners").json()
    row = next(w for w in api["wallets"] if w["address"] == k[1])
    assert row["owner"] == "KuCoin" and row["source"] == "manual" and "synthetic note" not in json.dumps(row)

    tok = csrf_token(adm, f"/cases/{case.id}/recovery-plan")
    assert "Turn owner lookups on" in adm.get(f"/cases/{case.id}/recovery-plan").text
    assert adm.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1"},
                    follow_redirects=False).status_code == 400  # no consent tick
    r = adm.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1"},
                 follow_redirects=False)
    assert r.status_code == 400  # consent is always to the endpoints the page showed
    r = adm.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1",
                 "hosts": ",".join(attr.consent_hosts(attr.egress_plan()))}, follow_redirects=False)
    assert r.status_code == 303
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "UPDATE").order_by(AuditEvent.id.desc()).limit(1))
    assert ev.detail.get("setting") == "owner_lookups" and "eth.blockscout.com" in ev.detail.get("hosts")
    tok = csrf_token(inv, f"/cases/{case.id}/recovery-plan")
    r = inv.post(f"/cases/{case.id}/owners/lookup", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and ex.calls
    assert not any(k[1] in p for _, p in ex.calls)  # a wallet a person marked is never sent
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "OWNER_LOOKUP").order_by(AuditEvent.id.desc())
                   .limit(1))
    assert ev.outcome == "allowed" and ev.detail.get("looked_up", 0) > 0

    fz = ro.get(f"/cases/{case.id}/freeze").text  # the freeze page's wallet list names the owner
    assert "Owner:" in fz


def test_graph_nodes_carry_the_owner_without_a_persons_note(db, case):
    from app.tracing.annotate import annotate_owners
    from app.tracing.graph import build_graph, to_cytoscape

    k = _addr(db, case, "Hub outflow #3")
    attr.mark(db, case, None, chain=k[0], address=k[1], owner="KuCoin", kind="exchange_deposit",
              note="synthetic private note")
    db.commit()
    run = services.latest_run(db, case)
    els = annotate_owners(db, case, run, to_cytoscape(build_graph(db, run)))
    node = next(n["data"] for n in els["nodes"] if attr.key_of(n["data"]["chain"], n["data"]["address"]) == k)
    assert node["owner"]["owner"] == "KuCoin" and node["owner"]["confidence"] == "H"
    assert "synthetic private note" not in json.dumps(els)


def test_migration_0011_up_down_up(tmp_path):
    from sqlalchemy import create_engine, inspect
    from test_migrations import _cfg

    from alembic import command

    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0011_wallet_attributions")
    with engine.connect() as conn:
        assert "wallet_attributions" in inspect(conn).get_table_names()
        assert "owner_lookup_consent" in {c["name"] for c in inspect(conn).get_columns("cases")}
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0010_mailbox_status")
    with engine.connect() as conn:
        assert "wallet_attributions" not in inspect(conn).get_table_names()
        assert "owner_lookup_consent" not in {c["name"] for c in inspect(conn).get_columns("cases")}
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    engine.dispose()


def test_an_issuer_frozen_wallet_is_never_read_as_a_service_hot_wallet():
    """A large balance an issuer blacklisted is the funds held, not a service's pooled float (behaviour rule)."""
    from app.attribution import service as svc

    w = svc.Wallet(chain="ethereum", address="0x" + "ab" * 20, watched=True, held_usd=86_000.0, frozen=True)
    assert not [c for c in svc._behaviour(w, {}, {}) if c.kind == "exchange_hot_wallet"]
    w.frozen = False
    assert [c for c in svc._behaviour(w, {}, {}) if c.kind == "exchange_hot_wallet"]


def test_owner_lookups_are_on_by_default_and_follow_every_trace(db, case, ex, monkeypatch):
    """No one has to switch owner lookups on; a trace run looks up its wallets'
    public tags itself, and the scheduler refreshes the cases whose last run is older than the cache window."""
    from app import services

    case.owner_lookup_consent = None
    db.commit()
    on = TEST_SETTINGS.model_copy(update={"aegis_owner_lookups_auto": "1"})
    monkeypatch.setattr(attr, "_settings", lambda settings=None: settings or on)
    assert attr.is_enabled(case) and attr.status(case)["default"]
    assert case in attr.due_cases(db)  # never looked up: due
    services.run_trace(db, case, provider_mode="fixture")  # the trace itself runs the lookups
    db.refresh(case)
    last = attr.setting(case)["last_run"]
    assert last["trigger"] == "trace" and last["looked_up"] > 0 and ex.calls
    assert attr.setting(case).get("default") and case not in attr.due_cases(db)  # fresh: not due again
    calls = len(ex.calls)
    attr.set_enabled(db, case, None, False)  # a case admin's off stays off: no automatic lookup
    services.run_trace(db, case, provider_mode="fixture")
    assert len(ex.calls) == calls and case not in attr.due_cases(db)
    case.owner_lookup_consent = None
    db.commit()
