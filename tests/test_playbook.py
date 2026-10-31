"""Provider playbooks (app.domain.playbook, data/catalogue/providers/*.json): the shipped files and their facts,
the validator, the loader merge into the cached catalogue, the LE-only gate (guidance ranking, next letter,
letter templates, compose recipient check) and the sent-only authority domains."""

import copy
import json
import os
import re
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from test_mail_compose_send import TO, FakeSettings, FakeTransport, _auth, _compose, _draft

from app import services
from app.db.models import CorrespondenceDirection, CorrespondenceStatus, MailMessage
from app.domain import correspondence as desk
from app.domain import directory, mail_send
from app.domain import mail_guidance as mg
from app.domain import playbook as pbm
from app.domain import sender as sender_mod
from app.mail import matching

PROVIDERS = directory.CATALOGUE_PATH.parent / "providers"
OCT18 = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)


def _channels_json() -> dict:
    return json.loads(directory.CATALOGUE_PATH.read_text(encoding="utf-8"))


def _pb(**over) -> dict:
    """A minimal valid playbook for the shipped 'kucoin' organisation (synthetic facts, reserved domains)."""
    prov = {"source_ids": ["s1"], "basis": "D", "confidence": "H", "retrieved_at": "2026-10-20"}
    base = {
        "key": "kucoin", "version": 1, "side": "provider", "jurisdiction": None, "issuer_jurisdictions": [],
        "domains": {"own": ["kucoin.example"]},
        "channels": [{"key": "kucoin.lert", "kind": "email", "value": "le-requests@kucoin.example",
                      "purpose": "le_request", "source_url": "https://kucoin.example/legal", "label": "LE desk",
                      "who": "le_only", **prov}],
        "channels_ext": {"kucoin.le": {"who": "le_only", **prov}},
        "paths": [
            {"key": "notice", "kind": "private_notice", "requester": ["victim", "pi", "counsel"],
             "channel_keys": ["kucoin.web"], "instrument": {"type": "none"}, "on_refusal": "le", **prov},
            {"key": "le", "kind": "le_request", "requester": ["le"], "channel_keys": ["kucoin.lert"],
             "instrument": {"type": "le_request", "signing": "not_digital", "language": ["en"]},
             "timing": {"auto_lift_days": 30, "deadlines": [
                 {"key": "lift", "what": "auto_lift", "days": 30, "starts": "hold_confirmed", "by": "le", **prov}]},
             "evidence": ["le_agency_identity", "freeze_duration_stmt"], **prov}],
        "reply_signals": [{"phrase": "digital signature", "means": "info_requested", **prov}],
        "tickets": [{"system": "kucoin_ticket", "regex": r"#\d{6}", **prov}],
        "sources": [{"id": "s1", "title": "Synthetic LE guidelines", "url": "https://kucoin.example/legal",
                     "retrieved_at": "2026-10-20"}],
    }
    base.update(over)
    return base


def _parse(raw: dict):
    org = directory.parse_catalogue(_channels_json()).by_key[raw.get("key", "kucoin")]
    keys = {c.key for o in directory.parse_catalogue(_channels_json()).orgs for c in o.channels}
    return pbm.parse(raw, org_channels={c.key: c.purpose for c in org.channels}, all_channel_keys=keys)


def _catalogue_with(raw: dict) -> directory.Catalogue:
    return directory.parse_catalogue(_channels_json(), {f"{raw['key']}.json": raw})


# --------------------------------------------------------------------------- shipped files
def test_shipped_playbooks_load_and_merge_into_the_catalogue():
    cat = directory.load_catalogue()
    files = sorted(p.stem for p in PROVIDERS.glob("*.json"))
    assert {"circle", "tether", "fbi-ic3", "carabinieri"} <= set(files)
    for key in files:
        org = cat.by_key[key]
        assert org.playbook is not None and org.playbook.key == key
        raw = json.loads((PROVIDERS / f"{key}.json").read_text(encoding="utf-8"))
        assert not pbm._forbidden(raw)
        for p in org.playbook.paths:  # every claim sourced, with basis, confidence and date
            assert p.prov.source_ids and p.prov.basis in pbm.BASIS and p.prov.confidence in pbm.CONFIDENCE
            assert all(org.playbook.source(s) for s in p.prov.source_ids)
        for c in org.channels:
            if c.purpose == "le_request":
                assert c.who, c.key  # who may use every LE channel is stated
        for s in org.playbook.sources:
            assert (s.url is None) == s.observed and (not s.observed or re.fullmatch(r"\d{4}-\d{2}", s.retrieved_at))
    # no address beyond what the organisations published (channels.json's reviewed pair)
    found = set()
    for p in PROVIDERS.glob("*.json"):
        found |= set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+", p.read_text(encoding="utf-8")))
    assert found <= {"circleblocklisting@circle.com", "subpoenas@circle.com", "inforequests@tether.to"}


def test_circle_playbook_facts():
    org = directory.load_catalogue().by_key["circle"]
    pb = org.playbook
    ch = {c.key: c for c in org.channels}
    assert ch["circle.blocklisting"].purpose == "freeze" and ch["circle.blocklisting"].who == "counsel_with_order"
    assert pb.issuer_jurisdictions == ("US", "FR") and pb.ground_truth == "onchain"
    # Italy → Circle is cross-border: an EU freezing order / EIO to France, an MLAT to the US, or US counsel
    assert pb.route_for("Italy") == "cross_border" and pb.route_for("IT") == "cross_border"
    assert pb.route_for("USA") == "direct" and pb.route_for("France") == "direct" and pb.route_for(None) is None
    kinds = {p.key: p for p in pb.paths}
    assert kinds["eu_freezing_order_fr"].instrument.type == "eu_freezing_order"
    assert kinds["eu_freezing_order_fr"].entity == "circle-eu" and kinds["eio_fr"].instrument.type == "eio"
    assert kinds["mlat_us"].instrument.type == "mlat" and "counsel" in kinds["court_order_us_fr"].requester
    assert kinds["court_order_us_fr"].instrument.type == "us_or_fr_court_order"
    assert not any("funds_returned" in p.outcomes for p in pb.paths)  # no return by burn-and-reissue
    d = {x.key: x for x in kinds["eu_freezing_order_fr"].timing.deadlines}
    # Reg. 2018/1805 Art. 9(3): 48h only with "immediate freezing" ticked (no working-day limit exists)
    assert (d["recognition"].unit, d["recognition"].amount, d["recognition"].starts) == ("hours", 48,
                                                                                      "certificate_received")
    assert (d["execution"].unit, d["execution"].amount, d["execution"].starts) == ("hours", 48, "recognition")
    assert [p.key for p in pb.open_paths("pi")] == ["private_notice"]
    assert pb.gate("pi", name="Circle").reason is None  # a notice is allowed; it draws "court order required"
    assert pb.domain_class("circleblocklisting@circle.com") == "own"
    observed = [s for s in pb.sources if s.observed]
    assert observed and all(re.fullmatch(r"\d{4}-\d{2}", s.retrieved_at) for s in observed)
    notes = " ".join(c.notes or "" for c in org.channels)
    assert "20 Oct" not in notes  # an observed fact carries the month, never the day


def test_tether_playbook_facts():
    org = directory.load_catalogue().by_key["tether"]
    pb = org.playbook
    ch = {c.key: c for c in org.channels}
    assert ch["tether.le"].value is None and ch["tether.le"].who == "le_only"
    assert ch["tether.t3fcu"].who == "le_only" and ch["tether.t3fcu"].kind == "webform"
    mails = [c for c in org.channels if c.kind == "email"]  # only the LE inbox Tether names (never compliance@)
    assert [(c.key, c.who) for c in mails] == [("tether.inforequests", "le_only")]
    assert "tether.inforequests" in pb.path("le_request").channel_keys
    assert pb.ground_truth == "onchain" and not org.portal_only  # an LE-only form never makes it "portal only"
    t3 = pb.path("t3fcu_tron")
    assert t3.requester == ("le",) and t3.channel_keys == ("tether.t3fcu",)
    assert pb.path("private_notice").produces == ("prior_ticket_ref",)
    assert pb.gate("pi").reason is None and [p.key for p in pb.open_paths("pi")] == ["private_notice"]


def test_le_side_playbooks():
    cat = directory.load_catalogue()
    ic3, cara = cat.by_key["fbi-ic3"].playbook, cat.by_key["carabinieri"].playbook
    assert ic3.side == cara.side == "le" and ic3.jurisdiction == "US" and cara.jurisdiction == "IT"
    complaint = ic3.path("complaint")
    assert {"victim", "pi"} <= set(complaint.requester) and "ic3_ref" in complaint.produces
    assert {"tether", "circle"} <= {k for i in ic3.issues if i.instrument == "le_request" for k in i.to}
    q = cara.path("querela")
    assert "special_proxy" in q.evidence and "police_report" in q.produces
    term = q.timing.deadlines[0]
    assert (term.unit, term.amount, term.starts, term.by) == ("months", 3, "fact_known", "victim")
    seq = {d.key: d for d in cara.path("sequestro_preventivo").timing.deadlines}
    assert (seq["validation_request"].amount, seq["validation_decision"].amount) == (48, 10)
    # the binding / cross-border instruments are the prosecutor's, not the police station's
    proc = cat.by_key["procura"].playbook
    assert proc.le_role == "judicial" and cara.le_role == "police" and cat.by_key["fbi-ic3"].playbook.le_role == "intake"
    assert any(i.instrument == "eu_freezing_order" and "circle" in i.to for i in proc.issues)
    assert not any("circle" in i.to for i in cara.issues)
    # the Carabinieri's jurisdiction is not one Circle acts on directly
    assert cat.by_key["circle"].playbook.route_for(cara.jurisdiction) == "cross_border"
    assert cat.by_key["circle"].playbook.route_for(ic3.jurisdiction) == "direct"


# --------------------------------------------------------------------------- validator
def test_minimal_playbook_parses():
    pb, declared = _parse(_pb())
    assert pb.who("kucoin.lert") == "le_only" and pb.who("kucoin.le") == "le_only"
    assert declared[0]["key"] == "kucoin.lert" and "who" not in declared[0]
    le = pb.path("le")
    assert le.instrument.binding and le.instrument.signing == "not_digital" and le.timing.auto_lift_days == 30
    assert le.timing.deadlines[0].span == "30 days" and not le.open_to("pi") and le.open_to("le", held=["le_request"])
    assert pb.stale(now=datetime(2027, 6, 1, tzinfo=UTC)) and not pb.stale(now=datetime(2026, 11, 1, tzinfo=UTC))


def _mut(path: str, value):
    raw = _pb()
    node = raw
    parts = path.split(".")
    for p in parts[:-1]:
        node = node[int(p)] if p.isdigit() else node[p]
    last = parts[-1]
    if value is ...:
        del node[int(last) if last.isdigit() else last]
    elif last.isdigit():
        node[int(last)] = value
    else:
        node[last] = value
    return raw


@pytest.mark.parametrize("path,value,needle", [
    ("paths.0.source_ids", ..., "source_ids"),
    ("paths.0.source_ids", ["nope"], "unknown source_ids"),
    ("paths.0.basis", "X", "basis"),
    ("paths.0.confidence", "high", "confidence"),
    ("paths.0.retrieved_at", "20 Oct 2026", "retrieved_at"),
    ("paths.0.basis", "O", "month only"),
    ("channels_ext", {"kucoin.nope": {"who": "any", "source_ids": ["s1"], "basis": "D", "confidence": "H",
                                      "retrieved_at": "2026-10"}}, "no channel"),
    ("channels_ext", {}, "needs a 'who'"),
    ("channels.0.who", ..., "who must be"),
    ("channels.0.key", "kucoin.web", "already exists"),
    ("channels.0.key", "other.lert", "starts with 'kucoin.'"),
    ("channels.0.value", "TBC", "real value"),
    ("channels.0.value", "le-requests@elsewhere.example", "own domains"),
    ("channels.0.source_url", "https://elsewhere.example/x", "own site"),
    ("paths.0.channel_keys", ["kucoin.lert"], "le_only channel"),
    ("paths.0.channel_keys", ["kucoin.missing"], "unknown channel"),
    ("paths.0.instrument", {"type": "court_order"}, "no binding instrument"),
    ("paths.0.instrument", {"type": "wet_ink"}, "unknown instrument"),
    ("paths.0.requester", ["pi", "le"], "private requesters only"),
    ("paths.1.requester", ["le", "pi"], "law enforcement only"),
    ("paths.0.kind", "risk_flag", "unknown kind"),
    ("paths.0.on_refusal", "nowhere", "on_refusal"),
    ("paths.0.evidence", ["selfie"], "unknown evidence"),
    ("paths.0.expected_replies", ["approved"], "unknown expected_replies"),
    ("paths.1.instrument.signing", "wet", "signing"),
    ("paths.1.timing.deadlines.0.hours", 48, "exactly one"),
    ("paths.1.timing.deadlines.0.starts", "whenever", "starts"),
    ("paths.0.verified", True, "verification state"),
    ("paths.0.colour", "red", "unknown field"),
    ("reply_signals.0.means", "approved", "means"),
    ("tickets.0.regex", "(", "compile"),
    ("issues", [{"instrument": "mlat", "source_ids": ["s1"], "basis": "D", "confidence": "H",
                 "retrieved_at": "2026-10"}], "side 'le' only"),
    ("sources.0.url", "http://kucoin.example/legal", "https://"),
    ("sources.0.observed", True, "no URL"),
    ("jurisdiction", "Italy", "ISO 3166"),
    ("side", "exchange", "side"),
    ("version", 2, "version"),
])
def test_validator_refuses(path, value, needle):
    with pytest.raises(pbm.PlaybookError) as e:
        _parse(_mut(path, value))
    assert needle in str(e.value), str(e.value)


def test_validator_closes_observed_and_placeholder_gaps():
    obs = {"id": "o1", "title": "Provider auto-reply received (Oct 2026)", "observed": True, "retrieved_at": "2026-10"}

    def refused(raw, needle):
        with pytest.raises(pbm.PlaybookError) as e:
            _parse(raw)
        assert needle in str(e.value), str(e.value)

    raw = _pb()
    raw["sources"].append(dict(obs))
    raw["paths"][0].update(source_ids=["o1"], basis="D")  # a day-dated D claim resting only on a reply
    refused(raw, "month only")
    raw["paths"][0]["retrieved_at"] = "2026-10"
    refused(raw, "observed source backs only a basis O")
    raw = _mut("paths.0.basis", "O")
    raw["paths"][0]["retrieved_at"] = "2026-10"
    refused(raw, "basis O claim cites an observed source")
    raw = _pb()
    raw["sources"].append(dict(obs))
    raw["paths"][0].update(source_ids=["o1"], basis="O", retrieved_at="2026-10", notes="Replied on Oct 20 2026.")
    refused(raw, "names no day-level date")
    raw["paths"][0]["notes"] = "Replied in Oct 2026."
    _parse(raw)
    for title in ("Auto-reply of Oct 20 2026", "Auto-reply of 20/10"):
        raw = _pb()
        raw["sources"].append({**obs, "title": title})
        refused(raw, "no day-level date")
    refused(_mut("channels.0.notes", "unknown"), "placeholder")
    refused(_mut("paths.0.retrieved_at", "2099-01-01"), "in the future")
    raw = _pb(entities=[{"key": "e1", "name": "Synthetic entity", "source_ids": []}])
    refused(raw, "needs at least one value")
    raw = _pb()
    raw["channels"].append({"key": "kucoin.kodex", "kind": "webform", "value": "https://portal.example/kucoin/signup",
                            "purpose": "le_request", "label": "LE portal", "who": "le_only",
                            "source_url": "https://kucoin.example/legal", **{k: raw["paths"][0][k] for k in
                                                                              pbm.PROV_FIELDS}})
    raw["domains"]["vendor_portals"] = [{"host": "portal.example", "path_prefix": "/kucoin/", "le_only": False,
                                         **{k: raw["paths"][0][k] for k in pbm.PROV_FIELDS}}]
    refused(raw, "mark it le_only")
    raw["domains"]["vendor_portals"][0]["le_only"] = True
    _parse(raw)


def test_observed_sources_never_carry_a_day_or_an_address():
    for title, ok in (("Provider auto-reply received (Oct 2026)", True), ("Auto-reply of 20 Oct 2026", False),
                      ("Auto-reply 2026-10-20", False), ("Auto-reply from desk@kucoin.example", False)):
        raw = _pb()
        raw["sources"].append({"id": "o1", "title": title, "observed": True, "retrieved_at": "2026-10"})
        if ok:
            _parse(raw)
        else:
            with pytest.raises(pbm.PlaybookError, match="no day-level date"):
                _parse(raw)
    raw = _pb()
    raw["sources"].append({"id": "o1", "title": "Auto-reply", "observed": True, "retrieved_at": "2026-10-20"})
    with pytest.raises(pbm.PlaybookError, match="month only"):
        _parse(raw)


def test_catalogue_merge_rules(tmp_path):
    cat = _catalogue_with(_pb())
    org = cat.by_key["kucoin"]
    ch = {c.key: c for c in org.channels}
    assert ch["kucoin.lert"].value == "le-requests@kucoin.example" and ch["kucoin.lert"].who == "le_only"
    assert ch["kucoin.le"].who == "le_only" and ch["kucoin.web"].who is None and org.playbook.key == "kucoin"
    assert cat.channel("kucoin.lert") is not None
    with pytest.raises(directory.CatalogueError, match="named kucoin.json"):
        directory.parse_catalogue(_channels_json(), {"other.json": _pb()})
    with pytest.raises(directory.CatalogueError, match="no catalogue organisation"):
        directory.parse_catalogue(_channels_json(), {"acme.json": _pb(key="acme")})
    bad = _pb()
    bad["channels"][0]["value"] = "desk@kucoin.example"  # not a generic alias
    with pytest.raises(directory.CatalogueError, match="generic e-mail aliases"):
        _catalogue_with(bad)
    le_raw = _pb(side="le", issues=[{"instrument": "mlat", "to": ["nobody"], "source_ids": ["s1"], "basis": "D",
                                     "confidence": "H", "retrieved_at": "2026-10"}])
    with pytest.raises(directory.CatalogueError, match="unknown organisations"):
        _catalogue_with(le_raw)
    raw = _channels_json()
    raw["orgs"][0]["channels"][1]["value"] = "TBC"
    with pytest.raises(directory.CatalogueError, match="placeholder"):
        directory.parse_catalogue(raw)


def test_loader_caches_and_reloads_provider_files(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text(json.dumps(_channels_json()), encoding="utf-8")
    first = directory.load_catalogue(p)
    assert first.by_key["kucoin"].playbook is None and directory.load_catalogue(p) is first
    (tmp_path / "providers").mkdir()
    f = tmp_path / "providers" / "kucoin.json"
    f.write_text(json.dumps(_pb()), encoding="utf-8")
    second = directory.load_catalogue(p)
    assert second is not first and second.by_key["kucoin"].playbook is not None
    assert directory.load_catalogue(p) is second
    broken = _pb()
    broken["paths"][0]["basis"] = "Z"
    f.write_text(json.dumps(broken), encoding="utf-8")
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    with pytest.raises(directory.CatalogueError, match="providers/kucoin.json"):
        directory.load_catalogue(p)  # never loaded half-valid


def test_playbook_for_an_authority(db, case):
    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    names = {a.name: a for a in desk.case_authorities(db, case, run=run)}
    ic3 = next(a for n, a in names.items() if "IC3" in n)
    pb = directory.playbook_for(ic3)
    assert pb is not None and pb.key == "fbi-ic3"
    tether = next(a for n, a in names.items() if "Tether" in n)
    assert directory.playbook_for(tether).key == "tether"


# --------------------------------------------------------------------------- the LE-only gate
def test_may_use_and_gate():
    assert not pbm.may_use("le_only", "pi") and not pbm.may_use("le_only", "victim") and pbm.may_use("le_only", "le")
    assert pbm.may_use("counsel_with_order", "pi") and pbm.may_use("any", "victim") and pbm.may_use(None, "pi")
    assert pbm.may_use("victim_or_rep", "counsel") and not pbm.may_use("victim_or_rep", "le")
    closed, _ = _parse(_pb(paths=[_pb()["paths"][1]]))
    g = closed.gate("pi", name="KuCoin")
    assert g.le_only and g.reason.startswith(pbm.LE_ONLY_REASON) and "KuCoin" in g.reason
    assert closed.gate("le").reason is None
    raw = _pb()
    raw["paths"][1]["requester"] = ["le", "court"]
    raw["paths"] = [raw["paths"][1], {**_pb()["paths"][1], "key": "order", "kind": "court_order",
                                      "requester": ["counsel", "court"], "channel_keys": [],
                                      "instrument": {"type": "court_order"}}]
    needs, _ = _parse(raw)
    g = needs.gate("counsel")
    assert not g.le_only and g.needs == ("court_order",) and "a court order" in g.reason
    assert needs.gate("counsel", held=["court_order"]).reason is None


def _inp(**kw) -> mg.Inputs:
    base = {"authority_name": "KuCoin", "case_reference": "DEMO-2026-001", "letter_kind": "stop_order",
            "letter_id": 12, "mailbox": "case-desk@aegis.example", "manual": True}
    base.update(kw)
    return mg.Inputs(**base)


def test_rank_to_never_offers_an_le_only_channel_to_us():
    lert = "lert@kucoin-demo.example"
    channels = (mg.Channel(lert, verified=True, source="catalogue", purpose="le_request", who="le_only"),
                mg.Channel("compliance@kucoin-demo.example", source="catalogue", purpose="compliance", who="any"))
    sent = (mg.SentLetter(at=OCT18, to=(lert,)),)
    redirect = (mg.Redirect(away="compliance@kucoin-demo.example", to=lert, at=OCT18, trusted=True),)
    g = mg.guide(_inp(channels=channels, sent=sent, redirects=redirect, letter_kind="status_request"))
    assert lert not in [s.address for s in g.to]  # not from the directory, an earlier letter or a redirect
    assert g.why_for(lert) == "Not suggested: " + pbm.LE_ONLY_REASON
    w = next(w for w in g.warnings if w.code == "le_only_channel")
    assert lert in w.text and pbm.LE_ONLY_REASON in w.text
    officer = mg.guide(_inp(channels=channels, requester="le"))  # an LE sender (never Aegis) would get it
    assert officer.to[0].address == lert


def test_guidance_le_only_warning_freeze_purpose_and_order_channels():
    g = mg.guide(_inp(le_only_reason="LE only: send the officer the pack: KuCoin acts only on LE requests."))
    assert g.warnings[0].code == "le_only" and g.warnings[0].level == "critical" and g.blocking
    le = mg.guide(_inp(is_le=True, le_only_reason="x"))
    assert not any(w.code == "le_only" for w in le.warnings)
    freeze = mg.guide(_inp(channels=(mg.Channel("circleblocklisting@circle-demo.example", verified=True,
                                                source="catalogue", purpose="freeze", who="counsel_with_order",
                                                label="Freeze requests"),)))
    top = freeze.to[0]
    assert top.score == 100 and top.why.startswith("verified freeze-request channel (Freeze requests) — acts on LE")
    unverified = mg.guide(_inp(channels=(mg.Channel("circleblocklisting@circle-demo.example", source="catalogue",
                                                    purpose="freeze", who="counsel_with_order"),)))
    assert "published freeze-request address" in unverified.to[0].why and "expect a redirect" in unverified.to[0].why


def _closed_kucoin(monkeypatch, *, open_path: bool):
    raw = _pb()
    if not open_path:
        raw["paths"] = [raw["paths"][1]]
    cat = _catalogue_with(raw)
    monkeypatch.setattr(directory, "load_catalogue", lambda *a, **k: cat)
    return cat


def test_next_letter_and_templates_follow_the_gate(db, case, monkeypatch):
    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    _closed_kucoin(monkeypatch, open_path=False)
    kucoin = next(a for a in desk.case_authorities(db, case, run=run) if a.name == "KuCoin")
    assert mg.next_kind(kucoin) == "le_handoff" and "LE hand-off" in mg.KIND_LABELS["le_handoff"]
    opts = {o["key"]: o for o in desk.template_options(kucoin, run)}
    for key in ("stop_order", "info_request"):  # first contact only
        assert not opts[key]["available"] and opts[key]["reason"].startswith(pbm.LE_ONLY_REASON), key
    for key in ("status_request", "release_request"):  # a follow-up on a letter sent stays possible
        assert not (opts[key]["reason"] or "").startswith(pbm.LE_ONLY_REASON), key
    assert not services.generate_stop_orders(db, case, run, only=["KuCoin"])  # the bulk generator gates too
    with pytest.raises(desk.DeskError, match="LE only"):
        desk.generate_letter(db, case, kucoin, "info_request", actor=None, run=run)
    db.rollback()
    access = SimpleNamespace(case=case, can=lambda action: True, user=None)
    card = SimpleNamespace(emails=list, info_only=False, portal_only=False, portal_url=None)
    g = mg.for_authority(db, access, kucoin, card=card)
    assert g.letter_kind == "le_handoff" and g.warnings[0].code == "le_only"
    ic3 = next(a for a in desk.case_authorities(db, case, run=run) if "IC3" in a.name)
    assert mg.next_kind(ic3) != "le_handoff"  # LE authorities are never gated
    assert sender_mod.requester_kind(db, case) in pbm.PRIVATE


def test_open_path_changes_nothing(db, case, monkeypatch):
    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    _closed_kucoin(monkeypatch, open_path=True)
    kucoin = next(a for a in desk.case_authorities(db, case, run=run) if a.name == "KuCoin")
    assert desk.playbook_gate_reason(kucoin) is None and mg.next_kind(kucoin) != "le_handoff"
    assert next(o for o in desk.template_options(kucoin, run) if o["key"] == "info_request")["available"]


@pytest.fixture
def mail(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    settings, transport = FakeSettings(), FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport)


def test_compose_refuses_an_le_only_recipient(db, case, client_for, mail, monkeypatch):
    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    corr = _draft(db, case, run)  # drafted before the playbook says the address is LE-only
    _closed_kucoin(monkeypatch, open_path=True)
    assert TO == "le-requests@kucoin.example"  # the synthetic playbook's le_only address
    inv = client_for("investigator", case=case)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert re.search(rf'name="to" value="{re.escape(TO)}"[^>]*disabled', page) and pbm.LE_ONLY_REASON in page
    for form in ({"to_other": TO}, {"to_other": "desk@kucoin.example", "cc_other": TO},
                 {"to_other": "desk@kucoin.example", "bcc_other": TO}):  # LE only: never a hidden recipient either
        r = _compose(inv, case, corr, **form)
        assert r.status_code == 400 and "LE only" in r.text and "reserved for law enforcement" in r.text
    assert not db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)).all()
    assert _compose(inv, case, corr, to_other="desk@kucoin.example").status_code == 303
    assert _auth(db, case, "KuCoin", run) is not None


# --------------------------------------------------------------------------- matching hygiene
def test_authority_domains_count_sent_letters_only(db, case):
    def letter(status, to):
        return SimpleNamespace(direction=CorrespondenceDirection.OUT, status=status, recipients=[to], meta={})

    authority = SimpleNamespace(entity=None, le_contacts=[], name="Synthetic Exchange", correspondence=[
        letter(CorrespondenceStatus.SENT, "desk@sent-exchange.example"),
        letter(CorrespondenceStatus.DRAFT, "typo@draft-only.example")])
    got = matching.authority_domains(db, case, authority)
    assert "sent-exchange.example" in got and "draft-only.example" not in got


def test_shipped_files_round_trip_through_the_parser():
    for f in PROVIDERS.glob("*.json"):
        raw = json.loads(f.read_text(encoding="utf-8"))
        cat = directory.parse_catalogue(_channels_json(), {f.name: copy.deepcopy(raw)})
        assert cat.by_key[raw["key"]].playbook is not None
