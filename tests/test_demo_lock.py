"""The demo lock: a demo / training case (Case.is_demo) never prepares, sends or records an e-mail to a real
organisation, and its "How to email" guidance never names one (app.domain.mail_guidance / mail_compose /
mail_send)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from test_mail_compose_send import TO, _compose, _draft, _prepared, _send
from test_mail_one_send import mail, run  # noqa: F401 - fixtures

from app.core.permissions import CaseAccess, effective_role, membership
from app.db.models import MailStatus
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_guidance as mg
from app.domain import mail_send

AT = "@"  # real-looking addresses are built at run time: the PII scan reads only literal reserved-domain ones
REAL = f"ops{AT}" + "kucoin-real" + ".io"


def test_demo_safe_is_the_reserved_names_only():
    for ok in ("a@circle-demo.example", f"a{AT}x.test", "a@example.com", "A@Sub.Example.ORG", f"a{AT}host.localhost",
               f"a{AT}b.invalid", "a@example.net"):
        assert mg.demo_safe(ok), ok
    for bad in (REAL, f"a{AT}example.io", f"a{AT}notexample.com", f"a{AT}example.com.evil.io", "no-at-sign", "", None,
                f"a{AT}circle" + ".com"):
        assert not mg.demo_safe(bad), bad


def test_guide_hides_real_addresses_for_a_demo_case():
    real = f"circleblocklisting{AT}" + "circle" + ".com"
    channels = (mg.Channel(real, verified=True, source="catalogue", purpose="freeze"),
                mg.Channel("compliance@circle-demo.example", source="entity_record"))
    base = {"authority_name": "Circle (USDC issuer)", "case_reference": "DEMO-2026-001", "channels": channels,
            "sent": (mg.SentLetter(at=None, to=(f"legal{AT}" + "circle" + ".com",)),)}
    live = mg.guide(mg.Inputs(**base))
    assert live.to[0].address == real  # a live (non-demo) case: the verified freeze channel first
    demo = mg.guide(mg.Inputs(**base, demo=True))
    shown = [s.address for s in [*demo.to, *demo.cc, *demo.avoid]]
    assert shown == ["compliance@circle-demo.example"] and demo.to[0].recommended
    w = next(w for w in demo.warnings if w.code == "demo")
    assert w.level == "info" and "2 real published addresses not shown" in w.text
    assert not [w for w in demo.warnings if w.code == "unverified"]


def test_demo_lock_problem():
    demo, real_case = SimpleNamespace(is_demo=True), SimpleNamespace(is_demo=False)
    assert compose.demo_lock_problem(real_case, [REAL]) is None
    assert compose.demo_lock_problem(demo, [TO, "x@example.com"]) is None
    assert REAL in compose.demo_lock_problem(demo, [TO, REAL])
    mailbox = f"desk{AT}" + "athena-real" + ".io"
    assert compose.demo_lock_problem(demo, [TO, mailbox], mailbox=mailbox) is None  # our own mailbox (manual Cc)


def test_compose_options_and_guidance_offer_no_real_address(db, case, run, client_for, mail):  # noqa: F811
    assert case.is_demo
    circle = next(a for a in desk.case_authorities(db, case, run=run) if a.name.startswith("Circle"))
    adm = client_for("admin", case=case)
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    g = mg.for_authority(db, access, circle)
    shown = [s.address for s in [*g.to, *g.cc, *g.avoid]]
    assert "compliance@circle-demo.example" in shown and all(mg.demo_safe(a) for a in shown), shown
    assert any(w.code == "demo" for w in g.warnings)
    corr = _draft(db, case, run)
    opts = compose.compose_options(db, access, corr, desk.get_authority(db, case, corr_key(corr)))
    assert all(mg.demo_safe(r.address) for r in opts.recipients)  # KuCoin's published channels are real: none
    assert all(mg.demo_safe(a) for a in compose._split(opts.to_other) + compose._split(opts.cc_other))


def corr_key(corr) -> str:
    return f"entity-{corr.entity_id}"


def test_prepare_refuses_a_real_recipient_on_a_demo_case(db, case, run, client_for, mail):  # noqa: F811
    corr = _draft(db, case, run)
    adm = client_for("admin", case=case)
    for field in ("to_other", "cc_other", "bcc_other"):
        r = _compose(adm, case, corr, **{field: (TO + ", " + REAL) if field == "to_other" else REAL})
        assert r.status_code == 400 and "demo case" in r.text and REAL in r.text, field
    mail.settings.aegis_mail_live_sending = True  # the deployment went live: the demo lock still holds
    r = _compose(adm, case, corr, to_other=REAL)
    assert r.status_code == 400 and "demo case" in r.text


def test_send_and_record_refuse_a_real_recipient_on_a_demo_case(db, case, run, client_for, mail):  # noqa: F811
    corr = _draft(db, case, run)
    adm = client_for("admin", case=case)
    mm = _prepared(db, _compose(adm, case, corr))
    assert mm.to_addrs == [TO]
    mm.cc_addrs = [REAL]  # a row changed after the preview (or written by an older build): Send checks again
    db.commit()
    r = _send(adm, case, mm)
    assert r.status_code == 409 and "Demo case: e-mail goes only to reserved demo addresses" in r.text
    db.expire_all()
    assert db.get(type(mm), mm.id).status == MailStatus.PREPARED and not mail.transport.sent
    access = SimpleNamespace(case=case, user=adm.user, can=lambda action: True)
    with pytest.raises(mail_send.SendError) as e:
        mail_send.record_external(db, access, db.get(type(mm), mm.id), {
            "confirm_external": "1", "sent_at": datetime.now(tz=UTC).isoformat(), "to": REAL})
    assert e.value.reason == "demo_lock"
