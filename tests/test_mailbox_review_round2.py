"""Review fixes of the mailbox sync and the e-mail desk (review round 2):

* the compose page keeps the purpose of a letter when an authority's reply redirected an earlier request: a
  new information request (not tied to the redirected stop order) is addressed to the legal inbox the reply
  named, and the inbox that redirected us is not ticked;
* an Outlook e-mail logged for review / dismissed / "not addressed to the authority" never feeds the
  authority's contacts, the guidance's "earlier recipients" or the compose page's options;
* Tie to letter never offers (nor accepts) a letter recorded as sent long after the e-mail;
* an Outlook e-mail whose candidate letters are all recorded since reads "probably a copy" and is not
  counted as "to review".

Offline: the fake Microsoft Graph of tests/test_mailbox_sync.py (httpx.MockTransport); no model; every case
is created by the test itself.
"""

# ruff: noqa: F811  (the `mbx` fixture is imported from test_mailbox_sync and used as a parameter)
from __future__ import annotations

import re
import uuid
from datetime import UTC, timedelta

import pytest
from conftest import csrf_token, ungated
from test_block_status import CIRCLE_LIKE, _authority, _order, _reply, fresh_case
from test_mailbox_sync import FREEMAIL, NOW, RECENT, _rows, eml, make_case, mbx  # noqa: F401 (fixtures)

from app.ai import providers
from app.blocks import report
from app.blocks import status as bs
from app.core.permissions import CaseAccess, effective_role, membership
from app.db import models as M
from app.domain import correspondence as desk
from app.domain import directory, mail_compose, mail_guidance
from app.mail import sync_outbound

LEGACY = "compliance@kucoin-demo.example"
FREEZE_TO = "asset-freeze@kucoin-demo.example"
LEGAL_TO = "legal-process@kucoin-demo.example"


@pytest.fixture(autouse=True)
def _no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


def _checked(page: str, name: str, address: str) -> bool:
    m = re.search(rf'<input type="checkbox" name="{name}" value="{re.escape(address)}" ([^>]*)>', page)
    return bool(m and "checked" in m.group(1))


def _to_other(page: str) -> str:
    return re.search(r'name="to_other" class="mono" value="([^"]*)"', page).group(1)


# --------------------------------------------------------------------------- MAJOR: the purpose of a new letter
def _circle_like_redirect(db, case):
    order = _order(case, "KuCoin")
    order.recipient_email = LEGACY
    db.commit()
    reply = _reply(db, case, order, CIRCLE_LIKE, mailbox=True, auto=True)
    reply.sender = LEGACY
    reply.meta = {**(reply.meta or {}), "sender_domain_ok": True}
    db.commit()
    return order, reply


def test_a_new_information_request_after_a_redirected_stop_order_goes_to_the_legal_inbox(db, client_for, tmp_path):
    case = fresh_case(db, tmp_path)
    order, reply = _circle_like_redirect(db, case)
    a = _authority(db, case, order)
    with ungated():  # a records request beside the redirected stop order (the redirect hint is under test)
        info = desk.generate_letter(db, case, a, "info_request", actor=None)
    info.stop_order_id = None  # a new request, not tied to the redirected stop order
    info.recipients = [LEGACY]  # what the draft was generated with: the legacy inbox
    db.commit()
    hint = mail_compose.redirect_hint(db, case, info, a)
    assert hint is not None and hint["to"] == LEGAL_TO and hint["legacy"] == LEGACY and hint["prefilled"]
    assert hint["reply_id"] == reply.id
    adm = client_for("admin", case=case, email=f"adm-info-redirect-{uuid.uuid4().hex[:6]}@tests.example")
    page = adm.get(f"/cases/{case.id}/authorities/correspondence/{info.id}/email")
    assert page.status_code == 200, page.text[:300]
    text = page.text
    assert "mail-redirect" in text and LEGAL_TO in text
    others = [x.strip() for x in _to_other(text).split(",") if x.strip()]
    assert others and others[0] == LEGAL_TO and LEGACY not in others
    assert not _checked(text, "to", LEGACY)
    # a status request on the same authority, not tied to the stop order either: the freeze inbox
    status = desk.generate_letter(db, case, a, "status_request", actor=None)
    status.stop_order_id = None
    db.commit()
    assert mail_compose.redirect_hint(db, case, status, a)["to"] == FREEZE_TO


def test_after_the_resend_a_new_letter_still_avoids_the_legacy_inbox(db, tmp_path):
    case = fresh_case(db, tmp_path)
    order, reply = _circle_like_redirect(db, case)
    a = _authority(db, case, order)
    desk.log_entry(db, case, a, actor=None, direction="out", channel="email", kind="status_request",
                   subject="Follow-up", body="Resent.", stop_order=order, recipients=[FREEZE_TO], due_days=7,
                   occurred_at=reply.occurred_at.replace(tzinfo=UTC) + timedelta(hours=2))
    assert bs.find_row(bs.case_blocks(db, case), f"o{order.id}").status == bs.AWAITING  # no longer "redirected"
    a = _authority(db, case, order)  # (an Authority is a snapshot of its correspondence)
    follow = desk.generate_letter(db, case, a, "status_request", actor=None)
    assert follow.stop_order_id == order.id
    hint = mail_compose.redirect_hint(db, case, follow, a)
    assert hint is not None and hint["to"] == FREEZE_TO and hint["legacy"] == LEGACY


def test_no_hint_without_a_redirect_or_from_a_foreign_domain(db, tmp_path):
    case = fresh_case(db, tmp_path)
    order = _order(case, "KuCoin")
    a = _authority(db, case, order)
    with ungated():  # a records request beside the stop order (the redirect hint is under test)
        info = desk.generate_letter(db, case, a, "info_request", actor=None)
    assert mail_compose.redirect_hint(db, case, info, a) is None
    reply = _reply(db, case, order, CIRCLE_LIKE, mailbox=True, auto=True)
    reply.sender = LEGACY
    reply.meta = {**(reply.meta or {}), "sender_domain_ok": False}
    db.commit()
    info.stop_order_id = None
    db.commit()
    assert mail_compose.redirect_hint(db, case, info, a) is None  # an untrusted redirect never retargets a new letter


# --------------------------------------------------------------------------- Outlook e-mails not to the authority
def test_an_outlook_email_to_someone_else_never_feeds_the_authoritys_contacts(db, mbx, client_for):
    w = make_case(db)
    other = f"partner.{w.tag}@lawfirm-mbx-demo.example"
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=other, cc=f"assoc.{w.tag}@{FREEMAIL}", subject=w.subject,
                                  body=f"FYI: please freeze {w.wallet}."), at=RECENT)
    assert mbx.sync(db).sent["logged"] == 1
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.meta["review_reason"] == "no recipient is the letter's authority"
    entry = db.get(M.Correspondence, mm.correspondence_id)
    assert entry.status == M.CorrespondenceStatus.SENT and directory.recipients_untrusted(entry)
    adm = client_for("admin", case=w.case, email=f"adm-partner-{w.tag}@tests.example")

    def check():
        page = adm.get(f"/cases/{w.case.id}/authorities/correspondence/{w.corr.id}/email")
        assert page.status_code == 200, page.text[:300]
        assert other not in page.text  # not an option, not "an address used in the letter you sent"
        # the contact card ("From this case's correspondence"): the timeline still shows the e-mail as sent
        db.expire_all()
        case = db.get(M.Case, w.case.id)
        a = next(x for x in desk.case_authorities(db, case, include_prospects=False) if x.key == f"entity-{w.entity.id}")
        access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                            member=membership(db, adm.user, case))
        assert other not in [e.value for e in directory.channels_for(db, access, a).emails()]
        guidance = mail_guidance.for_authority(db, access, a, db.get(M.Correspondence, w.corr.id))
        assert all(other not in s.address for s in [*guidance.to, *guidance.cc, *guidance.avoid])

    check()
    # dismissed, it still says nothing about the authority's addresses
    tok = csrf_token(adm, f"/cases/{w.case.id}/blocks")
    r = adm.post(f"/cases/{w.case.id}/blocks/c{entry.id}/outlook", data={"action": "dismiss", "csrf_token": tok},
                 follow_redirects=False)
    assert r.status_code in (303, 404)
    db.expire_all()
    if r.status_code == 404:  # (not listed as a request when it named no candidate): dismiss it directly
        sync_outbound.dismiss(db, db.get(M.MailMessage, mm.id))
    assert directory.recipients_untrusted(db.get(M.Correspondence, entry.id))
    check()


def test_recipients_untrusted_unit():
    class C:
        def __init__(self, **meta):
            self.meta = meta

    assert not directory.recipients_untrusted(C())
    assert not directory.recipients_untrusted(C(source="mailbox_sent", needs_review=False, follow_up_of="o1"))
    assert directory.recipients_untrusted(C(source="mailbox_sent", needs_review=True))
    assert directory.recipients_untrusted(C(source="mailbox_sent", needs_review=False, dismissed=True))
    assert directory.recipients_untrusted(C(source="mailbox_sent", needs_review=False, tied_to="c1",
                                            review_reason="no recipient is the letter's authority"))
    assert not directory.recipients_untrusted(C(source="mailbox_sent", needs_review=False, tied_to="c1",
                                                review_reason="2 letters match (c1, o2)"))


# --------------------------------------------------------------------------- Tie to letter: time rule
def _logged_review(db, mbx):
    w = make_case(db, second_order=True)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    assert mbx.sync(db).sent["logged"] == 1
    (mm,) = _rows(db, mbx.mailbox)
    return w, mm


def test_tie_never_offers_a_letter_sent_long_after_the_email(db, mbx):
    w, mm = _logged_review(db, mbx)
    sent_at = mm.sent_at.replace(tzinfo=UTC) if mm.sent_at.tzinfo is None else mm.sent_at
    desk.mark_sent(db, w.case, w.corr, actor=None, sent_at=sent_at + timedelta(days=3), channel="email")
    desk.record_stop_order_status(db, w.case, w.order2, "sent", actor=None, occurred_at=sent_at + timedelta(hours=3))
    db.expire_all()
    mm = db.get(M.MailMessage, mm.id)
    cands = sync_outbound.tie_candidates(db, mm)
    orders = {x.order.id for x in cands if x.order is not None}
    assert w.order2.id in orders  # a send recorded a few hours later is still that send
    assert w.order.id not in orders and all(x.corr is None or x.corr.id != w.corr.id for x in cands)  # 3 days later
    with pytest.raises(sync_outbound.ReviewError) as err:
        sync_outbound.tie_to_letter(db, mm, f"c{w.corr.id}")
    assert err.value.status == 400 and "sent after this e-mail" in str(err.value)
    labels = [label for _, label in report.tie_options(db, db.get(M.Case, w.case.id),
                                                       next(r for r in bs.case_blocks(db, db.get(M.Case, w.case.id))
                                                            if r.kind == "outlook"))]
    assert labels and not any(f"Stop order #{w.order.id} " in x for x in labels)


# --------------------------------------------------------------------------- "probably a copy"
def test_an_outlook_email_whose_candidates_are_recorded_reads_probably_a_copy(db, mbx, client_for):
    w, _ = _logged_review(db, mbx)
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    (row,) = [r for r in rows if r.kind == "outlook"]
    assert row.needs_review and row.label == bs.LABELS[bs.SENT_REVIEW] and bs.summary(rows)["sent_review"] == 1
    desk.mark_sent(db, w.case, w.corr, actor=None, sent_at=NOW, channel="email")
    desk.record_stop_order_status(db, w.case, w.order2, "sent", actor=None, occurred_at=NOW)
    db.expire_all()
    case = db.get(M.Case, w.case.id)
    rows = bs.case_blocks(db, case)
    (row,) = [r for r in rows if r.kind == "outlook"]
    assert not row.needs_review and row.probable_copy and row.label == bs.SENT_COPY_LABEL
    s = bs.summary(rows)
    assert s["sent_review"] == 0 and s["to_review"] == sum(1 for r in rows if r.needs_review or r.status in bs.OUR_ACTION)
    assert row not in report._filter(rows, "action")
    adm = client_for("admin", case=w.case, email=f"adm-copy-{w.tag}@tests.example")
    page = adm.get(f"/cases/{w.case.id}/blocks").text
    i = page.index(f'id="{row.key}"')
    cell = page[i:page.index("</tr>", i)]
    assert bs.SENT_COPY_LABEL in cell and "needs review" not in cell
    overview = adm.get(f"/cases/{w.case.id}").text
    assert "sent from Outlook to review" not in overview
