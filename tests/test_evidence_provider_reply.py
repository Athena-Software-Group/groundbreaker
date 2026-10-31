"""Evidence intel: an uploaded provider reply (an exchange's compliance letter saying an account is frozen, with the
amount held and its ticket) is read as a provider's reply, never as a letter from law enforcement although it
cites "law enforcement requests" and our "preservation request"; the request it answers is suggested (a person picks
and files it), its ticket and reply date are proposals the person keeps or edits, the outcome it states stays a
suggestion on Block status, and once filed it leaves the "Unclassified / suggested" list. Synthetic documents."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from test_block_status import fresh_case
from test_evidence_intel import _new_item, _tok, _upload, make_pdf

from app.db.models import AuditEvent, Correspondence, EvidenceFolder, EvidenceItem
from app.domain import evidence as ev
from app.evidence_intel import findings, rules
from app.evidence_intel import service as intel


@pytest.fixture
def vault(tmp_path, monkeypatch):
    path = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(path))
    return path


@pytest.fixture
def fcase(db, tmp_path):
    return fresh_case(db, tmp_path)


@pytest.fixture
def client(client_for, fcase):
    return client_for("admin", case=fcase)


def _kucoin_order(case):
    return next(o for o in case.stop_orders if o.entity is not None and o.entity.name == "KuCoin"
                and o.status.value != "superseded")


def _deposit(order) -> str:
    import re

    return re.search(r"0x[0-9a-fA-F]{40}", order.body_markdown).group(0)


def _reply_lines(case, address: str) -> list[str]:
    return ["KuCoin Compliance", "Law Enforcement Response Team", "21 October 2026", "",
            f"Re: Your law enforcement request / preservation request - Ref {case.reference}",
            "Ticket KC-DEMO-55555", "", "Dear Sir or Madam,",
            f"Thank you for your preservation request regarding deposit address {address}.",
            "We confirm that the account associated with the above deposit address has been frozen.",
            "Amount held 0.0568 ETH.",
            "Any disclosure of account information requires a formal law enforcement request.",
            "KuCoin Compliance Team"]


SHORT = ("We confirm that the account associated with the above deposit address has been frozen. Amount held 0.0568 "
         "ETH. Ticket KC-DEMO-55555. Our compliance team handles law enforcement requests; your preservation request "
         "is noted. KuCoin")


def test_rules_read_a_freeze_confirmation_as_a_provider_reply():
    f = findings.find(SHORT, orgs=intel._catalogue_orgs())
    assert f["tickets"] == ["KC-DEMO-55555"]
    r = rules.classify(SHORT, name="reply.pdf", kind="pdf", provider_named=True, ticket=True,
                       reply_status="frozen")
    assert r["type"] == "provider_reply" and r["folder"] == "stop_orders_correspondence", r
    assert r["confidence"] in ("H", "M") and "a provider's ticket number" in r["reasons"]
    # the reasons show the cue's frame, never the account / ticket the document names
    assert not any("kc-demo" in x.lower() for x in r["reasons"])
    # without the provider's own signals the LE words alone still never win over its own cues
    assert rules.classify(SHORT, name="reply.pdf", kind="pdf")["type"] == "provider_reply"


def test_a_real_le_letter_and_a_chat_stay_what_they_are():
    le = ("Federal Bureau of Investigation\nSpecial Agent J. Doe\nLaw enforcement request: preservation request for "
          "the account at KuCoin. We are investigating a fraud. Please preserve all records.")
    assert rules.classify(le, kind="pdf", provider_named=True)["type"] == "le_letter"
    chat = ("[01/09/2026, 10:05:00] KuCoin Support: your account has been frozen. Ticket #558812\n"
            "[01/09/2026, 10:06:00] Anna: what do I do?\n[01/09/2026, 10:07:00] KuCoin Support: pay the unlock fee\n"
            "[01/09/2026, 10:08:00] Anna: ok\n[01/09/2026, 10:09:00] KuCoin Support: thanks")
    r = rules.classify(chat, kind="text", provider_named=True, ticket=True, reply_status="frozen")
    assert r["type"] == "chat_export", r


def test_upload_suggest_link_and_queue(client, fcase, vault, db):
    case = fcase
    order = _kucoin_order(case)
    address = _deposit(order)
    data = make_pdf([_reply_lines(case, address)])
    r = _upload(client, case, "scan_0042.pdf", data, "application/pdf")
    assert r.status_code == 303
    item = _new_item(db, case, data)
    iv = intel.intel(item)
    assert iv["rules"]["type"] == "provider_reply", iv["rules"]
    assert iv["reply"]["ticket"] == "KC-DEMO-55555" and iv["reply"]["status"] == "frozen"
    assert iv["reply"]["amount"] == "0.0568" and iv["reply"]["asset"] == "ETH"
    assert item.folder == EvidenceFolder.OTHER and not iv.get("confirmed")  # nothing applied by itself

    tab = client.get(f"/cases/{case.id}?tab=evidence").text
    assert "Review the reply" in tab and "KC-DEMO-55555" in tab

    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert "a provider's reply (Frozen 0.0568 ETH; ticket KC-DEMO-55555)" in intel.summary_line(item)
    assert "A reply to your request?" in page and f'value="{order.id}" checked' in page
    assert 'name="ticket" value="KC-DEMO-55555"' in page and 'name="reply_date" value="2026-10-21"' in page
    assert "A suggestion, not a result" in page and "Already on this case" in page
    v = intel.view(db, _admin_access(db, case), item)
    assert v["orders"][0]["id"] == order.id and v["orders"][0].get("suggested")
    assert any("cites" in w for w in v["orders"][0]["why"])

    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/link",
                    data={"csrf_token": _tok(client, case), "stop_order_id": str(order.id), "record_ticket": "1",
                          "ticket": "KC-DEMO-55555", "reply_date": "2026-10-21"}, follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    db.expire_all()
    corr = db.scalar(select(Correspondence).where(Correspondence.evidence_item_id == item.id))
    assert corr.stop_order_id == order.id and corr.external_ref == "KC-DEMO-55555"
    assert corr.occurred_at.date().isoformat() == "2026-10-21"
    item = db.get(EvidenceItem, item.id)
    conf = intel.intel(item)["confirmed"]
    assert conf["type"] == "provider_reply" and conf["source"] == "link"
    assert item.folder == EvidenceFolder.STOP_ORDERS_CORRESPONDENCE
    # the stop order's outcome is not recorded by the filing: Block status suggests it, a person confirms it
    assert db.get(type(order), order.id).status.value != "frozen"
    rows = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id)).all()
    assert "KC-DEMO-55555" not in str([a.detail for a in rows])
    tab = client.get(f"/cases/{case.id}?tab=evidence").text
    assert f"/evidence/{item.id}#ev-intel-reply" not in tab and f"/evidence/{item.id}#ev-intel\"" not in tab
    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert "Filed as the reply" in page and "filed as the reply to a request" in page
    blocks = client.get(f"/cases/{case.id}/blocks").text
    assert "0.0568" in blocks and "KC-DEMO-55555" in blocks  # Block status: a suggestion, with their ticket


def test_ticket_is_kept_only_when_the_person_keeps_it(client, fcase, vault, db):
    case = fcase
    order = _kucoin_order(case)
    data = make_pdf([_reply_lines(case, _deposit(order))[:-1] + ["KuCoin Compliance Team (copy 2)"]])
    _upload(client, case, "reply-2.pdf", data, "application/pdf")
    item = _new_item(db, case, data)
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/link",
                    data={"csrf_token": _tok(client, case), "stop_order_id": str(order.id),
                          "ticket": "KC-DEMO-55555", "reply_date": "not a date"}, follow_redirects=False)
    assert "ev_err" in r.headers["location"]
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/link",
                    data={"csrf_token": _tok(client, case), "stop_order_id": str(order.id),
                          "ticket": "KC-DEMO-55555"}, follow_redirects=False)
    assert "ev_err" not in r.headers["location"]
    db.expire_all()
    corr = db.scalar(select(Correspondence).where(Correspondence.evidence_item_id == item.id))
    assert corr.external_ref is None


def test_seed_pass_verifies_and_reads_without_applying(db, fcase):
    for e in fcase.evidence_items:
        e.meta = {k: v for k, v in (e.meta or {}).items() if k not in ("intel", "integrity")}
    db.flush()
    counts = intel.seed_pass(db, fcase)
    assert counts["read"] == len(fcase.evidence_items) and counts["verified"] >= 1
    for e in fcase.evidence_items:
        assert intel.intel(e) and not intel.intel(e).get("confirmed") and not (intel.intel(e).get("ai"))
    db.rollback()


def test_source_type_labels():
    assert ev.source_type_label("complaint_receipt") == "Complaint receipt"
    assert ev.source_type_label("authority_instrument") == "Authority document"
    assert ev.source_type_label("my_custom_kind") == "My custom kind"
    assert ev.source_type_label(None) == ""


def _admin_access(db, case):
    from app.core.permissions import CaseAccess
    from app.db.models import CaseMember, CaseRole, User

    m = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.role == CaseRole.ADMIN))
    user = db.get(User, m.user_id)
    return CaseAccess(case=case, user=user, role=m.role, member=m)
