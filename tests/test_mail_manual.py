"""E-mail desk, "Draft — you send" (AEGIS_MAIL_TRANSPORT=manual, the default): recipient and subject
guidance, the send-it-yourself checklist (X-Unsent draft, attachments .zip, copy data, mailto), recording
a send made outside Aegis, importing a reply (.eml / .msg) for review — with no outbound network at all."""

import hashlib
import io
import itertools
import json
import re
import socket
import struct
import uuid
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime
from types import SimpleNamespace

import httpx
import pytest
from conftest import csrf_token, ungated
from sqlalchemy import select

from app import services
from app.db.models import (
    AuditEvent,
    Chain,
    Correspondence,
    CorrespondenceStatus,
    EvidenceItem,
    MailDirection,
    MailMessage,
    MailStatus,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_guidance as mg
from app.domain import mail_import, mail_send
from app.mail.config import MailSettings
from app.mail.transport import ManualTransport, TransportError, get_transport

# the stop orders drafted here past the request gate repeat a request the shared demo case already sent (duplicates):
# e-mailed all the same (conftest.past_duplicates)
pytestmark = pytest.mark.usefixtures("past_duplicates")

MAILBOX = "investigations@athena-demo.example"
TO = "le-requests@kucoin-demo.example"


# --------------------------------------------------------------------------- fakes
@dataclass
class FakeSettings:
    aegis_mail_transport: str = "manual"
    aegis_mail_from: str = MAILBOX
    aegis_mail_from_name: str = "Athena Software Group, Inc."
    aegis_mail_max_message_bytes: int = 2_900_000
    aegis_mail_send_per_hour: int = 20
    aegis_mail_send_per_hour_global: int = 60
    aegis_mail_dev_allowed_domains: str = "example.com,example.org,example.net,example"
    max_inbound_bytes: int = 25 * 1024 * 1024

    @property
    def mail_from(self):
        return self.aegis_mail_from.strip().lower()

    @property
    def mail_domain(self):
        return self.mail_from.rpartition("@")[2]

    @property
    def from_name(self):
        return self.aegis_mail_from_name

    @property
    def max_message_bytes(self):
        return self.aegis_mail_max_message_bytes

    @property
    def dev_allowed_domains(self):
        return {d.strip() for d in self.aegis_mail_dev_allowed_domains.split(",") if d.strip()}


class NoTransport:
    """Manual mode never reaches a transport: any call fails the test."""

    name = "manual"

    def status(self):
        return SimpleNamespace(name="manual", configured=False, reason="manual mode", mailbox=MAILBOX)

    def send_mime(self, raw, *, message_id):  # pragma: no cover - must never run
        raise AssertionError("manual mode must not send")

    def lookup_sent(self, **kw):  # pragma: no cover
        raise AssertionError("manual mode must not ask a mailbox")


@pytest.fixture
def no_network(monkeypatch):
    """Every outbound connection attempt fails the test (sockets and httpx)."""
    attempts = []

    def refuse(*a, **kw):
        attempts.append(a)
        raise AssertionError("outbound network in manual mode")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    return attempts


@pytest.fixture
def mail(monkeypatch, tmp_path, no_network):
    vault = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    settings = FakeSettings()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: NoTransport())
    return SimpleNamespace(settings=settings, vault=vault, network=no_network)


@pytest.fixture
def emitted(monkeypatch):
    calls = []
    real = desk.events.emit

    def spy(db, case, event_type, **kw):
        calls.append({"type": event_type, **kw})
        return real(db, case, event_type, **kw)

    monkeypatch.setattr(desk.events, "emit", spy)
    return calls


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


def _auth(db, case, name, run=None):
    db.expire_all()
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == name)


def _draft(db, case, run, template="stop_order", name="KuCoin"):
    """A draft letter to `name` of the shared demo case, one test after another (past the request gate: conftest
    .ungated)."""
    with ungated():
        return desk.generate_letter(db, case, _auth(db, case, name, run), template, actor=None, run=run)


def _compose(c, case, corr, **form):
    path = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = c.get(path)
    assert page.status_code == 200, page.text[:500]
    subject = re.search(r'name="subject" id="mail-subject" maxlength="220" required value="([^"]*)"', page.text)
    data = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page.text).group(1),
            "subject": subject.group(1).replace("&amp;", "&") if subject else corr.subject[:200],
            "to_other": TO, "attach": ["letter"]}
    data.update(form)
    return c.post(path, data=data, follow_redirects=False)


def _prepared(db, response) -> MailMessage:
    assert response.status_code == 303, response.text[:2000]
    db.expire_all()
    return db.get(MailMessage, int(response.headers["location"].rsplit("/", 1)[1]))


def _raw(mm) -> bytes:
    return compose.read_raw(mm)


def _record(c, case, mm, files=None, **form):
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    data = {"csrf_token": csrf_token(c, path), "sent_at": (datetime.now(tz=UTC) - timedelta(minutes=2))
            .strftime("%Y-%m-%dT%H:%M"), "to": ", ".join(mm.to_addrs or []), "cc": ", ".join(mm.cc_addrs or []),
            "due_days": "5", "confirm_external": "1"}
    data.update(form)
    return c.post(f"{path}/record-sent", data=data, files=files, follow_redirects=False)


def _other_case(db):
    return services.create_case(
        db, reference=f"TEST-MAN-{uuid.uuid4().hex[:8]}", title="Another case", victim_name="Other Victim",
        victim_entity=None, loss_amount=Decimal(1), loss_asset="USDC", loss_usd=Decimal(1), fraud_date=None,
        chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None, perpetrator_wallet=None)


def reply_eml(*, subject: str, from_="Compliance <le-requests@kucoin-demo.example>", to=MAILBOX, headers=None,
              attachments=(), body="We have placed a hold on the account.") -> bytes:
    msg = EmailMessage()
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.now(tz=UTC) - timedelta(hours=1))
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@kucoin-demo.example>"
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(body)
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="pdf", filename=name)
    return msg.as_bytes()


# --------------------------------------------------------------------------- a tiny compound-file writer (.msg)
def make_cfb(tree: dict) -> bytes:
    """An OLE compound file (v3, 512-byte sectors) holding `tree` ({name: bytes | {…}}): small streams
    in the mini stream, larger ones in regular sectors, like Outlook writes them."""
    SS, MSS, CUTOFF, END, FREE, FATS, NONE = 512, 64, 4096, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
    entries = []

    def add(name, node, kind=None):
        idx = len(entries)
        e = {"name": name, "type": kind or (1 if isinstance(node, dict) else 2), "left": NONE, "right": NONE,
             "child": NONE, "start": END, "size": 0, "data": node if isinstance(node, bytes) else None}
        entries.append(e)
        if isinstance(node, dict):
            kids = [add(k, v) for k, v in node.items()]
            if kids:  # a degenerate tree: the first child, each with its right sibling
                e["child"] = kids[0]
                for a, b in itertools.pairwise(kids):
                    entries[a]["right"] = b
        return idx

    add("Root Entry", tree, kind=5)
    mini, minifat = bytearray(), []
    big = []
    for e in entries[1:]:
        if e["type"] != 2:
            continue
        data = e["data"]
        e["size"] = len(data)
        if len(data) < CUTOFF:
            n = max(1, -(-len(data) // MSS))
            e["start"] = len(mini) // MSS if data else END
            if data:
                first = len(mini) // MSS
                minifat += [first + i + 1 for i in range(n - 1)] + [END]
                mini += data + b"\0" * (n * MSS - len(data))
        else:
            big.append(e)
    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes) -> int:
        n = max(1, -(-len(data) // SS))
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * SS:(i + 1) * SS].ljust(SS, b"\0"))
            fat.append(start + i + 1 if i < n - 1 else END)
        return start

    for e in big:
        e["start"] = place(e["data"])
    root = entries[0]
    root["start"] = place(bytes(mini)) if mini else END
    root["size"] = len(mini)
    minifat_start = place(struct.pack(f"<{len(minifat)}I", *minifat)) if minifat else END
    n_minifat = -(-len(minifat) * 4 // SS) if minifat else 0
    dirs = b""
    for e in entries:
        name = e["name"].encode("utf-16-le") + b"\0\0"
        dirs += name.ljust(64, b"\0") + struct.pack("<HBB", len(name), e["type"], 1) + struct.pack(
            "<III", e["left"], e["right"], e["child"]) + b"\0" * 16 + b"\0" * 4 + b"\0" * 16 + struct.pack(
            "<IQ", e["start"], e["size"])
    dir_start = place(dirs.ljust(-(-len(dirs) // SS) * SS, b"\0"))
    n_fat = 1
    while (len(sectors) + n_fat) * 4 > n_fat * SS:
        n_fat += 1
    fat_ids = list(range(len(sectors), len(sectors) + n_fat))
    fat += [FATS] * n_fat
    fat += [FREE] * (n_fat * SS // 4 - len(fat))
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for i in range(n_fat):
        sectors.append(fat_bytes[i * SS:(i + 1) * SS])
    header = bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIII", 0, n_fat, dir_start, 0) + struct.pack("<IIIII", CUTOFF, minifat_start, n_minifat,
                                                                         END, 0)
    difat = fat_ids + [FREE] * (109 - len(fat_ids))
    header += struct.pack("<109I", *difat)
    assert len(header) == 512
    return header + b"".join(sectors)


def _u(s: str) -> bytes:
    return s.encode("utf-16-le")


def make_msg(*, subject: str, sender="le-requests@kucoin-demo.example", body="We froze the account.",
             headers: str | None = None, attachment: bytes | None = None) -> bytes:
    fixed_top = b"\0" * 32 + struct.pack("<IIQ", 0x00390040, 6, 133_000_000_000_000_000)  # PR_CLIENT_SUBMIT_TIME
    tree = {"__substg1.0_0037001F": _u(subject), "__substg1.0_1000001F": _u(body),
            "__substg1.0_0C1F001F": _u(sender), "__substg1.0_5D01001F": _u(sender),
            "__substg1.0_0C1A001F": _u("KuCoin Compliance"), "__properties_version1.0": fixed_top,
            "__recip_version1.0_#00000000": {
                "__substg1.0_39FE001F": _u(MAILBOX), "__substg1.0_3001001F": _u("Investigations"),
                "__properties_version1.0": b"\0" * 8 + struct.pack("<IIQ", 0x0C150003, 6, 1)}}
    if headers:
        tree["__substg1.0_007D001F"] = _u(headers)
    if attachment is not None:
        tree["__attach_version1.0_#00000000"] = {
            "__substg1.0_37010102": attachment, "__substg1.0_3707001F": _u("hold-confirmation.pdf"),
            "__substg1.0_370E001F": _u("application/pdf")}
    return make_cfb(tree)


# --------------------------------------------------------------------------- manual mode is the default
def test_manual_mode_is_the_default_and_never_transmits(monkeypatch, no_network):
    for k in [k for k in list(__import__("os").environ) if k.startswith("AEGIS_MAIL_")]:
        monkeypatch.delenv(k)
    assert MailSettings().aegis_mail_transport == "manual"
    monkeypatch.setenv("AEGIS_MAIL_TRANSPORT", "")
    assert MailSettings().aegis_mail_transport == "manual"
    monkeypatch.delenv("AEGIS_MAIL_TRANSPORT")
    t = get_transport()
    assert isinstance(t, ManualTransport) and t.name == "manual"
    st = t.status()
    assert not st.configured and "Outlook" in st.reason
    for call in (lambda: t.send_mime(b"x", message_id="<a@b>"), lambda: t.lookup_sent(message_id="<a@b>",
                                                                                         provider_message_id=None)):
        with pytest.raises(TransportError) as e:
            call()
        assert e.value.reason == "disabled"
    for name in ("graph", "file", "none"):  # still available
        monkeypatch.setenv("AEGIS_MAIL_TRANSPORT", name)
        assert MailSettings().aegis_mail_transport == name
    assert compose.is_manual(MailSettings(aegis_mail_transport="manual"))
    assert not compose.is_manual(MailSettings(aegis_mail_transport="graph"))
    assert not no_network


# --------------------------------------------------------------------------- guidance (pure)
OCT18 = datetime(2026, 10, 18, 23, 14, tzinfo=UTC)


def _inp(**kw) -> mg.Inputs:
    base = {"authority_name": "KuCoin", "case_reference": "DEMO-2026-001", "letter_kind": "stop_order",
            "letter_id": 12, "mailbox": MAILBOX, "manual": True}
    base.update(kw)
    return mg.Inputs(**base)


def test_to_ranking_and_reasons():
    channels = (mg.Channel("compliance@kucoin-demo.example", source="entity_record", purpose="compliance"),
                mg.Channel("le@kucoin-demo.example", verified=True, source="global", purpose="le_request",
                           label="LE desk"),
                mg.Channel("legal@kucoin-demo.example", source="catalogue", purpose="legal"),
                mg.Channel("cc-desk@kucoin-demo.example", verified=True, role_default="cc", label="Copy desk"))
    sent = (mg.SentLetter(at=OCT18, to=("old-desk@kucoin-demo.example",), subject="Urgent Preservation Request"),)
    first = mg.guide(_inp(channels=channels, sent=sent))
    assert [s.address for s in first.to] == ["le@kucoin-demo.example", "old-desk@kucoin-demo.example",
                                             "legal@kucoin-demo.example", "compliance@kucoin-demo.example"]
    assert first.to[0].why == "verified LE-request channel (LE desk)" and first.to[0].recommended
    assert first.to[1].why == "address used in the letter you sent on 18 Oct 2026 (not verified in the directory)"
    assert first.to[3].why == "entity compliance address (unverified — confirm on their LE portal first)"
    assert "cc-desk@kucoin-demo.example" not in [s.address for s in first.to]  # a copy address is a Cc
    # a follow-up goes where the first letter went
    follow = mg.guide(_inp(letter_kind="status_request", channels=channels, sent=sent))
    assert follow.to[0].address == "old-desk@kucoin-demo.example" and follow.to[1].address == "le@kucoin-demo.example"
    assert first.why_for("LE@kucoin-demo.example").startswith("To #1: verified")
    # a reply address ranks above an unverified published one
    replied = mg.guide(_inp(channels=channels[2:3], replies=(mg.Reply("analyst@kucoin-demo.example", OCT18),)))
    assert replied.to[0].address == "analyst@kucoin-demo.example" and "replied" in replied.to[0].why


def test_cc_suggestions_never_copy_the_victim():
    victim = "victim@northbridge.example"
    inp = _inp(channels=(mg.Channel(TO, verified=True, purpose="le_request"),
                         mg.Channel("cc-desk@kucoin-demo.example", verified=True, role_default="cc")),
               profile_cc=("investigations@kestrel-ridge.example",), victim_addresses=(victim,),
               draft_cc=(victim, "assistant@northbridge.example"), le_addresses=("officer@police-demo.example",),
               sent=(mg.SentLetter(at=OCT18, to=(TO,), cc=(victim, "officer@police-demo.example")),))
    g = mg.guide(inp)
    cc = [s.address for s in g.cc]
    assert cc[0] == MAILBOX and "replies" in g.cc[0].why  # manual: the case mailbox captures replies
    assert "investigations@kestrel-ridge.example" in cc and "sender profile" in g.cc[1].why
    assert "cc-desk@kucoin-demo.example" in cc
    assert victim not in cc and "assistant@northbridge.example" not in cc  # the victim's own domain too
    assert "officer@police-demo.example" not in cc  # LE officers: LE cover letters only
    codes = {w.code for w in g.warnings}
    assert {"victim_cc", "le_cc"} <= codes
    assert victim in next(w.text for w in g.warnings if w.code == "victim_cc")
    # Aegis sending from the mailbox: it is not a Cc suggestion
    assert MAILBOX not in [s.address for s in mg.guide(_inp(manual=False, channels=inp.channels)).cc]
    # an LE cover letter copies the officer
    le_cover = mg.guide(_inp(letter_kind="le_cover", channels=inp.channels, le_addresses=("officer@police-demo.example",)))
    assert "officer@police-demo.example" in [s.address for s in le_cover.cc]
    # the victim and the mailbox are never a To either
    g2 = mg.guide(_inp(channels=(mg.Channel(victim, verified=True), mg.Channel(MAILBOX, verified=True)),
                       victim_addresses=(victim,)))
    assert not g2.to and {"no_address", "victim_cc"} <= {w.code for w in g2.warnings}


def test_warnings_portal_only_non_custodial_unverified():
    ic3 = mg.guide(_inp(authority_name="FBI Internet Crime Complaint Center (IC3)", letter_kind="le_cover", is_le=True,
                        portal_only=True, portal_url="https://www.ic3.gov/"))
    w = ic3.warnings[0]
    assert w.code == "portal_only" and w.level == "critical" and w.text.startswith("Submit via portal, not e-mail")
    assert "https://www.ic3.gov/" in w.text and "no_address" not in {x.code for x in ic3.warnings}
    uni = mg.guide(_inp(authority_name="Uniswap", info_only=True))
    w = next(x for x in uni.warnings if x.code == "info_only")
    assert w.level == "critical" and w.text.startswith("Cannot freeze — information request only")
    info = mg.guide(_inp(authority_name="Uniswap", info_only=True, letter_kind="info_request"))
    assert next(x for x in info.warnings if x.code == "info_only").level == "info"
    unverified = mg.guide(_inp(channels=(mg.Channel("compliance@kucoin-demo.example", source="entity_record"),)))
    assert any(x.code == "unverified" and "compliance@kucoin-demo.example" in x.text for x in unverified.warnings)
    assert {x.code for x in mg.guide(_inp()).warnings} == {"no_address"}


def test_subject_amount_never_counts_the_same_funds_twice():
    """A stop order's addresses often lie on one path: the subject gives the largest amount one address
    received, not the sum (the demo's Circle order lists the first receiver and the swap wallet, 399k each)."""
    def addr(*amounts, asset="USDC"):
        return {"inbound": [{"asset": asset, "amount": str(a), "amount_usd": str(a)} for a in amounts]}
    order = SimpleNamespace(identifiers={"addresses": [addr(399247.92), addr(399247.92), "0xbare"]})
    assert mg._order_asset_amount(order) == ("USDC", Decimal("399247.92"))
    split = SimpleNamespace(identifiers={"addresses": [addr(100, 50), addr(120), addr(5, asset="ETH")]})
    assert mg._order_asset_amount(split) == ("USDC", Decimal(150))  # per address: 150 and 120
    assert mg._order_asset_amount(SimpleNamespace(identifiers={})) == (None, None)


def test_subject_patterns_end_with_the_tracking_tag():
    tag = "[Aegis DEMO-2026-001 #12]"
    stop = mg.guide(_inp(facts=mg.SubjectFacts(service="KuCoin", asset="ETH", amount=Decimal("0.0581"))))
    assert stop.subject == f"URGENT – Preservation & Risk-Control Request – KuCoin – ETH 0.0581 – Ref DEMO-2026-001 {tag}"
    assert stop.subject_body + " " + stop.tag == stop.subject and stop.subject.endswith(tag)
    big = mg.subject_body("stop_order", "DEMO-2026-001", mg.SubjectFacts(service="Circle", asset="USDC",
                                                                          amount=Decimal("399247.92")))
    assert big == "URGENT – Preservation & Risk-Control Request – Circle – USDC 399,247.92 – Ref DEMO-2026-001"
    follow = mg.subject_body("status_request", "DEMO-2026-001", mg.SubjectFacts(
        original_subject="Follow-up: [Aegis DEMO-2026-001 #7] Urgent Preservation Request – Fraud proceeds",
        original_sent_at=OCT18))
    assert follow == "Follow-up: Urgent Preservation Request – Fraud proceeds – sent 18 Oct 2026 – Ref DEMO-2026-001"
    again = mg.subject_body("status_request", "DEMO-2026-001", mg.SubjectFacts(original_subject=follow + " " + tag,
                                                                                original_sent_at=OCT18))
    assert again == follow  # a follow-up of a follow-up does not stack
    assert mg.subject_body("info_request", "R-1", mg.SubjectFacts(service="Uniswap")) == \
        "Information & Preservation Request – Uniswap – Ref R-1"
    assert mg.subject_body("le_cover", "R-1", mg.SubjectFacts(complaint_ref="IC3-DEMO-1")) == \
        "Fund-Flow Summary & Freeze Opportunities – Your ref IC3-DEMO-1 – Ref R-1"
    assert mg.subject_body("release_request", "R-1", mg.SubjectFacts(service="KuCoin", asset="ETH", amount="1.5")) == \
        "Request for Release of Held Funds – KuCoin – ETH 1.5 – Ref R-1"
    long = mg.subject_body("status_request", "DEMO-2026-001", mg.SubjectFacts(original_subject="x" * 400,
                                                                               original_sent_at=OCT18))
    assert len(long) <= mg.SUBJECT_MAX and long.endswith("– sent 18 Oct 2026 – Ref DEMO-2026-001") and "…" in long
    assert mg.guide(_inp(letter_id=None)).tag == "[Aegis DEMO-2026-001 #<letter no.>]"
    # the tag survives a reply prefix and is what inbound matching reads
    from app.mail.matching import parse_tag

    assert parse_tag("RE: AW: " + stop.subject) == ("DEMO-2026-001", 12)


# --------------------------------------------------------------------------- prepare + the checklist
def test_prepare_builds_an_unsent_draft_and_a_checklist(db, case, run, client, client_for, mail, emitted):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert "Draft — you send" in page and "How to email KuCoin" in page
    assert "URGENT – Preservation &amp; Risk-Control Request – KuCoin" in page  # the standard subject, prefilled
    mm = _prepared(db, _compose(inv, case, corr, cc_other=MAILBOX))  # the case mailbox may be copied
    tag = f"[Aegis {case.reference} #{corr.id}]"
    assert mm.transport == "manual" and mm.status == MailStatus.PREPARED and mm.subject.endswith(tag)
    assert mm.subject.startswith("URGENT - Preservation & Risk-Control Request - KuCoin")
    assert mm.message_id == "" and mm.cc_addrs == [MAILBOX] and MAILBOX not in mm.confirmations["unverified"]
    assert mm.expires_at - mm.prepared_at == compose.MANUAL_TTL
    raw = _raw(mm)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert msg["X-Unsent"] == "1" and msg["Date"] is None and msg["Message-ID"] is None
    assert MAILBOX in str(msg["From"]) and MAILBOX in str(msg["Reply-To"]) and str(msg["To"]) == TO
    assert [p.get_filename() for p in msg.iter_attachments()] == [f"{case.reference}_letter-{corr.id}.docx"]
    note = next(c for c in emitted if c["type"] == "mail_prepared")
    assert "ready to send from Outlook" in note["title"] and "@" not in note["title"] + note["body"]

    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    for who, c in (("investigator", inv), ("admin", client)):
        page = c.get(path).text
        assert "Send it yourself" in page and 'id="mail-send-form"' not in page and "Send e-mail" not in page
        assert "keep the subject unchanged so replies are matched" in page
        assert 'data-mail-copy="to"' in page and 'data-mail-copy="body"' in page
        data = json.loads(re.search(r'<script type="application/json" id="mail-manual-data">(.*?)</script>', page,
                                    re.DOTALL).group(1))
        assert data["to"] == TO and data["cc"] == MAILBOX and data["subject"] == mm.subject and data["tag"] == tag
        assert data["text"].strip() and "<html" in data["html"].lower()
        assert re.findall(r"<script(?![^>]*type=\"application/json\")(?![^>]*src=)[^>]*>", page) == []  # CSP
        assert ("draft.eml" in page) == (who == "admin") and ("attachments.zip" in page) == (who == "admin")
        assert ('id="mail-record-form"' in page) == (who == "admin")
    assert not mail.network


def test_prepare_in_manual_mode_without_a_mailbox(db, case, run, client, mail):
    mail.settings.aegis_mail_from = ""
    corr = _draft(db, case, run, template="info_request")
    page = client.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert "No case mailbox is configured" in page
    mm = _prepared(db, _compose(client, case, corr))
    msg = BytesParser(policy=policy.default).parsebytes(_raw(mm))
    assert msg["From"] is None and msg["Reply-To"] is None and msg["X-Unsent"] == "1"
    assert mm.mailbox == "" and mm.subject.startswith("Information & Preservation Request - KuCoin")


def test_prepare_refuses_the_mailbox_as_to(db, case, run, client, mail):
    corr = _draft(db, case, run)
    r = _compose(client, case, corr, to_other=MAILBOX)
    assert r.status_code == 400 and "copy it as Cc instead" in r.text


def test_draft_eml_zip_and_single_attachments(db, case, run, client, client_for, mail):
    corr = _draft(db, case, run)
    item = next(e for e in case.evidence_items if e.title.startswith("Chat excerpt"))
    mm = _prepared(db, _compose(client, case, corr, attach=["letter", f"evidence:{item.id}"]))
    base = f"/cases/{case.id}/mail/messages/{mm.id}"
    inv = client_for("investigator", case=case)
    for suffix in ("/draft.eml", "/attachments.zip", "/attachments/1"):
        assert inv.get(base + suffix).status_code == 403  # downloads: case admins (audited)
    r = client.get(base + "/draft.eml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("message/rfc822")
    assert "attachment;" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
    assert r.content == _raw(mm)
    head = r.content.split(b"\r\n\r\n", 1)[0]
    assert b"\r\nX-Unsent: 1" in b"\r\n" + head and b"Message-ID" not in head and b"\r\nDate:" not in b"\r\n" + head
    z = client.get(base + "/attachments.zip")
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        names = zf.namelist()
        assert names == [m["filename"] for m in mm.attachments]
        for m in mm.attachments:
            assert hashlib.sha256(zf.read(m["filename"])).hexdigest() == m["sha256"]
    one = client.get(base + "/attachments/2")
    assert one.status_code == 200 and hashlib.sha256(one.content).hexdigest() == mm.attachments[1]["sha256"]
    assert mm.attachments[1]["filename"] in one.headers["content-disposition"]
    assert client.get(base + "/attachments/3").status_code == 404
    assert client.get(base + "/attachments/0").status_code == 404
    modes = [a.detail.get("mode") for a in db.scalars(select(AuditEvent).where(
        AuditEvent.action == "DOWNLOAD", AuditEvent.object_id == str(mm.id)))]
    assert {"draft_eml", "attachments_zip", "attachment"} <= set(modes)
    # a message Aegis would send itself (not a draft) is not offered as an Outlook draft
    mail.settings.aegis_mail_transport = "file"
    sent_kind = _prepared(db, _compose(client, case, _draft(db, case, run, template="info_request")))
    assert client.get(f"/cases/{case.id}/mail/messages/{sent_kind.id}/draft.eml").status_code == 409


def test_mailto_only_for_short_letters():
    short = compose.mailto_url(["a@x.example"], ["b@x.example"], "Hello – Ref R [Aegis R-1 #1]", "Short body.")
    assert short.startswith("mailto:a@x.example?cc=b@x.example&subject=Hello%20%E2%80%93") and "body=Short" in short
    assert compose.mailto_url(["a@x.example"], [], "s", "x" * 3000) is None


# --------------------------------------------------------------------------- record as sent
def test_record_as_sent_gating_and_state(db, case, run, client, client_for, mail, emitted):
    corr = _draft(db, case, run)
    order = corr.stop_order
    inv = client_for("investigator", case=case)
    mm = _prepared(db, _compose(inv, case, corr))
    assert _record(inv, case, mm).status_code == 403
    ro = client_for("read_only", case=case)
    assert ro.get(f"/cases/{case.id}/mail/messages/{mm.id}").status_code == 403
    assert _record(client, case, mm, confirm_external="").status_code == 400
    future = (datetime.now(tz=UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
    r = _record(client, case, mm, sent_at=future)
    assert r.status_code == 400 and "future" in r.text
    r = _record(client, case, mm, sent_at="2026-01-01T00:00")
    assert r.status_code == 400 and "before this e-mail was prepared" in r.text
    no_csrf = client.post(f"/cases/{case.id}/mail/messages/{mm.id}/record-sent", data={"confirm_external": "1"})
    assert no_csrf.status_code in (400, 403)
    db.expire_all()
    assert db.get(MailMessage, mm.id).status == MailStatus.PREPARED

    sent_at = (datetime.now(tz=UTC) - timedelta(minutes=3)).replace(second=0, microsecond=0)
    sent = reply_eml(subject=mm.subject, from_=MAILBOX, to=TO)
    r = _record(client, case, mm, sent_at=sent_at.strftime("%Y-%m-%dT%H:%M"), cc="copy@kucoin-demo.example",
                files={"sent_message": ("sent.eml", sent, "message/rfc822")})
    assert r.status_code == 303 and r.headers["location"].endswith("?r=sent_external"), r.text[:500]
    db.expire_all()
    mm, corr, order = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id), db.get(type(order), order.id)
    assert mm.status == MailStatus.SENT_EXTERNAL and mm.sent_by == client.user.id and mm.sent_at == sent_at
    assert mm.cc_addrs == ["copy@kucoin-demo.example"] and mm.meta["sent_external"]["recipients_changed"]
    assert corr.status == CorrespondenceStatus.SENT and corr.occurred_at == sent_at and corr.recipients == [TO]
    assert corr.due_at == sent_at + timedelta(days=5) and corr.meta["sent_via"] == "email_external"
    assert order.status == StopOrderStatus.SENT and order.sent_via == "email (sent outside Aegis)"
    assert order.response_due_at == sent_at + timedelta(days=5)
    item = db.get(EvidenceItem, mm.meta["sent_external"]["evidence_id"])
    assert item.sha256 == hashlib.sha256(sent).hexdigest() and item.classification.value == "R3"
    assert item.folder.value == "stop_orders_correspondence" and "sent-email" in item.tags
    assert corr.evidence_item_id == item.id and str(mail.vault) not in json.dumps(item.meta)
    assert mm.meta["sent_external"]["subject_tag_missing"] is False
    types = [c["type"] for c in emitted]
    assert "correspondence_out" in types and "stop_order_status" in types
    a = db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT",
                                            AuditEvent.object_id == str(corr.id))).all()[-1]
    assert a.detail["via"] == "email_external" and a.detail["sent_evidence_id"] == item.id
    assert "@" not in json.dumps(a.detail) and corr.subject not in json.dumps(a.detail)
    page = client.get(r.headers["location"]).text
    assert "Sent outside Aegis" in page and "Import the reply" in page and 'id="mail-record-form"' not in page

    # one e-mail per letter: recorded once, never prepared or sent again
    again = _record(client, case, mm)
    assert again.status_code == 303 and again.headers["location"].endswith("?r=already")
    with ungated():  # the shared demo case holds earlier tests' open drafts
        corr2 = desk.generate_letter(db, case, _auth(db, case, "KuCoin", run), "status_request", actor=None, run=run)
    assert corr2.status == CorrespondenceStatus.DRAFT  # a follow-up letter is the way to write again
    sibling = MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=mm.letter_key,
                          direction=MailDirection.OUT, status=MailStatus.CANCELLED, transport="manual", mailbox=MAILBOX,
                          message_id="", to_addrs=[TO], cc_addrs=[], attachments=[], confirmations={}, match={},
                          meta={"draft_hash": compose.draft_hash(corr)})
    db.add(sibling)
    db.commit()
    busy = compose.letter_in_flight(db, corr, exclude_id=sibling.id)
    assert busy is not None and busy.id == mm.id and "sent outside Aegis" in compose.letter_busy_text(corr, busy)
    assert not mail.network


def test_record_without_upload_and_refusals(db, case, run, client, mail):
    corr = _draft(db, case, run, template="info_request")
    mm = _prepared(db, _compose(client, case, corr))
    r = _record(client, case, mm, files={"sent_message": ("sent.msg", b"not an outlook file", "application/octet-stream")})
    assert r.status_code == 400 and "not an Outlook message" in r.text
    r = _record(client, case, mm, files={"sent_message": ("sent.pdf", b"%PDF-1.4", "application/pdf")})
    assert r.status_code == 400 and ".eml or .msg" in r.text
    r = _record(client, case, mm, to="")
    assert r.status_code == 400 and "To address" in r.text
    # the draft changed after the checklist: refused (what went out is not the current letter)
    desk.update_draft(db, corr, subject=corr.subject, body=corr.body_markdown + "\nP.S.", recipients=[], cc=[])
    r = _record(client, case, mm)
    assert r.status_code == 409 and "draft changed" in r.text
    corr2 = _draft(db, case, run, template="info_request")
    mm2 = _prepared(db, _compose(client, case, corr2))
    msg = make_msg(subject=mm2.subject, sender=MAILBOX)
    r = _record(client, case, mm2, files={"sent_message": ("Sent.msg", msg, "application/vnd.ms-outlook")})
    assert r.status_code == 303
    db.expire_all()
    mm2 = db.get(MailMessage, mm2.id)
    item = db.get(EvidenceItem, mm2.meta["sent_external"]["evidence_id"])
    assert item.sha256 == hashlib.sha256(msg).hexdigest() and item.source_type == "msg"
    # the stored .msg is mail correspondence: never attachable to another authority
    assert compose.is_correspondence_item(item, db)


def test_record_race_is_refused_by_the_letter_index(db, case, run, client, mail, monkeypatch):
    """Two records of one letter at once: the app check is bypassed (as in a race), and the partial unique
    index (0009: incl. sent_external) refuses the second one; nothing is recorded."""
    corr = _draft(db, case, run, template="info_request")
    mm = _prepared(db, _compose(client, case, corr))
    other = MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=mm.letter_key,
                        direction=MailDirection.OUT, status=MailStatus.SENT_EXTERNAL, transport="manual",
                        mailbox=MAILBOX, message_id="", to_addrs=[TO], cc_addrs=[], attachments=[], confirmations={},
                        match={}, meta={})
    db.add(other)
    db.commit()
    monkeypatch.setattr(compose, "letter_in_flight", lambda *a, **kw: None)
    r = _record(client, case, mm)
    assert r.status_code == 409 and "nothing was recorded" in r.text
    db.expire_all()
    assert db.get(MailMessage, mm.id).status == MailStatus.PREPARED
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.DRAFT


# --------------------------------------------------------------------------- import a reply
def _sent_letter(db, case, run, client, mail):
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client, case, corr))
    assert _record(client, case, mm).status_code == 303
    db.expire_all()
    return db.get(Correspondence, corr.id), db.get(MailMessage, mm.id)


def _import(c, case, data: bytes, name="reply.eml", authority_key=""):
    path = f"/cases/{case.id}/mail/import"
    return c.post(path, data={"csrf_token": csrf_token(c, f"/cases/{case.id}"), "authority_key": authority_key},
                  files={"reply": (name, data, "message/rfc822")}, follow_redirects=False)


def test_import_reply_waits_for_review_with_the_letter_preselected(db, case, run, client, client_for, mail):
    corr, mm = _sent_letter(db, case, run, client, mail)
    inv = client_for("investigator", case=case)
    ar = {"Authentication-Results": "spf=pass smtp.mailfrom=kucoin-demo.example; dkim=pass header.d=kucoin-demo.example;"
                                    "dmarc=pass action=none header.from=kucoin-demo.example;compauth=pass reason=100"}
    raw = reply_eml(subject=f"RE: {mm.subject}", headers=ar, attachments=[("hold.pdf", b"%PDF-1.4 synthetic")])
    r = _import(inv, case, raw)
    assert r.status_code == 303 and "imported=" in r.headers["location"]
    page = inv.get(r.headers["location"]).text
    assert "waits on <b>Mail to review</b>" in page and f"letter #{corr.id} pre-selected" in page
    db.expire_all()
    row = db.scalars(select(MailMessage).where(MailMessage.direction == MailDirection.IN,
                                               MailMessage.case_id == case.id)).all()[-1]
    # an upload is never trusted, even with an Authentication-Results pass (file-transport semantics)
    assert row.status == MailStatus.NEEDS_REVIEW and row.match["confident"] is False
    assert row.match["correspondence_id"] == corr.id and row.match["method"] == "tag" and row.transport == "upload"
    assert row.mime_sha256 == hashlib.sha256(raw).hexdigest() and row.correspondence_id is None
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT  # nothing changed yet
    a = db.scalars(select(AuditEvent).where(AuditEvent.action == "MAIL_IMPORTED")).all()[-1]
    assert a.detail["letter_id"] == corr.id and "@" not in json.dumps(a.detail)
    # the same bytes again: imported once
    again = _import(inv, case, raw)
    assert "dup=1" in again.headers["location"] and "imported before" in inv.get(again.headers["location"]).text
    # the case admin accepts on Mail to review -> the timeline
    review = client.get(f"/cases/{case.id}/mail/review").text
    assert f'<option value="{corr.id}" selected' in review
    tok = csrf_token(client, f"/cases/{case.id}/mail/review")
    acc = client.post(f"/cases/{case.id}/mail/review/{row.id}/accept",
                      data={"csrf_token": tok, "authority_key": f"entity-{corr.entity_id}", "in_reply_to": str(corr.id)},
                      follow_redirects=False)
    assert acc.status_code == 303
    db.expire_all()
    row = db.get(MailMessage, row.id)
    reply = db.get(Correspondence, row.correspondence_id)
    assert row.status == MailStatus.ASSIGNED and reply.direction.value == "in" and reply.in_reply_to_id == corr.id
    assert reply.meta["source"] == "mailbox" and reply.meta["untrusted_external"] is True
    timeline = client.get(f"/cases/{case.id}/authorities/entity-{corr.entity_id}").text
    assert f'id="c{reply.id}"' in timeline
    assert not mail.network


def test_import_rules(db, case, run, client, client_for, mail):
    corr, mm = _sent_letter(db, case, run, client, mail)
    ro = client_for("read_only", case=case)
    assert _import(ro, case, reply_eml(subject="x")).status_code == 403
    assert "the case mailbox itself" in _import(client, case, reply_eml(subject=mm.subject, from_=MAILBOX)).text
    assert ".eml or .msg" in _import(client, case, b"%PDF-1.4", name="reply.pdf").text
    assert "no e-mail headers" in _import(client, case, b"just text\n", name="x.eml").text
    # a tag naming another case's letter is dropped (an upload never touches another case)
    other = _other_case(db)
    foreign = reply_eml(subject=f"RE: [Aegis {other.reference} #{corr.id}] hold")
    r = _import(client, case, foreign)
    db.expire_all()
    row = db.get(MailMessage, int(re.search(r"imported=(\d+)", r.headers["location"]).group(1)))
    assert row.case_id == case.id and row.match["correspondence_id"] is None and row.match["method"] == "upload"
    # no tag, uploaded on the authority's page: that authority's latest letter is pre-selected
    key = f"entity-{corr.entity_id}"
    r = _import(client, case, reply_eml(subject="Your request (our ticket 123)"), authority_key=key)
    db.expire_all()
    row = db.get(MailMessage, int(re.search(r"imported=(\d+)", r.headers["location"]).group(1)))
    authority = desk.get_authority(db, case, key)
    latest = max((c for c in authority.correspondence if c.direction.value == "out" and c.status.value == "sent"),
                 key=lambda c: (c.occurred_at.replace(tzinfo=None), c.id))
    assert row.match["correspondence_id"] == latest.id and "latest letter" in row.match["reason"]
    assert client.get(f"/cases/{case.id}/authorities/{key}").status_code == 200


def test_import_threads_on_the_message_id_of_the_recorded_sent_copy(db, case, run, client, mail):
    """A reply whose subject lost the tag still finds its letter: In-Reply-To names the Message-ID Outlook gave
    the sent message (read from the .eml uploaded with Record as sent). Still only pre-selected, for review."""
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client, case, corr))
    sent = reply_eml(subject=mm.subject, from_=MAILBOX, to=TO)
    sent_id = BytesParser(policy=policy.default).parsebytes(sent)["Message-ID"]
    assert _record(client, case, mm, files={"sent_message": ("sent.eml", sent, "message/rfc822")}).status_code == 303
    db.expire_all()
    assert db.get(MailMessage, mm.id).internet_message_id == sent_id
    r = _import(client, case, reply_eml(subject="Your request", headers={"In-Reply-To": sent_id}))
    db.expire_all()
    row = db.get(MailMessage, int(re.search(r"imported=(\d+)", r.headers["location"]).group(1)))
    assert row.status == MailStatus.NEEDS_REVIEW and row.match["confident"] is False
    assert row.match["correspondence_id"] == corr.id and row.match["method"] == "header"
    assert not mail.network


def test_import_an_outlook_msg(db, case, run, client, client_for, mail):
    corr, mm = _sent_letter(db, case, run, client, mail)
    pdf = b"%PDF-1.4 synthetic hold confirmation\n" + b"0" * 6000  # > 4096: regular sectors, not the mini stream
    msg = make_msg(subject=f"RE: {mm.subject}", attachment=pdf, body="We froze 0.0581 ETH.")
    parsed = mail_import.read_msg(msg)
    assert parsed.subject == f"RE: {mm.subject}" and parsed.sender == "le-requests@kucoin-demo.example"
    assert parsed.to == [("Investigations", MAILBOX)] and parsed.attachments[0][2] == pdf
    assert parsed.sent_at is not None and parsed.sent_at.year > 2020
    eml = BytesParser(policy=policy.default).parsebytes(mail_import.msg_to_eml(msg))
    assert eml["Subject"] == f"RE: {mm.subject}" and "le-requests@kucoin-demo.example" in str(eml["From"])
    assert eml.get_body(preferencelist=("plain",)).get_content().strip() == "We froze 0.0581 ETH."
    inv = client_for("investigator", case=case)
    r = _import(inv, case, msg, name="RE hold.msg")
    assert r.status_code == 303, r.text[:400]
    db.expire_all()
    row = db.get(MailMessage, int(re.search(r"imported=(\d+)", r.headers["location"]).group(1)))
    assert row.status == MailStatus.NEEDS_REVIEW and row.match["correspondence_id"] == corr.id
    assert row.meta["imported_from"] == "msg" and row.attachments[0]["sha256"] == hashlib.sha256(pdf).hexdigest()
    original = db.get(EvidenceItem, row.meta["original_evidence_id"])
    assert original.sha256 == hashlib.sha256(msg).hexdigest() and "received-email" in original.tags
    assert compose.is_received_email(original, db)  # never attachable
    # headers kept by Outlook (a received message) win over the rebuilt ones
    with_headers = make_msg(subject="ignored", headers=f"From: Desk <desk@kucoin-demo.example>\r\nTo: {MAILBOX}\r\n"
                                                         f"Subject: RE: {mm.subject}\r\nMessage-ID: <x1@kucoin-demo.example>\r\n")
    eml = BytesParser(policy=policy.default).parsebytes(mail_import.msg_to_eml(with_headers))
    assert eml["Message-ID"] == "<x1@kucoin-demo.example>" and "desk@kucoin-demo.example" in str(eml["From"])
    assert eml["Subject"] == f"RE: {mm.subject}"
    for bad in (b"", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100, msg[:600]):
        with pytest.raises(mail_import.MailImportError):
            mail_import.read_msg(bad)
    assert not mail.network


def test_authority_page_shows_how_to_email(db, case, run, client, client_for, mail):
    key = _auth(db, case, "KuCoin", run).key
    page = client.get(f"/cases/{case.id}/authorities/{key}").text
    assert "How to email KuCoin" in page and "Import a reply from KuCoin" in page
    assert "keep the subject unchanged so replies are matched" in page and "#&lt;letter no.&gt;]" in page
    ro = client_for("read_only", case=case).get(f"/cases/{case.id}/authorities/{key}").text
    assert "How to email" not in ro
    imp = client_for("investigator", case=case).get(f"/cases/{case.id}/mail/import?authority={key}").text
    assert "Import a reply" in imp and f'value="{key}" selected' in imp


def test_authorities_tab_in_manual_mode(db, case, run, client, client_for, mail):
    """The tab says the prepared e-mail waits to be sent from Outlook, the timeline tag too, and offers Import reply
    (investigators and up) instead of a disabled "Check mailbox now". (A letter, not a stop order: a stop order past
    the gate to KuCoin, already asked, is a duplicate the board says to discard, its e-mail never a call to send.)"""
    corr = _draft(db, case, run, template="info_request")
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr))
    inv = client_for("investigator", case=case)
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    assert re.search(r"E-mail awaiting send from Outlook \(\d+\)", tab) and "records it as sent" in tab
    assert f"/mail/messages/{mm.id}" in tab
    assert f'href="/cases/{case.id}/mail/import"' in tab and "E-mail awaiting Send" not in tab
    admin_tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert "Check mailbox now" not in admin_tab and "Import reply" in admin_tab
    ro = client_for("read_only", case=case).get(f"/cases/{case.id}?tab=authorities").text
    assert f'href="/cases/{case.id}/mail/import"' not in ro
    page = inv.get(f"/cases/{case.id}/authorities/entity-{corr.entity_id}").text
    assert "e-mail awaiting send from Outlook" in page and f"/mail/messages/{mm.id}" in page
    assert not mail.network


# --------------------------------------------------------------------------- review fixes: .msg reader limits, dedupe
def _shared_chain_msg(k: int, data_sectors: int, *, overlap: bool) -> bytes:
    """A crafted .msg: k recipient storages whose PR_SMTP_ADDRESS streams all point into one long sector chain
    (the same start sector, or each one sector further on: `overlap`). Read naively, that is k x the file."""
    SS, END, FREE, FATS, NONE = 512, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
    n_entries = 1 + 2 * k
    dir_sectors = -(-n_entries * 128 // SS)
    n_fat = 1
    while (data_sectors + dir_sectors + n_fat) > n_fat * (SS // 4):
        n_fat += 1
    fat = [FATS] * n_fat
    d0 = n_fat
    fat += [d0 + i + 1 if i < data_sectors - 1 else END for i in range(data_sectors)]
    dir0 = n_fat + data_sectors
    fat += [dir0 + i + 1 if i < dir_sectors - 1 else END for i in range(dir_sectors)]
    fat += [FREE] * (n_fat * SS // 4 - len(fat))

    def entry(name, kind, right, child, start, size):
        raw = (name + "\0").encode("utf-16-le")
        return (raw.ljust(64, b"\0") + struct.pack("<HBB", len(raw), kind, 1) + struct.pack("<III", NONE, right, child)
                + b"\0" * 36 + struct.pack("<IQ", start, size))

    ents = [entry("Root Entry", 5, NONE, 1, END, 0)]
    for i in range(k):  # storage 1 + 2i, its stream 2 + 2i
        sid = 1 + 2 * i
        ents.append(entry(f"__recip_version1.0_#{i:08X}", 1, sid + 2 if i < k - 1 else NONE, sid + 1, 0, 0))
        start = d0 + (min(i, data_sectors - 9) if overlap else 0)
        ents.append(entry("__substg1.0_39FE001F", 2, NONE, NONE, start, (data_sectors - (start - d0)) * SS))
    dirb = b"".join(ents).ljust(dir_sectors * SS, b"\0")
    header = bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIII", 0, n_fat, dir0, 0) + struct.pack("<IIIII", 4096, END, 0, END, 0)
    header += struct.pack("<109I", *(list(range(n_fat)) + [FREE] * (109 - n_fat)))
    return header + struct.pack(f"<{len(fat)}I", *fat) + _u("a@b.example").ljust(data_sectors * SS, b"A") + dirb


def test_msg_reader_cannot_be_made_to_copy_one_chain_many_times():
    import tracemalloc

    for overlap in (False, True):
        blob = _shared_chain_msg(400, 400, overlap=overlap)  # ~0.3 MB file; a naive read copies ~80 MB
        tracemalloc.start()
        try:
            try:
                parsed = mail_import.read_msg(blob)
            except mail_import.MsgError as exc:
                assert "larger than the file" in str(exc)
            else:
                assert len(parsed.to) <= 1  # entries sharing a start sector read as empty after the first
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert peak < 8 * len(blob), (overlap, peak, len(blob))
    # a stream declared larger than the file is not read
    small = _shared_chain_msg(1, 20, overlap=False)
    cf = mail_import.CompoundFile(small)
    assert cf.stream(2).startswith(_u("a@b.example"))
    cf = mail_import.CompoundFile(small)
    cf.entries[2].size = len(small) + 1
    assert cf.stream(2) == b""


def test_the_same_msg_imports_once(db, case, run, client, mail):
    _corr, mm = _sent_letter(db, case, run, client, mail)
    msg = make_msg(subject=f"RE: {mm.subject}", attachment=b"%PDF-1.4 hold " + b"1" * 5000)
    assert mail_import.msg_to_eml(msg) == mail_import.msg_to_eml(msg)  # fixed MIME boundaries
    first = _import(client, case, msg, name="reply.msg")
    again = _import(client, case, msg, name="reply again.msg")
    assert "imported=" in first.headers["location"] and "dup=1" in again.headers["location"]
    db.expire_all()
    rows = db.scalars(select(MailMessage).where(MailMessage.case_id == case.id, MailMessage.direction == MailDirection.IN,
                                                MailMessage.transport == "upload")).all()
    assert len([r for r in rows if (r.meta or {}).get("original_sha256") == hashlib.sha256(msg).hexdigest()]) == 1


def test_deeply_nested_mime_is_a_clean_400(db, case, run, client, mail):
    depth = 2000
    head = b"From: desk@kucoin-demo.example\r\nTo: " + MAILBOX.encode() + b"\r\nSubject: nested\r\nMIME-Version: 1.0\r\n"
    parts = [b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n--b%d\r\n' % (i, i) for i in range(depth)]
    tail = b"Content-Type: text/plain\r\n\r\nx\r\n" + b"".join(b"--b%d--\r\n" % i for i in reversed(range(depth)))
    r = _import(client, case, head + b"".join(parts) + tail, name="nested.eml")
    assert r.status_code == 400 and "could not be read" in r.text


# --------------------------------------------------------------------------- review fixes: guidance
def test_guidance_for_the_case_s_own_pi_firm(db, case, run, client, mail):
    pi = desk.get_authority(db, case, "pi-0")
    assert pi is not None and pi.is_adviser
    assert mg.next_kind(pi) == "info_request"
    allowed = {o["key"] for o in desk.template_options(pi, run) if o.get("available")}
    access = SimpleNamespace(case=case, can=lambda action: True, user=None)
    g = mg.for_authority(db, access, pi, card=SimpleNamespace(emails=list, info_only=False, portal_only=False,
                                                              portal_url=None))
    assert g.letter_kind in allowed and g.letter_kind != "stop_order"
    assert g.subject_body == f"Case Update – Ref {case.reference}" and "Preservation" not in g.subject
    codes = {w.code for w in g.warnings}
    assert "adviser" in codes and not any("law-enforcement request channel" in w.text for w in g.warnings)
    page = client.get(f"/cases/{case.id}/authorities/pi-0").text
    assert "Adviser on this case" in page and "stop order (preservation" not in page
    assert "find their law-enforcement request channel" not in page


def test_portal_only_has_no_cc_and_le_cc_stays_with_the_agency():
    officer, other = "officer@police-demo.example", "cybercrime@procura-esempio.example"
    ic3 = mg.guide(_inp(authority_name="FBI Internet Crime Complaint Center (IC3)", letter_kind="le_cover", is_le=True,
                        portal_only=True, portal_url="https://www.ic3.gov/", le_addresses=(officer, other),
                        agency_le_addresses=()))
    assert ic3.cc == [] and ic3.warnings[0].code == "portal_only"
    carabinieri = mg.guide(_inp(authority_name="Carabinieri", letter_kind="le_cover", is_le=True,
                                le_addresses=(officer, other), agency_le_addresses=(officer,)))
    cc = [s.address for s in carabinieri.cc]
    assert officer in cc and other not in cc  # another agency's officer is never suggested


# --------------------------------------------------------------------------- owner review: guidance wording
def test_portal_only_instruction_never_says_email():
    g = mg.guide(_inp(portal_only=True, portal_url="https://portal.example"))
    assert "Do not e-mail" in g.instruction and "portal" in g.instruction and "Outlook" not in g.instruction
    plain = mg.guide(_inp())
    assert "Outlook" in plain.instruction and "keep the subject unchanged" in plain.instruction


def test_follow_up_subject_quotes_the_email_that_went_out(db, case, run, client, mail):
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client, case, corr))
    assert _record(client, case, mm).status_code == 303
    db.expire_all()
    sent_subject = db.get(MailMessage, mm.id).subject
    kucoin = _auth(db, case, "KuCoin", run)
    ref = next(r["value"] for r in desk.sent_references(kucoin)
               if r.get("order") is not None and r["order"].id == corr.stop_order_id)  # follow up *this* letter
    with ungated():  # the shared demo case holds earlier tests' open drafts
        follow = desk.generate_letter(db, case, kucoin, "status_request", actor=None, run=run, ref=ref)
    access = SimpleNamespace(case=case, can=lambda action: True, user=None)
    card = SimpleNamespace(emails=list, info_only=False, portal_only=False, portal_url=None)
    g = mg.for_authority(db, access, _auth(db, case, "KuCoin", run), follow, card=card)
    assert g.letter_kind == "status_request"
    quoted = mg._clean_subject(sent_subject)
    assert quoted and f"Follow-up: {quoted[:40]}" in g.subject_body  # the e-mail's subject, not the letter heading


@pytest.fixture(autouse=True)
def _retire_left_over_checklists(db):
    """The test DB is shared by the whole run: an Outlook checklist a test leaves open would (rightly) stop later
    tests from regenerating that entity's stop order (services.generate_stop_orders), so each is cancelled after."""
    yield
    from app.db.models import MailMessage as _MM
    from app.db.models import MailStatus as _MS

    db.rollback()
    for m in db.query(_MM).filter(_MM.transport == "manual", _MM.status.in_((_MS.PREPARED, _MS.EXPIRED))).all():
        m.status = _MS.CANCELLED
    db.commit()


FOOTER = "Sent from Aegis, the demo desk's *recovery* tool"


def test_footer_line_is_added_once_and_escaped():
    body = "Dear team,\n\nPlease freeze.\n\nYours faithfully,\n\nInvestigations Desk\n"
    md = compose.email_markdown(body, FOOTER)
    assert md.startswith(body.rstrip()) and md.rstrip().endswith("*") and md.count("Sent from Aegis") == 1
    assert compose.markdown_to_text(md).rstrip().endswith(FOOTER)  # plain text: the line as written
    html = compose.markdown_to_html(md)
    assert "<em>Sent from Aegis, the demo desk's *recovery* tool</em>" in html.replace("&#x27;", "'")
    assert compose.email_markdown(md, FOOTER) == md  # a letter that already says it is left alone
    assert compose.email_markdown(body, "") == compose.outbound_markdown(body)  # no footer configured: unchanged


def test_footer_reaches_the_email_but_not_the_letter(db, case, run, client, client_for, mail, monkeypatch):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    plain = _prepared(db, _compose(inv, case, corr))  # prepared before the footer was configured
    assert "Sent from Aegis" not in compose.preview(db, plain, corr).html_markdown
    plain_text = BytesParser(policy=policy.default).parsebytes(_raw(plain)).get_body(("plain",)).get_content()
    assert "Sent from Aegis" not in plain_text

    monkeypatch.setattr(mail.settings, "footer", FOOTER, raising=False)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert "Sent from Aegis" in page  # the editor's preview shows what goes out
    db.expire_all()
    mm = _prepared(db, _compose(inv, case, db.get(Correspondence, corr.id)))
    msg = BytesParser(policy=policy.default).parsebytes(_raw(mm))
    text, html = msg.get_body(("plain",)).get_content(), msg.get_body(("html",)).get_content()
    assert text.rstrip().endswith(FOOTER) and text.count("Sent from Aegis") == 1
    assert "<em>Sent from Aegis" in html
    assert "Sent from Aegis" in compose.preview(db, mm, corr).html_markdown
    db.expire_all()
    assert "Sent from Aegis" not in db.get(Correspondence, corr.id).body_markdown  # the letter itself: unchanged


def test_mail_settings_footer_is_one_line(monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FOOTER", "  Sent from Aegis,\n  the case desk  ")
    assert MailSettings().footer == "Sent from Aegis, the case desk"
    monkeypatch.delenv("AEGIS_MAIL_FOOTER")
    assert MailSettings(_env_file=None).footer == ""
