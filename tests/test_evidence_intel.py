"""Evidence intel (app/evidence_intel): text extraction (PDF, .docx, .eml / .msg, text formats, images), the rules'
type / folder / requirement keys with their cues (EN / IT / DE / FR), the findings and one-click proposals, the
upload flow (suggest, a person confirms), the checklist and the instrument gate, the per-case "AI reads evidence"
consent, the re-read backfill and the caps. Every document is synthetic, generated here."""

from __future__ import annotations

import io
import json
import zipfile
from email.message import EmailMessage

import docx
import httpx
import pytest
from conftest import csrf_token
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
from sqlalchemy import select
from test_block_ai import LABEL, MODEL, Recorder, _provider
from test_block_status import fresh_case

from app.ai import providers
from app.db.models import AIMode, AuditEvent, Correspondence, EvidenceFolder, EvidenceItem
from app.domain import evidence as ev
from app.domain import evidence_requirements as er
from app.evidence_intel import ai as eai
from app.evidence_intel import findings, rules, text
from app.evidence_intel import service as intel
from app.freeze import abi

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
TRON = abi.b58check_encode(b"\x41" + bytes(range(1, 21)))
EVM = "0x" + "ab12" * 10
TX = "0x" + "c3" * 32


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


SOL = _b58(bytes(range(7, 39)))


def make_pdf(pages: list[list[str]]) -> bytes:
    w = PdfWriter()
    for lines in pages:
        page = w.add_blank_page(612, 792)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject(
            {NameObject("/Font"): DictionaryObject({NameObject("/F1"): w._add_object(font)})})
        esc = [ln.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for ln in lines]
        s = DecodedStreamObject()
        s.set_data(("BT /F1 10 Tf 50 740 Td 13 TL " + " ".join(f"({ln}) Tj T*" for ln in esc) + " ET").encode("latin-1"))
        page[NameObject("/Contents")] = w._add_object(s)
    b = io.BytesIO()
    w.write(b)
    return b.getvalue()


def make_docx(paragraphs: list[str], table: list[list[str]] | None = None) -> bytes:
    d = docx.Document()
    for p in paragraphs:
        d.add_paragraph(p)
    if table:
        t = d.add_table(rows=len(table), cols=len(table[0]))
        for i, row in enumerate(table):
            for j, v in enumerate(row):
                t.cell(i, j).text = v
    b = io.BytesIO()
    d.save(b)
    return b.getvalue()


def make_eml(body: str, *, subject: str, sender: str = "compliance@exchange.example",
             attachment: tuple[str, bytes] | None = None) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"] = sender, "investigator@pi.example", subject, "Mon, 05 Oct 2026 10:00:00 +0000"
    m.set_content(body)
    if attachment:
        m.add_attachment(attachment[1], maintype="application", subtype="pdf", filename=attachment[0])
    return m.as_bytes()


DENUNCIA = ["Comando Carabinieri di Demo Valle", "Verbale di ricezione di denuncia-querela",
            "Prot. n. 4417/2026 del 3 ottobre 2026", "La persona offesa dichiara di aver inviato 12.500,00 USDT",
            f"all'indirizzo {TRON} su rete TRON, transazione {TX}."]


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
    """The fresh case's admin member (the conftest `client` is the shared demo case's)."""
    return client_for("admin", case=fcase)


def _tok(c, case) -> str:
    return csrf_token(c, f"/cases/{case.id}?tab=evidence")


def _upload(c, case, name: str, data: bytes, mime: str, folder: str = "other"):
    return c.post(f"/cases/{case.id}/evidence/upload", data={"csrf_token": _tok(c, case), "folder": folder},
                  files={"file": (name, data, mime)}, follow_redirects=False)


def _new_item(db, case, data: bytes) -> EvidenceItem:
    import hashlib

    db.expire_all()
    return db.scalar(select(EvidenceItem).where(EvidenceItem.case_id == case.id,
                                                EvidenceItem.sha256 == hashlib.sha256(data).hexdigest()))


# --------------------------------------------------------------------------- extraction
def test_pdf_text_layer_is_read_and_capped(monkeypatch):
    t = text.extract_text(make_pdf([DENUNCIA]), name="scan.pdf")
    assert t.kind == "pdf" and t.status == "ok" and t.pages == 1 and "denuncia-querela" in t.text
    monkeypatch.setattr(text, "MAX_PDF_PAGES", 2)
    t = text.extract_text(make_pdf([["page one"], ["page two"], ["page three secret"]]), name="x.pdf")
    assert t.pages == 3 and t.truncated and "page three" not in t.text and "first 2 of 3 pages" in t.note
    blank = text.extract_text(make_pdf([[]]), name="scan.pdf")
    assert blank.status == "no_text" and "text layer" in blank.note
    assert text.extract_text(b"%PDF-1.7 broken", name="x.pdf").status == "error"


def test_docx_paragraphs_and_tables_and_the_inflation_cap(monkeypatch):
    data = make_docx(["POWER OF ATTORNEY", "I hereby appoint the attorney-in-fact named below."],
                     table=[["Principal", "Demo Principal"], ["Wallet", EVM]])
    t = text.extract_text(data, name="poa.docx")
    assert t.kind == "docx" and "hereby appoint" in t.text and EVM in t.text
    monkeypatch.setattr(text, "MAX_DOCX_XML", 100)
    assert text.extract_text(data, name="poa.docx").status == "too_large"


def test_eml_headers_body_and_attachment_list_without_opening_it():
    data = make_eml("Dear investigator,\nWe have received your request. Ticket number: 99887766.\nKuCoin compliance team",
                    subject="Re: freeze request", attachment=("statement.pdf", make_pdf([["attachment secret words"]])))
    t = text.extract_text(data, name="reply.eml")
    assert t.kind == "email" and "Subject: Re: freeze request" in t.text and "Ticket number" in t.text
    assert "statement.pdf (application/pdf" in t.text and "attachment secret words" not in t.text
    assert t.meta["attachments"][0]["name"] == "statement.pdf"
    # a .msg that is an RFC 822 message is read as one; the binary Outlook form is refused with a hint
    assert text.extract_text(data, name="reply.msg").kind == "email"
    ole = text.extract_text(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, name="reply.msg")
    assert ole.status == "unsupported" and ".eml" in ole.note


@pytest.mark.parametrize("name,data,want", [
    ("notes.txt", b"Plain text note about a wire", "Plain text note"),
    ("rows.csv", b"date,amount\n2026-10-01,5000 USDT\n", "5000 USDT"),
    ("chat.json", json.dumps({"messages": [{"text": "hello there"}]}).encode(), "hello there"),
    ("readme.md", b"# Heading\nbody text", "body text"),
    ("page.html", b"<html><head><script>alert(1)</script></head><body><p>Visible</p><style>x{}</style></body></html>",
     "Visible"),
    ("letter.rtf", rb"{\rtf1\ansi{\fonttbl\f0 Helvetica;}\f0 Lettre de mandat\par caf\'e9}", "Lettre de mandat"),
    ("latin.txt", "Kontoauszug für Oktober".encode("cp1252"), "Kontoauszug für Oktober"),
])
def test_text_formats(name, data, want):
    t = text.extract_text(data, name=name)
    assert t.status == "ok" and want in t.text
    if name.endswith(".html"):
        assert "alert" not in t.text and "x{}" not in t.text
    if name.endswith(".rtf"):
        assert "Helvetica" not in t.text and "café" in t.text


def test_images_have_no_text_and_size_and_text_caps(monkeypatch):
    t = text.extract_text(PNG, name="shot.png")
    assert t.status == "image" and "describe" in t.note and t.text == ""
    monkeypatch.setattr(text, "MAX_READ_BYTES", 10)
    assert text.extract_text(b"x" * 11, name="a.txt").status == "too_large"
    monkeypatch.setattr(text, "MAX_READ_BYTES", 1 << 20)
    monkeypatch.setattr(text, "MAX_TEXT_CHARS", 50)
    t = text.extract_text(b"word " * 100, name="a.txt")
    assert len(t.text) == 50 and t.truncated


# --------------------------------------------------------------------------- the rules
@pytest.mark.parametrize("body,name,kind,want,folder", [
    ("\n".join(DENUNCIA), "scan.pdf", "pdf", "police_report", "law_enforcement"),
    ("Strafanzeige bei der Polizeiinspektion Demo, Vorgangsnummer 123/26", "x.pdf", "pdf", "police_report",
     "law_enforcement"),
    ("Récépissé de dépôt de plainte, commissariat de Demo", "x.pdf", "pdf", "police_report", "law_enforcement"),
    ("Internet Crime Complaint Center (IC3). Complaint ID: I2610051234ABC", "x.pdf", "pdf", "ic3_complaint",
     "law_enforcement"),
    ("IN THE HIGH COURT OF DEMO. FREEZING ORDER. It is hereby ordered that the respondent's assets be frozen.",
     "x.pdf", "pdf", "freezing_order", "legal"),
    ("UNITED STATES DISTRICT COURT. SEIZURE WARRANT. It is ordered that the property be seized.", "x.pdf", "pdf",
     "seizure_warrant", "legal"),
    ("Tribunale di Demo. Ordinanza del giudice. Il giudice dispone quanto segue.", "x.pdf", "pdf", "court_order",
     "legal"),
    ("Procura della Repubblica presso il Tribunale. Richiesta di informazioni ai sensi del codice.", "x.pdf", "pdf",
     "le_letter", "law_enforcement"),
    ("PROCURA SPECIALE. Il sottoscritto conferisce procura speciale.", "x.docx", "docx", "special_proxy", "legal"),
    ("Letter of authority: I authorise Demo Investigations to act on my behalf.", "x.docx", "docx", "loa", "legal"),
    ("Kontoauszug Nr. 10, IBAN DE00 0000 0000 0000 0000 00, Anfangssaldo", "x.pdf", "pdf", "bank_statement",
     "financial"),
    ("Relevé de compte bancaire du mois d'octobre", "x.pdf", "pdf", "bank_statement", "financial"),
    ("Avis de virement: virement SEPA vers le bénéficiaire", "x.pdf", "pdf", "wire_confirmation", "financial"),
    ("Estratto conto. Saldo iniziale e saldo finale.", "x.pdf", "pdf", "bank_statement", "financial"),
    ("Withdrawal history: TxID, network TRC20, withdrawal address", "x.csv", "text", "exchange_statement",
     "financial"),
    ("PASSPORT\nP<DEMDEMO<<SAMPLE<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nX000000000DEM0000000M0000000<<<<<<<<<<<<<<00",
     "id.pdf", "pdf", "kyc_id_document", "financial"),
    ("\n".join(f"0{i}/10/2026, 10:1{i} - Demo Persona: message {i}" for i in range(1, 8)), "export.txt", "text",
     "chat_export", "digital_artifacts"),
    ("Blockchain tracing report. Fund flow from the victim wallet over 4 hops.", "x.pdf", "pdf", "trace_report",
     "investigator_reports"),
    ("INVOICE no. 7. Amount due within 30 days. VAT 22%.", "x.pdf", "pdf", "invoice", "investigator_reports"),
    ("TERM SHEET. Whereas the parties agree, hereinafter the Agreement.", "x.docx", "docx", "contract", "legal"),
])
def test_rules_read_the_type_in_four_languages(body, name, kind, want, folder):
    r = rules.classify(body, name=name, kind=kind)
    assert r["type"] == want, r
    # round 12: a police report counts as one (its keys) only with its agency in the letterhead and a report number
    # `keys`: what the type counts for once a person confirms it (a suggestion applies nothing by itself)
    weak = want == "police_report" and not rules._POLICE_REF.search(body)
    assert r["folder"] == folder and r["reasons"] and r["keys"] == list(rules.DOC_TYPES[want].keys)
    assert (r["note"] == rules.REPORT_NOTE) if weak else not r["note"]


def test_rules_keys_and_names_and_the_image_fallback():
    assert rules.classify("Complaint ID for IC3", kind="pdf")["keys"] == ["police_report", "complaint_ref", "ic3_ref"]
    # an image: no text, the file name decides; nothing at all: a screenshot, unclassified
    r = rules.classify("", name="WhatsApp chat with persona.png", kind="image")
    assert r["type"] == "chat_export" and r["folder"] == "digital_artifacts" and "file name" in r["reasons"][0]
    r = rules.classify("", name="IMG_0042.png", kind="image")
    assert r["type"] == "other" and r["folder"] == "digital_artifacts" and r["section"] == "screenshots"
    assert rules.classify("lorem ipsum", name="x.txt", kind="text")["type"] == "other"
    # an e-mail from a provider answering a request is its reply, not a plain e-mail export
    r = rules.classify("We have received your request. Ticket number: 123. Compliance team", kind="email",
                       provider_named=True)
    assert r["type"] == "provider_reply" and r["folder"] == "stop_orders_correspondence"
    assert rules.classify("Hello, see you tomorrow", kind="email")["type"] == "email_export"


def test_findings_identifiers_refs_dates_amounts_providers():
    body = ("\n".join(DENUNCIA) + f"\nSolana wallet {SOL}. EVM wallet {EVM}. Binance UID: 77001234."
            "\nIC3 complaint ID: I2610051234ABC. Funds were sent through KuCoin and Binance.")
    cat = intel._catalogue_orgs()
    f = findings.find(body, orgs=cat)
    ids = {(i["kind"], i["chain"], i["value"]) for i in f["identifiers"]}
    assert ("address", "tron", TRON) in ids and ("address", "evm", EVM) in ids and ("tx", "evm", TX) in ids
    assert ("address", "solana", SOL) in ids and ("account", None, "77001234") in ids
    systems = {(r["system"], r["reference"]) for r in f["refs"]}
    assert ("protocollo", "4417/2026") in systems and ("ic3", "I2610051234ABC") in systems
    assert {"amount": "12500.00", "asset": "USDT", "raw": "12.500,00 USDT"} in f["amounts"]
    assert f["doc_date"] == "2026-10-03" and {p["name"] for p in f["providers"]} >= {"KuCoin", "Binance"}
    # a Solana-shaped run in a text that never mentions Solana is no address; "gate" is not Gate
    assert not [i for i in findings.find(f"code {SOL} here")["identifiers"] if i["chain"] == "solana"]
    assert "Gate" not in {p["name"] for p in findings.find("we investigate the gate", orgs=cat)["providers"]}
    stored = findings.stored(findings.find("Officer Demo Person, e-mail demo.person@police.example, Tel. +39 000 0000000. "
                                           "Prot. n. 55/2026 Carabinieri", orgs=cat))
    assert "demo.person" not in json.dumps(stored) and "Person" not in json.dumps(stored)


# --------------------------------------------------------------------------- upload -> suggest -> confirm
def test_upload_reads_suggests_and_moves_nothing_until_confirmed(client, fcase, vault, db):
    case = fcase
    c = client
    data = make_pdf([DENUNCIA + ["Testo finale riservato della denuncia che non entra nel database."]])
    r = _upload(c, case, "scan-2026-10-03.pdf", data, "application/pdf")
    loc = r.headers["location"]
    assert r.status_code == 303 and "ev_err" not in loc and "Aegis+read+this+as" in loc and "Police+report" in loc
    item = _new_item(db, case, data)
    assert item.folder == EvidenceFolder.OTHER and "police_report" not in (item.tags or [])  # nothing moved
    iv = intel.intel(item)
    assert iv["rules"]["type"] == "police_report" and iv["text"]["status"] == "ok"
    # the text is in the vault (sha256-linked), the database holds a short excerpt only
    stored = vault / iv["text"]["path"]
    assert stored.is_file() and stored.name == f"{item.sha256}.txt" and stored.is_relative_to(vault / "text")
    assert "Testo finale riservato" in stored.read_text() and intel.load_text(item) == stored.read_text()
    assert "Testo finale riservato" not in json.dumps(item.meta) and len(iv["text"]["excerpt"]) <= intel.EXCERPT_CHARS
    # the queue lists it; the checklist shows it as a suggestion to confirm, never on file
    page = c.get(f"/cases/{case.id}?tab=evidence").text
    assert "Unclassified / suggested" in page and f"/evidence/{item.id}#ev-intel" in page
    row = next(x for x in er.check(er.holdings(db, case, wallets=[]), ["police_report"]))
    assert item.id not in row["ids"]  # (the case's own complaint references count; the reading never does)
    proxy = ev.add_note(db, case, title="scan", text="PROCURA SPECIALE. Il sottoscritto conferisce procura speciale.")
    intel.read_item(db, proxy)
    db.commit()
    row = next(x for x in er.check(er.holdings(db, case, wallets=[]), ["special_proxy"]))
    assert row["state"] == "missing" and row["matched"] is None and row["suggested"]["ids"] == [proxy.id]
    assert row["state_label"] == "suggested: special proxy — confirm"
    # the item page shows the reading, the findings and one-click proposals
    page = c.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert "What Aegis read" in page and "Confirm: Police report" in page and TRON in page
    assert "Record the complaint reference" in page and "Watch for a freeze" in page and "role: you choose" in page
    # a person confirms: the type becomes a tag, the keys explicit matches, the item moves to its folder
    r = c.post(f"/cases/{case.id}/evidence/{item.id}/intel/confirm",
               data={"csrf_token": _tok(c, case), "doc_type": "police_report", "move": "1"}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    item = db.get(EvidenceItem, item.id)
    assert item.folder == EvidenceFolder.LAW_ENFORCEMENT and "police_report" in item.tags
    assert intel.confirmed_keys(item) == {"police_report", "complaint_ref"} and intel.status(item) == "confirmed"
    row = next(x for x in er.check(er.holdings(db, case, wallets=[]), ["complaint_ref"]))
    assert row["state"] == "have" and row["matched"] is None and item.id in row["ids"]
    assert item.id not in [q["item"].id for q in intel.queue(_access(db, case, c))]
    rows = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.object_id == str(item.id),
                                               AuditEvent.action.in_(["READ_EVIDENCE", "UPDATE"]))).all()
    assert {"READ_EVIDENCE", "UPDATE"} <= {a.action for a in rows}
    assert "denuncia" not in json.dumps([a.detail for a in rows]).lower().replace("police_report", "")


def _access(db, case, c):
    from app.core.permissions import ADMIN, CaseAccess

    return CaseAccess(case=case, user=c.user, role=ADMIN, member=None)


def test_image_upload_is_categorised_from_its_file_name(client, fcase, vault, db):
    data = PNG + b"wa-shot"
    r = _upload(client, fcase, "WhatsApp chat screenshot.png", data, "image/png")
    assert "No+text+%28image%29" in r.headers["location"] or "No text (image)" in r.headers["location"]
    item = _new_item(db, fcase, data)
    iv = intel.intel(item)
    assert iv["text"]["status"] == "image" and iv["rules"]["type"] == "chat_export"
    assert not (vault / "text").exists() or not list((vault / "text").rglob("*.txt"))


def test_an_order_opens_the_gate_only_once_a_person_confirms_it_with_its_addressee(client, fcase, vault, db):
    case = fcase
    body = ["United States District Court for the District of Demo", "ORDER",
            "It is hereby ordered that Circle shall freeze the USDC held at the address below.", EVM]
    data = make_pdf([body])
    _upload(client, case, "order.pdf", data, "application/pdf")
    item = _new_item(db, case, data)
    assert intel.intel(item)["rules"]["type"] == "court_order"
    # suggested only: never on file as an LE / court instrument, never in the gate
    assert er.held_instruments(case) == frozenset() and "court_order" in intel.suggested_keys(item)
    row = next(x for x in er.check(er.holdings(db, case, wallets=[]), ["court_order"]))
    assert row["state"] == "le" and row["state_label"] == "suggested: court order — confirm" and not row["ids"]
    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert "Confirm: Court order" not in page and "addressed to" in page and 'value="US"' in page
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/confirm",
                    data={"csrf_token": _tok(client, case), "doc_type": "court_order", "jurisdiction": "US",
                          "addressed_to": "Circle", "move": "1"}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    item, case = db.get(EvidenceItem, item.id), db.get(type(case), case.id)
    assert item.folder == EvidenceFolder.LEGAL and item.meta["jurisdiction"] == "US" and item.meta["to"] == "Circle"
    assert {"court_order", "us_or_fr_court_order"} <= er.held_instruments(case, ["Circle (USDC issuer)", "Circle"])
    assert er.held_instruments(case, ["KuCoin"]) == frozenset()


def test_financial_needs_a_case_admin_to_move(client_for, fcase, vault, db):
    inv = client_for("investigator", case=fcase)
    data = make_pdf([["Bank statement", "Opening balance 10,000.00 EUR", "Closing balance 0.00 EUR"]])
    _upload(inv, fcase, "statement.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    assert intel.intel(item)["rules"]["type"] == "bank_statement"
    r = inv.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/confirm",
                 data={"csrf_token": _tok(inv, fcase), "doc_type": "bank_statement", "move": "1"},
                 follow_redirects=False)
    assert "case+admin+can+file+it+under+Financial" in r.headers["location"]
    db.expire_all()
    item = db.get(EvidenceItem, item.id)
    assert item.folder == EvidenceFolder.OTHER and intel.confirmed_keys(item) == {"ownership_proof", "wire_details"}


def test_one_click_proposals_complaint_reference_and_reply_link(client, fcase, vault, db):
    case = fcase
    order = next(o for o in case.stop_orders if o.entity is not None and o.entity.name == "KuCoin")
    body = ["Dear investigator,", "We have received your request regarding the account below.",
            "Ticket number: 55667788. KuCoin compliance team.", "IC3 complaint ID: I2610059999XYZ was quoted.",
            f"The account received funds at {EVM}."]
    data = make_eml("\n".join(body), subject="Re: urgent request")
    _upload(client, case, "kucoin-reply.eml", data, "message/rfc822")
    item = _new_item(db, case, data)
    assert intel.intel(item)["rules"]["type"] == "provider_reply"
    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert f"File as the reply to stop order #{order.id}" in page
    assert "Seed the trace (" not in page  # every seed role is taken: a proposal never replaces a seed
    for seed in [s for s in case.seeds if s.role.value == "perpetrator_wallet"]:
        db.delete(seed)
    db.commit()
    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    # no role until a person picks one: watch and seed are offered disabled
    assert "Seed the trace (perpetrator wallet)" not in page and "Record the role" in page and "pick its role first" in page
    tok = _tok(client, case)
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/wallet-role",
                    data={"csrf_token": tok, "value": EVM, "role": "perpetrator"}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get(f"/cases/{case.id}/evidence/{item.id}").text
    assert "Seed the trace (perpetrator wallet)" in page and "Watch for a freeze" in page
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/complaint",
                    data={"csrf_token": tok, "authority": "FBI IC3", "reference": "I2610059999XYZ"},
                    follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    db.expire_all()
    case = db.get(type(case), case.id)
    assert any(c.get("reference") == "I2610059999XYZ" and c.get("evidence_item_id") == item.id
               for c in case.facts["complaints"])
    audit_rows = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id,
                                                     AuditEvent.action == "UPDATE")).all()
    assert "I2610059999XYZ" not in json.dumps([a.detail for a in audit_rows])
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/link",
                    data={"csrf_token": tok, "stop_order_id": str(order.id)}, follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    db.expire_all()
    corr = db.scalar(select(Correspondence).where(Correspondence.evidence_item_id == item.id))
    assert corr is not None and corr.direction.value == "in" and corr.stop_order_id == order.id
    assert "Ticket number: 55667788" in corr.body_markdown
    r = client.post(f"/cases/{case.id}/evidence/{item.id}/intel/link",
                    data={"csrf_token": tok, "stop_order_id": str(order.id)}, follow_redirects=False)
    assert "ev_err=1" in r.headers["location"]  # filed once


def test_mailbox_messages_and_trace_reports_stay_out_of_the_queue(db, fcase, client):
    a = ev.add_note(db, fcase, title="Received mail", text="hello", tags=["aegis-mail", "received-email"])
    b = ev.add_note(db, fcase, title="Police report scan text", text="denuncia querela carabinieri")
    db.commit()
    ids = [q["item"].id for q in intel.queue(_access(db, fcase, client))]
    assert a.id not in ids and b.id in ids


# --------------------------------------------------------------------------- AI: consent, verification, gating
@pytest.fixture
def ai_on(monkeypatch):
    monkeypatch.delenv("AEGIS_AI_DISABLED", raising=False)


def _use(monkeypatch, rec):
    p = _provider(rec)
    monkeypatch.setattr(providers, "get_provider", lambda: p)
    return p


def _enable(db, case):
    eai.set_enabled(db, case, None, True, consent=True,
                    dest={"provider": "hf_router", "label": LABEL, "model": MODEL, "host": "router.huggingface.co"})


def _ai_answer(doc_type, quote, **kw):
    return {"doc_type": doc_type, "quote": quote, "confidence": 0.9, "summary": "A complaint.", **kw}


def test_no_ai_call_while_the_setting_is_off(db, fcase, monkeypatch, ai_on):
    rec = Recorder(_ai_answer("police_report", "Verbale di ricezione di denuncia-querela"))
    _use(monkeypatch, rec)
    item = ev.add_note(db, fcase, title="note", text="\n".join(DENUNCIA))
    iv = intel.read_item(db, item)
    assert rec.requests == [] and "ai" not in iv and fcase.evidence_ai_consent is None
    assert eai.may_call(fcase, providers.get_provider()) == (False, "setting_off")


def test_ai_reads_redacted_text_and_its_reading_is_verified(db, fcase, monkeypatch, ai_on, vault):
    fcase.facts = {**(fcase.facts or {}), "victim_contact": {"name": "Quentin Victimname"}}
    fcase.ai_mode = AIMode.REDACTED
    db.commit()
    _enable(db, fcase)
    rec = Recorder(_ai_answer("police_report", "Verbale di ricezione di denuncia-querela",
                              parties=[{"name": "Comando Carabinieri", "role": "police",
                                        "quote": "Comando Carabinieri di Demo Valle"},
                                       {"name": "Invented Person", "quote": "not in the text at all"}],
                              amounts=[{"amount": "12500", "asset": "USDT",
                                        "quote": "La persona offesa dichiara di aver inviato 12.500,00 USDT"},
                                       {"amount": "999999", "asset": "USDT", "quote": "made up amount here"}],
                              identifiers=[{"kind": "address", "value": TRON}, {"kind": "address", "value": "TFake"}]))
    _use(monkeypatch, rec)
    item = ev.add_note(db, fcase, title="note", text="Denunciante: Quentin Victimname\n" + "\n".join(DENUNCIA))
    iv = intel.read_item(db, item)
    sent = json.dumps(rec.bodies())
    assert len(rec.requests) == 1 and "Quentin Victimname" not in sent and "Victimname" not in sent
    assert TRON in sent  # chain identifiers stay
    # the database keeps the type / verified / confidence / model; the quote, summary and parties are document content:
    # a vault sidecar, read back for the item page
    assert not {"quote", "summary", "parties", "amounts", "identifiers"} & set(iv["ai"]) and iv["ai"]["detail"]["path"]
    assert "Comando Carabinieri" not in json.dumps(item.meta["intel"]["ai"])
    a = intel.ai_reading(item)
    assert a["type"] == "police_report" and a["verified"] and a["quote"]
    assert [p["name"] for p in a["parties"]] == ["Comando Carabinieri"]
    assert [m["amount"] for m in a["amounts"]] == ["12500"] and [i["value"] for i in a["identifiers"]] == [TRON]
    row = db.scalar(select(AuditEvent).where(AuditEvent.action == "AI_QUERY", AuditEvent.object_id == str(item.id)))
    assert row.detail["kind"] == "evidence_classification" and row.detail["mode"] == "redacted"
    assert "denuncia" not in json.dumps(row.detail).lower() and row.detail["classified_as"] == "police_report"
    # the same text is not sent again on a re-read
    intel.read_item(db, item)
    assert len(rec.requests) == 1


def test_an_unverified_ai_reading_is_never_offered_as_the_suggestion(client, db, fcase, monkeypatch, ai_on, vault):
    _enable(db, fcase)
    rec = Recorder(_ai_answer("court_order", "It is hereby ordered that all funds be returned"))
    _use(monkeypatch, rec)
    item = ev.add_note(db, fcase, title="note", text="lorem ipsum dolor sit amet, a plain note about nothing")
    db.commit()
    iv = intel.read_item(db, item)
    db.commit()
    assert iv["ai"]["verified"] is False and iv["ai"]["confidence"] <= 0.3 and intel.status(item) == "unclassified"
    page = client.get(f"/cases/{fcase.id}/evidence/{item.id}").text
    assert "Use the AI&#39;s reading" not in page and "Use the AI's reading" not in page and "unverified" in page


@pytest.mark.parametrize("why", ["tlp", "mode_off", "kill", "outdated"])
def test_ai_gates(db, fcase, monkeypatch, ai_on, why):
    _enable(db, fcase)
    rec = Recorder(_ai_answer("police_report", "Verbale di ricezione di denuncia-querela"))
    p = _use(monkeypatch, rec)
    item = ev.add_note(db, fcase, title="note", text="\n".join(DENUNCIA),
                       tlp="TLP:RED" if why == "tlp" else None)
    if why == "mode_off":
        fcase.ai_mode = AIMode.OFF
    if why == "kill":
        monkeypatch.setenv("AEGIS_AI_DISABLED", "1")
    if why == "outdated":
        p.model = "another/model"
    db.commit()
    iv = intel.read_item(db, item)
    assert rec.requests == [] and "ai" not in iv
    assert iv["ai_skipped"] == {"tlp": "restricted_tlp", "mode_off": "ai_mode_off", "kill": "disabled",
                                "outdated": "consent_outdated"}[why]


def test_ai_setting_route_needs_an_admin_and_the_consent(client_for, fcase, db, monkeypatch):
    from app.web import routes_evidence_intel as rei

    monkeypatch.setattr(rei, "destination", lambda: {"provider": "hf_router", "label": LABEL, "model": MODEL,
                                                     "host": "router.huggingface.co", "third_party": True,
                                                     "configured": True, "kill_switch": False})
    inv = client_for("investigator", case=fcase)
    r = inv.post(f"/cases/{fcase.id}/evidence/intel/ai-setting",
                 data={"csrf_token": _tok(inv, fcase), "enabled": "1", "consent": "1"}, follow_redirects=False)
    assert r.status_code == 403
    adm = client_for("admin", case=fcase)
    r = adm.post(f"/cases/{fcase.id}/evidence/intel/ai-setting",
                 data={"csrf_token": _tok(adm, fcase), "enabled": "1"}, follow_redirects=False)
    assert r.status_code == 400
    r = adm.post(f"/cases/{fcase.id}/evidence/intel/ai-setting",
                 data={"csrf_token": _tok(adm, fcase), "enabled": "1", "consent": "1", "destination": LABEL},
                 follow_redirects=False)
    assert r.status_code == 400  # no model: consent is always to the destination and model the page showed
    r = adm.post(f"/cases/{fcase.id}/evidence/intel/ai-setting",
                 data={"csrf_token": _tok(adm, fcase), "enabled": "1", "consent": "1", "destination": LABEL,
                       "model": MODEL}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    st = db.get(type(fcase), fcase.id).evidence_ai_consent
    assert st["enabled"] and st["destination"] == LABEL and st["model"] == MODEL
    row = db.scalars(select(AuditEvent).where(AuditEvent.case_id == fcase.id, AuditEvent.action == "UPDATE")
                     .order_by(AuditEvent.id.desc())).first()
    assert row.detail["setting"] == eai.SETTING and row.detail["enabled"] is True


# --------------------------------------------------------------------------- the backfill
def test_reread_all_backfills_imported_items_rules_only_and_moves_nothing(client_for, fcase, db, tmp_path, monkeypatch,
                                                                          ai_on):
    rec = Recorder(_ai_answer("police_report", "x"))
    _use(monkeypatch, rec)
    src = tmp_path / "originals" / "Evidence"
    src.mkdir(parents=True)
    (src / "Denuncia scan.pdf").write_bytes(make_pdf([DENUNCIA]))
    (src / "notes.docx").write_bytes(make_docx(["Power of attorney: I hereby appoint my attorney-in-fact."]))
    rep = ev.import_directory(db, fcase, src.parent)
    db.commit()
    created = {e.title: e for e in rep.created}
    assert all(not intel.intel(e) for e in created.values())
    inv = client_for("investigator", case=fcase)
    r = inv.post(f"/cases/{fcase.id}/evidence/intel/reread", data={"csrf_token": _tok(inv, fcase)},
                 follow_redirects=False)
    assert r.status_code == 403
    adm = client_for("admin", case=fcase)
    folders = {e.id: e.folder for e in created.values()}
    r = adm.post(f"/cases/{fcase.id}/evidence/intel/reread", data={"csrf_token": _tok(adm, fcase)},
                 follow_redirects=False)
    assert r.status_code == 303 and "Nothing+was+moved" in r.headers["location"]
    db.expire_all()
    for title, want in (("Denuncia scan", "police_report"), ("notes", "poa")):
        e = db.get(EvidenceItem, created[title].id)
        assert intel.intel(e)["rules"]["type"] == want and e.folder == folders[e.id]
        assert intel.intel(e)["text"]["stored"] == "original"  # a reference: its text is never copied
    assert rec.requests == []  # rules only: the case never consented
    assert db.scalar(select(AuditEvent).where(AuditEvent.case_id == fcase.id, AuditEvent.action == "READ_EVIDENCE",
                                              AuditEvent.object_id.is_(None))).detail["read"] >= 2


def test_reading_an_unreadable_or_tampered_item_never_fails(db, fcase, vault):
    item = ev.store_upload(db, fcase, io.BytesIO(b"plain text that will be altered"), filename="x.txt", folder="other")
    db.commit()
    (vault / item.vault_path).write_bytes(b"tampered bytes")
    iv = intel.read_item(db, item)
    assert iv["text"]["status"] == "error" and "integrity" in iv["text"]["note"]
    assert intel.load_text(item) is None


def test_api_shapes_and_role_visibility(client_for, fcase, db, vault):
    adm = client_for("admin", case=fcase)
    data = make_pdf([DENUNCIA])
    _upload(adm, fcase, "scan.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    full = adm.get(f"/api/cases/{fcase.id}/evidence/{item.id}/intel").json()
    assert full["rules"]["type"] == "police_report" and TRON in json.dumps(full["findings"])
    ro = client_for("read_only", case=fcase)
    lite = ro.get(f"/api/cases/{fcase.id}/evidence/{item.id}/intel").json()
    assert lite["rules"]["type"] == "police_report" and "findings" not in lite and "excerpt" not in lite["text"]
    assert any(q["id"] == item.id for q in adm.get(f"/api/cases/{fcase.id}/evidence/intel/queue").json())


def test_migration_0011_adds_the_evidence_ai_consent(tmp_path):
    from sqlalchemy import create_engine, inspect
    from test_migrations import _cfg

    from alembic import command

    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0011_wallet_attributions")
    with engine.connect() as conn:
        assert "evidence_ai_consent" in {c["name"] for c in inspect(conn).get_columns("cases")}
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0010_mailbox_status")
    with engine.connect() as conn:
        assert "evidence_ai_consent" not in {c["name"] for c in inspect(conn).get_columns("cases")}
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    engine.dispose()


def test_zip_member_and_mime_mislabel_are_read_by_their_bytes():
    pdf = make_pdf([["Power of attorney"]])
    assert text.detect(pdf, "renamed.txt", "text/plain") == "pdf"
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as zf:
        zf.writestr("a.txt", "x")
    assert text.extract_text(b.getvalue(), name="bundle.zip").status == "unsupported"
    assert httpx  # the provider fake's transport (test_block_ai) is httpx.MockTransport


# --------------------------------------------------------------------------- verify round 7
VIC = "0x" + "be11" * 10
SUS = "0x" + "7d1a" * 10
TXH = "0x" + "9f" * 32
VICTIM_FIRST = (f"Police report. The victim sent 40,000 USDT from her own wallet {VIC} (MetaMask) to the suspect's "
                f"wallet {SUS}, transaction hash {TXH}. A later transfer went to {EVM}.")


def test_wallets_have_no_role_until_a_person_picks_one_then_watch_and_seed_open(client, fcase, vault, db):
    for s in list(fcase.seeds):
        db.delete(s)
    db.commit()
    data = VICTIM_FIRST.encode()
    _upload(client, fcase, "Police report.txt", data, "text/plain")
    item = _new_item(db, fcase, data)
    v = intel.view(db, _access(db, fcase, client), item)
    by = {i["value"]: i for i in v["ids"]}
    # the text only hints: every wallet's role is None, nothing to watch or seed; the tx hash keeps its origin seed
    for w in (VIC, SUS, EVM):
        assert by[w]["role"] is None and not by[w]["watch"] and by[w]["seed_role"] is None, w
    assert by[TXH]["seed_role"] == "origin_tx"
    assert "victim" in (by[VIC]["hint"] or "") and "suspect" in (by[SUS]["hint"] or "")
    assert findings.address_hint(VICTIM_FIRST, SUS) and not hasattr(findings, "address_role")
    page = client.get(f"/cases/{fcase.id}/evidence/{item.id}").text
    assert "Seed the trace (victim wallet)" not in page and "Seed the trace (perpetrator wallet)" not in page
    assert "role: you choose" in page and "Record the role" in page
    tok = _tok(client, fcase)
    for w, role in ((VIC, "victim"), (SUS, "perpetrator"), (EVM, "unknown")):
        r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/wallet-role",
                        data={"csrf_token": tok, "value": w, "role": role}, follow_redirects=False)
        assert r.status_code == 303, w
    r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/wallet-role",
                    data={"csrf_token": tok, "value": EVM, "role": "owner"}, follow_redirects=False)
    assert r.status_code == 400  # an unknown role
    r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/wallet-role",
                    data={"csrf_token": tok, "value": "0x" + "00" * 20, "role": "victim"}, follow_redirects=False)
    assert r.status_code == 400  # a wallet the item does not name
    db.expire_all()
    item = db.get(EvidenceItem, item.id)
    v = intel.view(db, _access(db, fcase, client), item)
    by = {i["value"]: i for i in v["ids"]}
    assert by[VIC]["role"] == "victim" and by[VIC]["seed_role"] == "victim_wallet" and not by[VIC]["watch"]
    assert by[SUS]["role"] == "perpetrator" and by[SUS]["seed_role"] == "perpetrator_wallet" and by[SUS]["watch"]
    assert by[EVM]["role"] == "unknown" and by[EVM]["seed_role"] == "known_downstream" and by[EVM]["watch"]
    # nothing was watched or seeded by the pick itself
    assert not db.get(type(fcase), fcase.id).seeds
    from app.db.models import FreezeWatch

    assert not {w.address.lower() for w in db.scalars(select(FreezeWatch).where(FreezeWatch.case_id == fcase.id))} & {
        VIC, SUS, EVM.lower()}
    # the pick is audited (the role and the item, never the address) and survives a re-read
    rows = db.scalars(select(AuditEvent).where(AuditEvent.case_id == fcase.id, AuditEvent.object_id == str(item.id),
                                               AuditEvent.action == "UPDATE")).all()
    picked = [a.detail for a in rows if (a.detail or {}).get("setting") == "wallet_role"]
    assert sorted(d["role"] for d in picked) == ["perpetrator", "unknown", "victim"]
    assert SUS not in json.dumps(picked) and SUS[2:] not in json.dumps(picked)
    intel.read_item(db, item, use_ai=False)
    db.commit()
    assert intel.wallet_roles(item)[SUS.lower()]["role"] == "perpetrator"
    page = client.get(f"/cases/{fcase.id}/evidence/{item.id}").text
    assert "Seed the trace (victim wallet)" in page and 'name="only_empty" value="1"' in page
    r = client.post(f"/cases/{fcase.id}/seeds", data={"csrf_token": tok, "role": "perpetrator_wallet",
                                                      "chain": "ethereum", "value": SUS, "only_empty": "1"},
                    follow_redirects=False)
    assert r.status_code == 303
    r = client.post(f"/cases/{fcase.id}/seeds", data={"csrf_token": tok, "role": "perpetrator_wallet",
                                                      "chain": "ethereum", "value": EVM, "only_empty": "1"},
                    follow_redirects=False)
    assert r.status_code == 409  # a proposal never replaces a seed
    db.expire_all()
    seeds = {s.role.value: s.value for s in db.get(type(fcase), fcase.id).seeds}
    assert seeds["perpetrator_wallet"].lower() == SUS


def test_a_type_suggestion_applies_only_once_a_person_confirms_it(client, fcase, vault, db):
    data = make_pdf([DENUNCIA])
    _upload(client, fcase, "scan.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    assert intel.intel(item)["rules"]["type"] == "police_report" and not intel.confirmed_keys(item)
    for key in ("police_report", "complaint_ref"):
        row = next(x for x in er.check(er.holdings(db, fcase, wallets=[]), [key]))
        assert row["state"] != "have" or item.id not in row["ids"], key  # never on file from the reading
        assert row["state"] == "have" or row["state_label"] == "suggested: police report — confirm", key
    r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/confirm",
                    data={"csrf_token": _tok(client, fcase), "doc_type": "police_report", "move": "1"},
                    follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    item = db.get(EvidenceItem, item.id)
    case = db.get(type(fcase), fcase.id)
    assert "police_report" in item.tags and intel.confirmed_keys(item) == {"police_report", "complaint_ref"}
    row = next(x for x in er.check(er.holdings(db, case, wallets=[]), ["police_report"]))
    assert row["state"] == "have" and item.id in row["ids"] and not row["suggested"]


def test_a_tlp_restricted_item_is_filed_as_a_reply_without_its_text(client, fcase, vault, db):
    from app.ai.context import build_context

    case = fcase
    order = next(o for o in case.stop_orders if o.entity is not None and o.entity.name == "KuCoin")
    item = ev.add_note(db, case, title="reply", text="KuCoin compliance: MARKER-RED-77 the account is frozen.",
                       tlp="TLP:RED")
    db.commit()
    corr = intel.link_reply(db, _access(db, case, client), item, order.id)
    db.commit()
    assert corr.body_markdown is None and "TLP-restricted" in corr.subject
    other = ev.add_note(db, case, title="reply 2", text="KuCoin compliance: MARKER-LATER-88 we hold the funds.")
    db.commit()
    intel.link_reply(db, _access(db, case, client), other, order.id)
    other.tlp = "TLP:AMBER+STRICT"  # restricted after it was filed: the context withholds it too
    db.commit()
    db.expire_all()
    ctx = json.dumps(build_context(db, db.get(type(case), case.id), AIMode.FULL), default=str)
    assert "MARKER-RED-77" not in ctx and "MARKER-LATER-88" not in ctx and "TLP-restricted evidence item" in ctx


def test_mailbox_items_and_personal_documents_are_never_sent_to_the_evidence_ai(db, fcase, monkeypatch, ai_on):
    _enable(db, fcase)
    fcase.ai_mode = AIMode.REDACTED
    db.commit()
    rec = Recorder(_ai_answer("police_report", "Verbale di ricezione di denuncia-querela"))
    _use(monkeypatch, rec)
    for tags in (["aegis-mail", "received-email"], ["aegis-mail", "email-attachment"]):
        item = ev.add_note(db, fcase, title="mail", text="\n".join(DENUNCIA), tags=tags)
        intel.read_item(db, item)
    kyc = ev.add_note(db, fcase, title="id", text="PASSPORT\nPassport No. X1234567\nDate of birth 01.02.1980\n"
                                                  "Nationality: Demo")
    iv = intel.read_item(db, kyc)
    assert iv["rules"]["type"] == "kyc_id_document" and iv["ai_skipped"] == "personal_financial"
    fin = ev.add_note(db, fcase, title="statement", text="\n".join(DENUNCIA), folder=EvidenceFolder.FINANCIAL)
    assert intel.read_item(db, fin)["ai_skipped"] == "personal_financial"
    assert rec.requests == []
    intel.read_item(db, ev.add_note(db, fcase, title="note", text="\n".join(DENUNCIA)))
    assert len(rec.requests) == 1


def test_members_without_access_to_the_content_see_no_vault_path_and_reads_are_bounded(client_for, fcase, db, vault,
                                                                                        monkeypatch):
    adm = client_for("admin", case=fcase)
    data = make_pdf([DENUNCIA])
    _upload(adm, fcase, "denuncia.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    item.shared_with_external = True
    db.commit()
    ro = client_for("read_only", case=fcase)
    lite = ro.get(f"/api/cases/{fcase.id}/evidence/{item.id}/intel").json()
    assert lite["text"] and set(lite["text"]) <= intel.TEXT_LITE and "path" not in lite["text"]
    seen = {}
    real = ev.read_verified

    def spy(it, limit=None):
        seen["limit"] = limit
        return real(it, limit=limit)

    monkeypatch.setattr(ev, "read_verified", spy)
    monkeypatch.setattr(intel, "MAX_READ_BYTES", 64)
    item.size_bytes = None  # registered without a size: the read is still bounded
    t = intel._read(item)
    assert seen["limit"] == 65 and t.status == "too_large"


def test_a_us_wire_confirmation_and_an_exchange_transaction_report_are_read(client, fcase, vault, db):
    wire = make_pdf([["Outgoing Wire Transfer Details", "Beneficiary Name: Demo Trading LLC",
                      "Beneficiary Bank: Demo Bank NA", "ABA Routing Number: 000000000",
                      "IMAD: 20260814B1Q8150C000123", "Amount: 40,000.00 USD"]])
    _upload(client, fcase, "Wire 0814.pdf", wire, "application/pdf")
    csv = ("ID,Timestamp,Transaction Type,Asset,Quantity Transacted,Price Currency,Price at Transaction,Subtotal,"
           f"Total,Fees,Notes\nx1,2026-08-14 10:00:00 UTC,Send,USDT,40000,USD,1,40000,40000,0,Sent 40000 USDT to {SUS}\n"
           ).encode()
    _upload(client, fcase, "coinbase_transaction_report.csv", csv, "text/csv")
    assert intel.intel(_new_item(db, fcase, wire))["rules"]["type"] == "wire_confirmation"
    assert intel.intel(_new_item(db, fcase, csv))["rules"]["type"] == "exchange_statement"
    assert rules.classify("", name="Chase_wire.pdf")["type"] == "wire_confirmation"
    db.expire_all()
    case = db.get(type(fcase), fcase.id)
    got = {e["key"]: e for e in er.check(er.holdings(db, case, wallets=[]), ["wire_details", "ownership_proof"])}
    # suggestions only: never on file until a person confirms each type
    assert got["wire_details"]["state_label"] == "suggested: wire confirmation — confirm"
    assert got["ownership_proof"]["state_label"] == "suggested: exchange statement — confirm"
    assert all(got[k]["state"] == "missing" for k in ("wire_details", "ownership_proof"))


US_REPORT = ["SPRINGFIELD POLICE DEPARTMENT", "INCIDENT REPORT", "Report Number: 26-004417",
             "Date Reported: 10/03/2026", "Reporting Officer: Ofc. J. Sample #1123",
             "Narrative: between 08/14/2026 and 09/20/2026 the victim sent funds to a fake platform."]


def test_a_us_police_report_gives_its_number_officer_and_report_date():
    f = findings.find("\n".join(US_REPORT))
    assert [(r["system"], r["reference"]) for r in f["refs"]] == [("police_us", "26-004417")]
    c = f["contacts"][0]
    assert c["role"] == "Ofc." and c["name"] == "J. Sample" and c["agency"] == "SPRINGFIELD POLICE DEPARTMENT"
    assert f["doc_date"] == "2026-10-03"  # the report's date, not the incident's (US month first)
    narrative = findings.find("SPRINGFIELD POLICE DEPARTMENT\nThe victim sent funds until 09/20/2026.")
    assert narrative["doc_date"] is None
    assert findings.find("\n".join(US_REPORT).replace("Report Number:", "Case No."))["refs"][0]["reference"] == "26-004417"
    # a provider's ticket is no police reference, even when it tells the victim to report to the police
    reply = findings.find("Your support case has been opened, case number: #500123. Please report it to the police.")
    assert reply["refs"] == []


def test_the_ai_setting_refuses_a_model_the_admin_did_not_see(client_for, fcase, db, monkeypatch):
    from app.web import routes_evidence_intel as rei

    monkeypatch.setattr(rei, "destination", lambda: {"provider": "hf_router", "label": LABEL, "model": MODEL,
                                                     "host": "router.huggingface.co", "third_party": True,
                                                     "configured": True, "kill_switch": False})
    adm = client_for("admin", case=fcase)
    r = adm.post(f"/cases/{fcase.id}/evidence/intel/ai-setting",
                 data={"csrf_token": _tok(adm, fcase), "enabled": "1", "consent": "1", "destination": LABEL,
                       "model": "another-model"}, follow_redirects=False)
    assert r.status_code == 409
    db.expire_all()
    assert not (db.get(type(fcase), fcase.id).evidence_ai_consent or {}).get("enabled")
