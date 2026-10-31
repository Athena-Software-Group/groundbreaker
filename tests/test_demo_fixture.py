"""The demo fixture: a fictional demo case with demo identities, demo references and no personal data or secrets."""

import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scripts import pii_scan

FIXTURE = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "demo_case.json"


@pytest.fixture(scope="module")
def raw() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def data(raw) -> dict:
    return json.loads(raw)


def test_fixture_contains_no_denylisted_string(raw):
    deny = os.environ.get("AEGIS_DENYLIST")
    if not deny:
        pytest.skip("AEGIS_DENYLIST not set (the denylist lives outside the repo)")
    rules = pii_scan.load_denylist(deny)
    assert rules, "denylist is empty"
    hits = [f.render() for f in pii_scan.scan_text(raw, "demo_case.json", rules) if f.rule == "denylist"]
    assert not hits, hits


def test_fixture_emails_are_fictional_or_generic_role_aliases(raw):
    emails = set(pii_scan.EMAIL_RE.findall(raw))
    assert emails, "expected at least the demo investigator / victim addresses"
    bad = sorted(e for e in emails if not pii_scan.email_allowed(e))
    assert not bad, bad
    for e in emails:
        local, domain = e.lower().split("@")
        assert domain.endswith(".example") or local in {"compliance", "legal", "abuse"}, e


def test_fixture_passes_generic_pii_rules(raw):
    assert pii_scan.scan_text(raw, "demo_case.json") == []


def test_fixture_uses_the_fixed_demo_identities(data):
    c = data["case"]
    assert c["reference"] == "DEMO-2026-001"
    assert c["title"] == "Exempla Holding AG impersonation — crypto investment fraud (demo case)"
    assert (c["victim_name"], c["victim_entity"], c["victim_jurisdiction"]) == (
        "Jordan Avery", "Northbridge Analytics, Inc.", "USA")
    f = c["facts"]
    assert f["investigator"]["firm"] == "Kestrel Ridge Investigations GmbH"
    assert f["investigator"]["authority_instrument"] == "Power of Attorney"
    assert f["investigator"]["phone"] == "+41 00 000 00 00"
    assert f["victim_contact"]["email"] == "victim@northbridge.example"
    assert f["domains"] == ["exempla-holding.example"]
    assert {x["reference"] for x in f["complaints"]} == {"DEMO-IT-0000000000", "IC3-DEMO-00000000"}
    # the complaint's filing time is a demo value too
    assert {x["filed_at"] for x in f["complaints"]} == {"2026-10-14T09:30:00+02:00", None}
    assert c["loss_amount"] == "399247.92" and c["loss_asset"] == "USDC"


def test_resolved_placeholders_are_gone_and_real_pending_ones_remain(raw):
    for gone in ("ORIGIN_TX_PENDING", "VICTIM_WALLET_PENDING", "USDC_RECEIVER_PENDING"):
        assert gone not in raw
    assert "USDT_DEST_PENDING" in raw


def test_origin_transfer_and_relays(data):
    tr = data["transfers"]
    origin = next(t for t in tr if t["tx_hash"] == "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814")
    assert origin["from"] == "0x7AC32c88e5489B4c406fFc1d6B835f4EBa7B455b"
    assert origin["to"] == "0x57de1021A507d46272d386995d5B58667Ac1F8df"
    assert (origin["amount"], origin["asset"], origin["timestamp"], origin["source"]) == (
        "399247.92", "USDC", "2026-10-12T10:49:47Z", "manual")
    assert origin["confidence"] >= 0.9 and "verify on-chain" in origin["notes"]

    relays = [t for t in tr if t["tx_hash"].startswith("ASSERTED:relay")]
    path = [relays[0]["from"].lower()] + [t["to"].lower() for t in relays]
    assert [a[:6] for a in path] == ["0x57de", "0x3007", "0x0d0b", "0xba02", "0xe944"]
    assert all(t["asset"] == "USDC" and t["amount"] == "399247.92" for t in relays)
    # provenance: the victim's statement, not the investigator's reports; hashes still pending
    assert all(t["source"] == "manual" and t["confidence"] < 1 and "Victim statement" in t["notes"] for t in relays)
    assert relays[-1]["timestamp"] == "2026-10-12T11:07:35Z"
    # the old ETH 'swap' guess into 0xe944 is gone
    assert not any(t["tx_hash"] == "ASSERTED:usdc-receiver->e944" for t in tr)

    addrs = {a["address"].lower(): a for a in data["addresses"]}
    e944 = addrs["0xe9449ba33c8dcf6f859c9bc476b8debab64a4b1b"]
    assert e944["address_type"] == "perpetrator" and "entity" not in e944


def test_no_named_vasp_contacts(data):
    for e in data["entities"]:
        mail = e.get("compliance_email")
        if mail:
            assert re.match(r"^(compliance|legal|abuse)@", mail), (e["name"], mail)
        # no personal mailbox survives in the free-text notes either
        for field in ("le_contact_notes", "notes"):
            assert not pii_scan.EMAIL_RE.search(e.get(field) or ""), (e["name"], field)


# --------------------------------------------------------------------------- workspace sections
SWFT_ORDER = "demo0swf_t000_0000_0000_000000000001"  # demo swap-order reference
PI_FIRM = "Kestrel Ridge Investigations GmbH"  # the investigating firm advising on the case (never a letter's sender)
SENDER = "Athena Software Group, Inc. <investigations@athena-demo.example>"
OPENING = ("We write as Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery), USA, the "
           "victim of a cryptocurrency investment fraud on 12 October 2026")
SIGNATURE = ("Yours faithfully,\n\nAthena Investigations\n\nAthena Software Group, Inc., on behalf of Northbridge "
             "Analytics, Inc. (Jordan Avery)\n\ninvestigations@athena-demo.example\n\n")
# The six demo letters logged as sent on 18.10.2026 (demo send times), with the chain references each one cites.
SENT_LETTERS = {
    "Hostinger": ("2026-10-18T22:02:41Z", []),
    "Supabase": ("2026-10-18T22:09:17Z", []),
    "Groq": ("2026-10-18T22:18:53Z", []),
    "KuCoin": ("2026-10-18T22:27:06Z", [
        "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2",
        "0x45300136662dD4e58fc0DF61E6290DFfD992B785",
        "0x580d3a804899ca7e084af17c13ecd2cb7af781e15572a62eaf604ff056c30293",
        "0x0c3593c8a9677fb107e765c8597ba3239074f0fa4173cb09f7a1128d05a5ad4e",
        "0xe5351383dcb18c14c3a7c1b9674c6dd501e0a8ed",
        "0x25018daA80887E133ee16a0070986dD8D4De57E3",
        "0x141D9aef573051c277676124a468223484077673",
        "0x9D4790695ec9CDC6DBe72aB5dd71158793dC391d",
        "0x693B36F71E3210Fde2C8A8c194648AC5A9Be3fBA",
        "block 26190041", "0.05683880584988242 ETH", "0.056837853652636425 ETH",
        "12.09, 18.09, 05.10 and 06.10.2026",
    ]),
    "Rainbet": ("2026-10-18T22:33:38Z", [
        "0x74e697c26f0ce168849411c53707ae689de10d5b",
        "0x307576Dd4F73f91BB8c4A2EdB762938E8e067d31",
        "09.10, 11.10 and 12.10 at 09:43 UTC",
    ]),
    "SWFT / Bridgers": ("2026-10-18T22:41:12Z", [
        SWFT_ORDER,
        "0xfda766545c41b900ce5ccee9f0c7b1a2318ba1186b741101b9ab47f4c3fa038c",
        "0x2b9ce18c974dce7166bf6e48dcd1c7e7c16baece43adb242d8b1dc4361aeb196",
        "0x1a456698F53732efe57503C867b2D1762F8dbf9E",
        "0xA2F14fe2965766F93e927C09729711133e8EeeFF",
        "0xc1d13492285eb664951E201BF7C80c7c6318a1b5",
        "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77",
        "705f713545499afc5860f45d1be2c40413a8d813d28f268fb203b3ead818ea67",
        "1,359.899028 USDT",
        "bc1pxnd9wrqg5yk4h4nvxmr5nmr4hne5yfpt4s6ec5hrm6ad9y9yv5jqsfknzn",
        "9e573f03585ce4647fbdeeb351bd6b95c154a49d42957ad68f19e34db5137897",
        "0.012836 BTC",
    ]),
}


@pytest.fixture(scope="module")
def letters(data) -> dict[str, dict]:
    return {o["entity"]: o for o in data["stop_orders_imported"]}


def test_six_imported_letters_with_their_send_times(data, letters):
    assert len(data["stop_orders_imported"]) == 6
    assert set(letters) == set(SENT_LETTERS)
    assert len({o["key"] for o in letters.values()}) == 6
    entity_names = {e["name"] for e in data["entities"]}
    for name, o in letters.items():
        assert o["entity"] in entity_names, name
        assert o["sent_at"] == SENT_LETTERS[name][0], name
        sent, due = (datetime.fromisoformat(o[k].replace("Z", "+00:00")) for k in ("sent_at", "response_due_at"))
        assert due - sent == timedelta(hours=72), name  # the team's 72-hour follow-up target
        assert (o["status"], o["origin"], o["kind"], o["sent_via"]) == ("sent", "imported", "preservation", "email")
        assert o["sender"] == SENDER, name  # one sender throughout: the case's sender of record
        assert o["log_correspondence"] is True and o["classification"] == "R3"


def test_imported_letters_cite_their_chain_references_in_full(letters, data):
    known_addresses = {a["address"].lower() for a in data["addresses"]}
    for name, (_, refs) in SENT_LETTERS.items():
        body = letters[name]["body_markdown"]
        for ref in refs:
            assert ref in body, (name, ref)
        for addr in letters[name]["identifiers"].get("addresses", []):
            assert addr in body and addr.lower() in known_addresses, (name, addr)
        for tx in letters[name]["identifiers"].get("tx_hashes", []):
            assert tx in body, (name, tx)
    assert letters["SWFT / Bridgers"]["identifiers"]["order_ids"] == [SWFT_ORDER]


def test_imported_letters_use_the_demo_identities(letters):
    for name, o in letters.items():
        body, subject = o["body_markdown"], o["subject"]
        assert body.startswith("Dear Compliance / Legal Team,\n"), name
        assert re.findall(r"^Dear .*$", body, re.MULTILINE) == ["Dear Compliance / Legal Team,"], name
        for fixed in ("Jordan Avery", "Northbridge Analytics, Inc.", "Exempla Holding AG", "exempla-holding.example",
                      '"Adrian Example, CFO"', "DEMO-IT-0000000000", OPENING, SIGNATURE,
                      "acting under the victim's Letter of Authorisation (attached)", "- Letter of Authorisation\n"):
            assert fixed in body, (name, fixed)
        # the sender of record signs, as every follow-up Aegis drafts does: no second sender in the story
        for other in (PI_FIRM, "Mara Lindqvist", "kestrel-ridge", "Power of Attorney", "+41 00 000 00 00",
                      "is a private investigations and intelligence firm"):
            assert other not in body, (name, other)
        # the only domain a subject may name is the demo impersonation domain
        assert set(re.findall(r"\(([\w.-]+\.[a-z]+)\)", subject)) <= {"exempla-holding.example"}, name
        assert pii_scan.scan_text(body + "\n" + subject, name) == [], name
        # e-mails: fictional (.example) or generic role aliases at the service's own domain
        for e in pii_scan.EMAIL_RE.findall(body + " " + " ".join(o["recipient_cc"]) + " " + (o["recipient_email"] or "")):
            local, domain = e.lower().split("@")
            assert domain.endswith(".example") or local in {"compliance", "legal", "abuse"}, (name, e)
    for name in ("Groq", "Supabase"):
        assert letters[name]["subject"].endswith("(exempla-holding.example)")
    # attacker infrastructure: demo values only
    infra = letters["Groq"]["body_markdown"] + letters["Supabase"]["body_markdown"]
    assert "demo0000project" in infra and "gsk_DEMO…" in infra and "index-DEMO0000.js" in infra
    assert not re.search(r"gsk_[A-Za-z0-9]{5,}|eyJ[A-Za-z0-9_-]{6,}", infra)


def test_demo_letter_defect_and_follow_ups_are_flagged(letters):
    """The demo's letters carry one demo defect and a follow-up (the "Known defect" / "Follow-up" panels): notes say
    what to do next, in plain words."""
    hostinger = letters["Hostinger"]
    assert hostinger["notes"].startswith("KNOWN DEFECT (demo):") and "FOLLOW-UP:" in hostinger["notes"]
    assert "FOLLOW-UP:" in letters["Groq"]["notes"]
    assert sum("KNOWN DEFECT" in o["notes"] for o in letters.values()) == 1
    for name, o in letters.items():
        assert "response_due_at" not in o["notes"], name  # no field names in user text
        assert "case vault" not in o["notes"] + json.dumps(o["identifiers"]), name  # notes name no other record
        assert "- Forensic report on the domain\n" in o["body_markdown"], name


def test_named_vasp_contacts_never_appear_as_recipients(letters):
    assert letters["Rainbet"]["recipient_email"] == "compliance@rainbet-demo.example"
    for name, o in letters.items():
        if o["recipient_email"] is None:
            assert "Compliance / Legal Team" in o["identifiers"]["recipient"], name
        assert "victim@northbridge.example" in o["recipient_cc"], name
        assert not [c for c in o["recipient_cc"] if "kestrel-ridge" in c], name


def test_one_sender_and_an_authorisation_that_predates_the_letters(data):
    """The demo story has one sender: the sender profile (Athena Investigations), the six letters, the notes and the
    reply all name it; the Letter of Authorisation it acts under is dated before the letters went out."""
    profile = data["sender_profile"]
    assert profile["signatory_name"] == "Athena Investigations" and profile["instrument"] == "Letter of Authorisation"
    loa = next(e for e in data["evidence"] if e["title"] in profile["authority_evidence_titles"])
    first_sent = min(o["sent_at"] for o in data["stop_orders_imported"])
    assert loa["doc_date"] < first_sent and loa["doc_date"][:10] in loa["inline_text"]
    for c in data["correspondence"]:
        assert "kestrel-ridge" not in json.dumps(c), c["key"]
    ack = next(c for c in data["correspondence"] if c["key"] == "rainbet-autoack-1")
    assert ack["recipients"] == ["investigations@athena-demo.example"]


def test_labels_and_notes_carry_no_dev_text(data, raw):
    labels = [a.get("label") or "" for a in data["addresses"]]
    assert "Peel wallet (investigator reports: 'scammers' wallet')" in labels
    assert not [x for x in labels if "\\" in x or "tokentx" in x]
    notes = " ".join(t.get("notes") or "" for t in data["transfers"])
    for dev in ("tokentx", "wei on live run", "first pass", "Resolve.", "Resolve by our own", "the PI's"):
        assert dev not in notes, dev


def test_demo_team_without_passwords(data):
    roles = {m["email"]: m["role"] for m in data["team"]}
    assert {
        "case.admin@aegis.example": "admin", "mara.lindqvist@kestrel-ridge.example": "investigator",
        "admin@northbridge.example": "admin", "viewer@northbridge.example": "read_only",
        "analyst@aegis.example": "read_only", "liaison@le-demo.example": "external",
    } == roles  # one member per role on each side: no overlapping demo analysts / LE officers
    for m in data["team"]:
        assert not {k for k in m if "password" in k} - {"password_env"}, m["email"]
        assert m["password_env"].startswith("AEGIS_DEMO_") and m["password_env"].endswith("_PASSWORD")
        if m["role"] == "external":  # time-boxed relative to the seed, within the 90-day maximum
            assert 0 < int(m.get("expires_in_days") or 0) <= 90 and not m.get("expires_at"), m["email"]


def test_le_contacts_are_fictional(data):
    agencies = {c["agency"] for c in data["le_contacts"]}
    assert "FBI Internet Crime Complaint Center (IC3)" in agencies
    assert "Carabinieri — Demo City station (demo)" in agencies
    assert any("prosecutor" in a for a in agencies)
    for c in data["le_contacts"]:
        assert c["name"] is None and c["phone"] is None
        assert c["reference"] in {"DEMO-IT-0000000000", "IC3-DEMO-00000000"}


def test_correspondence_threads_and_synthetic_ack(data):
    keys = {o["key"] for o in data["stop_orders_imported"]}
    items = {c["key"]: c for c in data["correspondence"]}
    for c in items.values():
        assert c.get("stop_order_key") in keys | {None}, c["key"]
        assert c.get("in_reply_to_key") in set(items) | {None}, c["key"]
    ack = items["rainbet-autoack-1"]
    assert (ack["entity"], ack["direction"], ack["kind"], ack["status"]) == ("Rainbet", "in", "reply", "received")
    assert ack["occurred_at"].startswith("2026-10-19") and ack["stop_order_key"] == "rainbet-preservation-1"
    assert ack["meta"]["synthetic"] is True and "SYNTHETIC DEMO MESSAGE" in ack["body_markdown"]
    assert any(c["direction"] == "note" for c in items.values())


def test_evidence_points_at_the_synthetic_demo_files(data):
    files = {e["meta"]["demo_file"] for e in data["evidence"]}
    assert files == {f"data/fixtures/demo_evidence/{n}" for n in ("chat_excerpt.txt", "ic3_receipt.txt",
                                                                  "police_receipt.txt", "meeting_transcript.txt",
                                                                  "letter_of_authorisation.txt")}
    for e in data["evidence"]:
        assert e["storage"] in {"inline", "reference"} and e["meta"]["synthetic"] is True
        assert not e.get("source_path") or not Path(e["source_path"]).is_absolute()  # nothing outside the repo


def test_notification_rules_cover_every_event_type(data):
    from app.core.events import EVENT_TYPES

    types = [r["event_type"] for r in data["notification_rules"]]
    assert len(types) == len(set(types)) and set(types) == set(EVENT_TYPES)


def test_demo_letters_seed_as_imported_stop_orders(db, case):
    from app.db.models import CorrespondenceDirection, StopOrderOrigin

    imported = {o.identifiers["fixture_key"]: o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED}
    assert len(imported) == 6
    kucoin = imported["kucoin-preservation-1"]
    assert kucoin.entity.name == "KuCoin" and kucoin.status.value == "sent"
    from conftest import shifted  # the seeded copy's workspace clock (conftest.FIXTURE_SHIFT)

    assert kucoin.sent_at.isoformat().startswith(shifted("2026-10-18T22:27:06Z").isoformat()[:19])
    assert all(len([c for c in o.correspondence if c.direction == CorrespondenceDirection.OUT]) == 1
               for o in imported.values())
    ack = next(c for c in case.correspondence if (c.meta or {}).get("fixture_key") == "rainbet-autoack-1")
    assert ack.stop_order is imported["rainbet-preservation-1"]
    assert len(case.evidence_items) >= 3 and len(case.le_contacts) == 3
