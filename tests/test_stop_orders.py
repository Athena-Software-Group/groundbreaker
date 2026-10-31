"""Stop-order letters generated from the demo case: content rules and candidate selection."""

from collections import Counter

import pytest
from conftest import ungated
from docx import Document
from sqlalchemy import select

from app.db.models import Address, Entity, StopOrderStatus
from app.reports.stop_orders import _fmt_amt, to_docx
from app.services import generate_stop_orders, latest_run, run_trace
from app.tracing.freeze import freeze_candidates

ROOT = "0x57de1021A507d46272d386995d5B58667Ac1F8df"  # checksum form, as the victim's records give it
HUB = "0x54453e25e38b11009963361a123bde2b4457becb"
ATHENA_BLOCK = "Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)"


def _run(db, case):
    return latest_run(db, case) or run_trace(db, case, provider_mode="fixture")


@pytest.fixture
def letters(db, case, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "case-desk@aegis.example")  # the profile's contact = the case mailbox
    with ungated():  # a letter to every candidate (the demo already asked some: the rendering is under test)
        orders = generate_stop_orders(db, case, _run(db, case))
    return {o.identifiers["entity"]: o for o in orders}


def test_one_letter_per_custodial_counterparty(letters):
    assert set(letters) == {
        "Circle (USDC issuer)", "Tether (USDT issuer)", "Rainbet", "KuCoin", "SWFT / Bridgers",
    }


def test_non_custodial_router_gets_no_letter(db, case):
    cands = freeze_candidates(db, _run(db, case))
    assert not [c for c in cands if c.category == "dex"]
    assert "Uniswap (Universal Router)" not in {c.entity_name for c in cands}


def test_regenerating_keeps_one_active_draft_per_entity(db, case):
    run = _run(db, case)
    generate_stop_orders(db, case, run)
    generate_stop_orders(db, case, run)
    db.refresh(case)
    drafts = Counter(o.identifiers["entity"] for o in case.stop_orders if o.status == StopOrderStatus.DRAFT)
    assert drafts["Tether (USDT issuer)"] == 1
    assert all(n == 1 for n in drafts.values()), drafts


def test_issuer_owned_address_is_folded_into_the_issuer_letter(db, case):
    """An address of the issuer's own on the path must not produce a second issuer letter."""
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    peel = db.scalar(select(Address).where(Address.address == "0xb9316bccc3ce126b0686470250e2d8c0bae775b9"))
    assert peel.entity_id is None
    peel.entity = tether
    db.commit()
    try:
        cands = freeze_candidates(db, run_trace(db, case, provider_mode="fixture"))
        tether_cands = [c for c in cands if c.entity_name == tether.name]
        assert len(tether_cands) == 1
        addrs = {i.address for i in tether_cands[0].identifiers}
        assert {peel.address, "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"} <= addrs
        assert tether_cands[0].kind == "issuer_blacklist"
    finally:
        peel.entity = None
        db.commit()
        run_trace(db, case, provider_mode="fixture")  # leave a clean latest run for other tests


def test_letters_use_demo_parties_and_cite_the_true_root(letters):
    for name, o in letters.items():
        body = o.body_markdown
        # the demo case has a sender profile: Athena writes on behalf of the victim (app.domain.sender)
        assert ATHENA_BLOCK in body and "Athena Investigations" in body and "case-desk@aegis.example" in body, name
        assert "Kestrel Ridge Investigations GmbH" not in body and "Mara Lindqvist" not in body, name
        assert "DEMO-IT-0000000000" in body and "IC3-DEMO-00000000" in body, name
        # the perpetrators' first-recipient wallet is 0x57de…, never the distribution hub
        assert f"`{ROOT}`, the perpetrators' first-recipient wallet" in body, name
        assert f"perpetrators' wallet `{HUB}`" not in body, name
        assert "Letter of Authorisation" in body and "Power of Attorney" not in body, name


def test_asserted_links_are_never_stated_as_fact(letters):
    for name, o in letters.items():
        assert "ASSERTED:" not in o.body_markdown, name
    # Rainbet's only tainted inbound is an asserted hop; SWFT and Tether hang off one
    for name in ("Rainbet", "SWFT / Bridgers", "Tether (USDT issuer)"):
        assert "suspected" in letters[name].subject.lower(), name
    assert "*Asserted*, not yet observed on-chain" in letters["Rainbet"].body_markdown
    assert "not a confirmed share of the loss" in letters["SWFT / Bridgers"].body_markdown
    # KuCoin's deposit is reached by observed transfers below the (amount-known) relay hops
    assert "suspected" not in letters["KuCoin"].subject.lower()
    # pre-fraud deposits at the KuCoin account come from the investigator's analysis only
    assert "According to our analysis (*asserted*" in letters["KuCoin"].body_markdown
    # the issuer letter does not claim the stablecoin is still held
    assert "held in" not in letters["Circle (USDC issuer)"].subject


def test_amounts_keep_full_precision():
    assert _fmt_amt("1359.899028") == "1,359.899028"
    assert _fmt_amt("399247.92") == "399,247.92"
    assert _fmt_amt("0.056838805849882420") == "0.05683881"
    assert _fmt_amt(None) == "?"


def test_docx_metadata_is_neutral(letters, tmp_path):
    o = letters["KuCoin"]
    path = to_docx(o, tmp_path / "k.docx")
    doc = Document(path)
    props = doc.core_properties
    assert props.author == "Aegis" and props.last_modified_by == "Aegis"
    assert props.title == o.subject
    assert "python-docx" not in (props.comments or "") + (props.author or "")
    text = "\n".join(p.text for p in doc.paragraphs)
    assert ROOT in text and "*" not in text.replace("* * *", "")
    # text only: the stock template's thumbnail image is dropped, and the scanner passes the export
    import zipfile

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    assert not [n for n in names if not n.endswith((".xml", ".rels"))], names
    from scripts import pii_scan

    assert pii_scan.scan_file(path, "k.docx", []) == []
