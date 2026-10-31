"""Scanner behaviour. Sample secrets/PII are assembled at runtime so this file itself scans clean."""

import io
import struct
import zipfile
import zlib

from scripts import pii_scan

GMAIL = "someone" + "@" + "gmail.com"
GROQ = "gsk" + "_" + "A1b2C3d4E5f6G7h8"
JWT = "ey" + "J" + "hbGciOiJIUzI1NiIs" + "InR5cCI6IkpXVCJ9"
PHONE = "+" + "1 202 555 01 23"


def _rules(findings):
    return sorted({f.rule for f in findings})


def test_flags_personal_email_phone_and_keys():
    text = f"mail {GMAIL}\ncall {PHONE}\nkey {GROQ}\ntoken {JWT}\n-----BEGIN RSA PRIVATE" + " KEY-----\n"
    found = pii_scan.scan_text(text, "x.txt")
    assert _rules(found) == ["api_key", "email", "jwt", "phone", "private_key"]
    assert {f.line for f in found} == {1, 2, 3, 4, 5}


def test_allows_fictional_and_role_addresses():
    text = (
        "victim@northbridge.example mara.lindqvist@kestrel-ridge.example a@example.com "
        "compliance@kucoin.com legal@hostinger.com abuse@supabase.com noreply@anthropic.com "
        "phone +41 00 000 00 00 at 2026-10-14T09:30:00+02:00 icon@2x.png gsk_DEMO…XXXX"
    )
    assert pii_scan.scan_text(text, "ok.txt") == []


def test_personal_mailbox_at_a_vasp_is_flagged():
    assert _rules(pii_scan.scan_text("someone" + "@kucoin.com", "x")) == ["email"]


def test_masking_keeps_only_edges():
    assert pii_scan.mask("abcdefgh") == "ab****gh"
    assert pii_scan.mask("abc") == "***"
    rendered = pii_scan.scan_text(GMAIL, "f.md")[0].render()
    assert GMAIL not in rendered and rendered.startswith("f.md:1:email: so")


def test_denylist_literals_and_regexes(tmp_path):
    deny = tmp_path / "deny.txt"
    deny.write_text("# comment\nAcme Secret Corp\nre:\\bZed\\b\n", encoding="utf-8")
    rules = pii_scan.load_denylist(deny)
    found = pii_scan.scan_text("hello acme secret corp\nzed\nzedd\n", "f", rules)
    assert [(f.line, f.rule) for f in found] == [(1, "denylist"), (2, "denylist")]


def test_docx_and_png_metadata_are_scanned(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", f"<w:document><w:p><w:r><w:t>{GMAIL}</w:t></w:r></w:p></w:document>")
        zf.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>" + "Acme Secret Corp" + "</dc:creator></cp:coreProperties>")
    docx = tmp_path / "letter.docx"
    docx.write_bytes(buf.getvalue())

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"tEXt", b"Author\x00" + GMAIL.encode()) + chunk(b"IEND", b""))

    rules = pii_scan.load_denylist(_write(tmp_path / "d.txt", "Acme Secret Corp\n"))
    d = pii_scan.scan_file(docx, "letter.docx", rules)
    assert {(f.path, f.rule) for f in d} == {("letter.docx[word/document.xml]", "email"),
                                              ("letter.docx[docProps/core.xml]", "denylist")}
    p = pii_scan.scan_file(png, "shot.png", [])
    assert [(f.path, f.rule) for f in p] == [("shot.png[png-text]", "email")]


def test_walk_honours_gitignore_and_scans_vendor(tmp_path):
    (tmp_path / ".gitignore").write_text("exports/\n*.db\n/secret.txt\n", encoding="utf-8")
    _write(tmp_path / "keep.md", "ok")
    _write(tmp_path / "secret.txt", GMAIL)
    _write(tmp_path / "a.db", GMAIL)
    _write(tmp_path / "exports" / "x.docx", GMAIL)
    _write(tmp_path / "app" / "web" / "static" / "vendor" / "lib.js", GMAIL)
    _write(tmp_path / "sub" / "secret.txt", "not anchored, so kept")
    files = pii_scan.candidate_files(tmp_path)
    assert sorted(files) == [".gitignore", "app/web/static/vendor/lib.js", "keep.md", "sub/secret.txt"]
    # vendored third-party code is scanned too
    found = pii_scan.scan(tmp_path, None, [])
    assert ("app/web/static/vendor/lib.js", "email") in {(f.path, f.rule) for f in found}


def test_repo_gitignore_reincludes_only_sample_letters(tmp_path):
    """The shipped-asset exceptions must not re-open the hard rules (last match wins in .gitignore)."""
    from pathlib import Path

    patterns = pii_scan._gitignore_patterns(Path(pii_scan.REPO_ROOT))
    blocked = [
        "brand/.env", "app/web/static/x.pem", "app/web/static/aegis.db", "docs/samples/denylist.txt",
        "docs/samples/denylist-extra.txt", "docs/samples/x.pdf", "brand/screenshot.png", "docs/samples/real.docx",
        "docs/samples/stop-orders/notes.docx", "data/fixtures/private_case.json", "app/x.sqlite3",
    ]
    assert [f for f in blocked if not pii_scan.is_ignored(f, False, patterns)] == []
    for d in ("docs/samples/evidence", "docs/samples/deliverables", "brand/vault", "app/exports"):
        assert pii_scan.is_ignored(d, True, patterns), d
    shipped = ["docs/samples/stop-orders/01-circle-blacklist.docx", "data/fixtures/demo_case.json",
               "brand/groundbreaker-mark-dark.svg", "app/web/static/graph.js", ".env.example"]
    assert [f for f in shipped if pii_scan.is_ignored(f, False, patterns)] == []


DENY = "Acme Secret Corp"


def _deny(tmp_path):
    return pii_scan.load_denylist(_write(tmp_path / "d.txt", DENY + "\n"))


def test_decoded_variants_are_scanned(tmp_path):
    rules = _deny(tmp_path)
    import base64
    import json

    svg_entities = "<svg><title>" + "".join(f"&#{ord(c)};" for c in DENY) + "</title></svg>"
    json_escaped = json.dumps({"n": DENY}, ensure_ascii=False).replace("A", "\\u0041")
    data_uri = "a{background:url(data:image/svg+xml;base64," + base64.b64encode(f"<svg>{DENY}</svg>".encode()).decode() + ")}"
    wrapped = "Acme Secret\n   Corp is mentioned here"
    for name, text in (("a.svg", svg_entities), ("a.json", json_escaped), ("a.css", data_uri), ("a.md", wrapped)):
        found = pii_scan.scan_text(text, name, rules)
        assert [f.rule for f in found] == ["denylist"], (name, found)
    assert pii_scan.scan_text(wrapped, "a.md", rules)[0].line == 1


def test_archives_and_pdfs_are_opened_and_fail_closed(tmp_path):
    rules = _deny(tmp_path)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes/a.txt", f"x {DENY} y")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested.zip", inner.getvalue())
    z = _write_bytes(tmp_path / "planted.zip", outer.getvalue())
    found = {(f.path, f.rule) for f in pii_scan.scan_file(z, "planted.zip", rules)}
    assert ("planted.zip[nested.zip][notes/a.txt]", "denylist") in found
    assert ("planted.zip", "forbidden_format") in found

    stream = zlib.compress(b"BT /F1 12 Tf 72 712 Td [(Acme) -250 ( Sec) 20 (ret Corp)] TJ ET")
    pdf = (b"%PDF-1.4\n1 0 obj << /Length " + str(len(stream)).encode() + b" /Filter /FlateDecode >>\nstream\n"
           + stream + b"\nendstream\nendobj\n%%EOF\n")
    pdf_path = _write_bytes(tmp_path / "planted.pdf", pdf)
    found = {(f.path, f.rule) for f in pii_scan.scan_file(pdf_path, "planted.pdf", rules)}
    assert found == {("planted.pdf[pdf]", "denylist"), ("planted.pdf", "forbidden_format")}

    # a forbidden format is a finding even when its content is clean; so is an unknown binary
    clean_pdf = _write_bytes(tmp_path / "clean.pdf", b"%PDF-1.4\n%%EOF\n")
    assert [f.rule for f in pii_scan.scan_file(clean_pdf, "clean.pdf", rules)] == ["forbidden_format"]
    blob = _write_bytes(tmp_path / "blob.bin", b"\x00\x01\x02" * 10)
    assert [f.rule for f in pii_scan.scan_file(blob, "blob.bin", rules)] == ["binary"]
    # renamed archive: dispatch is on magic bytes, not on the file name
    disguised = _write_bytes(tmp_path / "logo.svg", outer.getvalue())
    assert "denylist" in {f.rule for f in pii_scan.scan_file(disguised, "logo.svg", rules)}


def _write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_main_exit_codes(tmp_path, capsys):
    _write(tmp_path / "clean.md", "nothing here")
    assert pii_scan.main(["--root", str(tmp_path)]) == 0
    _write(tmp_path / "dirty.md", f"contact {GMAIL}")
    assert pii_scan.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "dirty.md:1:email:" in out and GMAIL not in out
    # directories given explicitly are expanded, not silently skipped
    _write(tmp_path / "nested" / "deep.txt", f"x {GMAIL}")
    assert pii_scan.main(["--root", str(tmp_path), str(tmp_path / "nested")]) == 1
    assert "nested/deep.txt:1:email:" in capsys.readouterr().out
    # a denylist inside the scanned tree is refused
    _write(tmp_path / "deny.txt", "x\n")
    assert pii_scan.main(["--root", str(tmp_path), "--denylist", str(tmp_path / "deny.txt")]) == 2


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
