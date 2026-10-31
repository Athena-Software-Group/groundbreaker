"""Local demo only: turn the newest e-mail in the file outbox into a synthetic reply in the inbox.

    python -m scripts.mail_demo_reply [--outbox DIR] [--inbox DIR]     # defaults: AEGIS_MAIL_OUTBOX_DIR / _INBOX_DIR

The reply comes From the original's first To address, goes To the case mailbox, answers its
Message-ID (In-Reply-To and References), is titled "RE: <subject>" and carries one small .txt
attachment. Nothing is sent anywhere: the file transport reads the inbox folder on the next sync
(`python -m scripts.mail_sync`, the scheduler, or "Check mailbox now").
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses, make_msgid

from app.mail.config import mail_settings
from app.mail.transport import TransportError, check_local_dir

BODY = "SYNTHETIC DEMO REPLY — we have placed a temporary hold; our ref DEMO-TKT-0000\n"
ATTACHMENT = b"Synthetic demo attachment: hold confirmation DEMO-TKT-0000 (no real data).\n"


def build_reply(original: bytes, *, now: datetime | None = None) -> bytes:
    msg = BytesParser(policy=policy.default).parsebytes(original)
    to = [a for _, a in getaddresses([str(msg.get("To") or "")]) if "@" in a]
    frm = [a for _, a in getaddresses([str(msg.get("From") or "")]) if "@" in a]
    mid = str(msg.get("Message-ID") or "").strip()
    if not to or not frm or not mid:
        raise ValueError("the outbox e-mail has no To, From or Message-ID")
    reply = EmailMessage()
    reply["From"] = to[0]
    reply["To"] = frm[0]
    reply["Subject"] = f"RE: {msg.get('Subject') or ''}".strip()
    reply["Date"] = format_datetime(now or datetime.now(tz=UTC))
    reply["Message-ID"] = make_msgid(idstring="demo-reply", domain=to[0].rpartition("@")[2])
    reply["In-Reply-To"] = mid
    reply["References"] = mid
    reply.set_content(BODY)
    reply.add_attachment(ATTACHMENT, maintype="text", subtype="plain", filename="demo-hold-confirmation.txt")
    return reply.as_bytes(policy=policy.SMTP)


def main(argv: list[str] | None = None) -> int:
    settings = mail_settings()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--outbox", default=settings.aegis_mail_outbox_dir)
    ap.add_argument("--inbox", default=settings.aegis_mail_inbox_dir)
    args = ap.parse_args(argv)
    try:
        outbox = check_local_dir(args.outbox, "--outbox")
        inbox = check_local_dir(args.inbox, "--inbox")
    except TransportError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    sent = sorted((p for p in outbox.glob("*.eml") if p.is_file() and not p.is_symlink()),
                  key=lambda p: (p.stat().st_mtime, p.name))
    if not sent:
        print("the outbox holds no .eml file yet: send a letter with AEGIS_MAIL_TRANSPORT=file first", file=sys.stderr)
        return 1
    try:
        raw = build_reply(sent[-1].read_bytes())
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    inbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = inbox / f"{datetime.now(tz=UTC):%Y%m%dT%H%M%SZ}_demo-reply.eml"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    print(f"wrote {target.name} to the inbox (reply to {sent[-1].name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
