import logging
import re
import sys

# Applied to log *output* only (handler filter); stored case data is never altered.
_REDACTIONS: list[tuple[re.Pattern[str], object]] = [
    # key=value secrets in URLs / messages (Etherscan ?apikey=, tokens, passwords)
    (re.compile(r"(?i)\b(api[_-]?key|apikey|access[_-]?token|token|secret|password|passwd)=([^&\s\"',;]+)"),
     r"\1=***"),
    (re.compile(r"(?i)\b(authorization:\s*(?:basic|bearer)\s+)\S+"), r"\1***"),
    # OAuth form bodies and token responses (app/mail/graph.py client-credentials flow)
    (re.compile(r"(?i)\b(client_secret|client_assertion|refresh_token|access_token)=([^&\s\"',;]+)"), r"\1=***"),
    (re.compile(r"(?i)(\"(?:access_token|refresh_token|id_token|client_secret)\"\s*:\s*\")[^\"]+(\")"), r"\1***\2"),
    # JWT-shaped bearer tokens
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"), "eyJ***"),
    (re.compile(r"gsk_[A-Za-z0-9]{8,}"), "gsk_***"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
     lambda m: m.group(0)[0] + "***@***"),
    # EVM addresses / tx hashes, bare 64-hex (BTC/TRON tx ids), TRON base58, BTC bech32 / base58
    (re.compile(r"\b(?:0x[0-9a-fA-F]{16,}|[0-9a-fA-F]{32,}|T[1-9A-HJ-NP-Za-km-z]{33}|bc1[02-9ac-hj-np-z]{20,87}"
                r"|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b"),
     lambda m: m.group(0)[:6] + "…" + m.group(0)[-4:]),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    """Masks secrets, e-mail addresses and long hashes / addresses (to 6…4) in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple):
            # uvicorn's AccessFormatter unpacks args positionally: redact them in place
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        else:
            record.msg, record.args = redact(record.getMessage()), None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def install_redaction(*logger_names: str) -> None:
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", *logger_names):
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(RedactingFilter())


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    install_redaction()
