"""Minimal ABI helpers for the issuer blacklist checks: Keccak-256, selectors, argument encoding,
result decoding and TRON address conversion. No third-party dependency (no web3 / eth-hash).

* `keccak256(b"isBlackListed(address)")[:4]` is the function selector (0xe47d6060); event topics are
  the full hash of the event signature. The selectors and topics in app/freeze/issuers.py are
  computed here and pinned against the published values in tests/test_freeze_abi.py.
* Keccak-256 is the original Keccak padding (0x01), not NIST SHA3-256 (0x06): `hashlib.sha3_256`
  gives a different digest.
* TRON addresses are base58check of 0x41 + the 20-byte account id; the ABI argument is the same
  20 bytes left-padded to 32, exactly as for an EVM address.
"""

from __future__ import annotations

import hashlib
import re

# --------------------------------------------------------------------------- Keccak-256
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum's hash) of `data`."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out[:32]


def selector(signature: str) -> str:
    """'isBlackListed(address)' -> '0xe47d6060'."""
    return "0x" + keccak256(signature.encode()).hex()[:8]


def topic(signature: str) -> str:
    """'AddedBlackList(address)' -> the event's topic0 (0x + 64 hex)."""
    return "0x" + keccak256(signature.encode()).hex()


# --------------------------------------------------------------------------- EVM encoding
_EVM_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def is_evm_address(value: str | None) -> bool:
    return bool(value) and bool(_EVM_RE.fullmatch(value.strip()))


def to_checksum(address: str) -> str:
    """The EIP-55 mixed-case form of an EVM address (0x + 40 hex)."""
    if not is_evm_address(address):
        raise ValueError("not an EVM address (0x + 40 hex)")
    h = address.strip()[2:].lower()
    digest = keccak256(h.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c for i, c in enumerate(h))


def checksum_ok(address: str) -> bool:
    """EIP-55: an all-lower-case or all-upper-case address carries no checksum (accepted); a mixed-case one
    must match its checksum exactly (a mistyped character almost always breaks it)."""
    if not is_evm_address(address):
        return False
    h = address.strip()[2:]
    if h == h.lower() or h == h.upper():
        return True
    return "0x" + h == to_checksum(address)


def address_word(address20: bytes) -> str:
    """A 20-byte account id as one 32-byte ABI word (64 hex, no 0x)."""
    if len(address20) != 20:
        raise ValueError("an address is 20 bytes")
    return address20.hex().rjust(64, "0")


def evm_bytes(address: str) -> bytes:
    if not is_evm_address(address):
        raise ValueError("not an EVM address (0x + 40 hex)")
    return bytes.fromhex(address.strip()[2:])


def encode_call(sig_or_selector: str, address20: bytes) -> str:
    """Call data of a one-address function: selector + the padded address."""
    sel = sig_or_selector if sig_or_selector.startswith("0x") else selector(sig_or_selector)
    return sel + address_word(address20)


def decode_uint(result: str | None) -> int:
    """A uint256 return value ('0x…' or bare hex). Empty data ('0x') is an error, not zero."""
    h = (result or "").strip()
    h = h[2:] if h.lower().startswith("0x") else h
    if not h or not re.fullmatch(r"[0-9a-fA-F]+", h):
        raise ValueError("empty or non-hex return data")
    return int(h[:64], 16)


def decode_bool(result: str | None) -> bool:
    v = decode_uint(result)
    if v not in (0, 1):
        raise ValueError("return data is not a bool")
    return v == 1


def word_address(word: str) -> str:
    """The last 20 bytes of a 32-byte word (a topic or a data word) as a lower-case 0x address."""
    h = word[2:] if word.lower().startswith("0x") else word
    return "0x" + h[-40:].lower()


# --------------------------------------------------------------------------- TRON addresses
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}
TRON_PREFIX = 0x41
_TRON_RE = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_IDX:
            raise ValueError("not base58")
        n = n * 58 + _B58_IDX[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        raise ValueError("too short")
    body, chk = raw[:-4], raw[-4:]
    if _sha256d(body)[:4] != chk:
        raise ValueError("bad base58check checksum")
    return body


def b58check_encode(body: bytes) -> str:
    data = body + _sha256d(body)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def is_tron_address(value: str | None) -> bool:
    if not value or not _TRON_RE.fullmatch(value.strip()):
        return False
    try:
        body = b58check_decode(value.strip())
    except ValueError:
        return False
    return len(body) == 21 and body[0] == TRON_PREFIX


def tron_to_hex(address: str) -> str:
    """'T…' base58 -> '41' + 40 hex (TronGrid's hex form, visible=false)."""
    body = b58check_decode(address.strip())
    if len(body) != 21 or body[0] != TRON_PREFIX:
        raise ValueError("not a TRON mainnet address")
    return body.hex()


def tron_bytes(address: str) -> bytes:
    """The 20-byte account id of a TRON address (what the ABI argument carries)."""
    return bytes.fromhex(tron_to_hex(address))[1:]


def hex_to_tron(value: str) -> str:
    """'41…' (42 hex), '0x…' (40 hex, as event results print it) or a padded word -> 'T…'."""
    h = value.strip().lower()
    h = h.removeprefix("0x")
    if len(h) == 42 and h.startswith("41"):
        body = bytes.fromhex(h)
    elif len(h) >= 40:
        body = bytes([TRON_PREFIX]) + bytes.fromhex(h[-40:])
    else:
        raise ValueError("not a TRON hex address")
    return b58check_encode(body)


def same_tron(a: str | None, b: str | None) -> bool:
    """Whether two TRON addresses in any of the forms above name the same account."""
    def norm(v: str | None) -> str | None:
        if not v:
            return None
        v = v.strip()
        try:
            return tron_to_hex(v if v.startswith("T") else hex_to_tron(v))
        except ValueError:
            return None

    na, nb = norm(a), norm(b)
    return na is not None and na == nb
