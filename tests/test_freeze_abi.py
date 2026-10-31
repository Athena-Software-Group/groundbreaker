"""app.freeze.abi and the issuer registry: Keccak-256, selectors / topics against the published values, ABI
encoding and decoding, decimals, TRON base58 <-> hex, wallet validation (offline, no I/O)."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.freeze import abi, issuers, signals

USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_TRON_HEX = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"


def test_keccak256_known_vectors():
    assert abi.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # the ERC-20 Transfer topic every explorer prints
    assert abi.topic("Transfer(address,address,uint256)") == \
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    # a message longer than one 136-byte block
    assert len(abi.keccak256(b"x" * 500)) == 32 and abi.keccak256(b"x" * 500) != abi.keccak256(b"x" * 499)


@pytest.mark.parametrize("sig,expected", [
    ("isBlackListed(address)", "0xe47d6060"),
    ("getBlackListStatus(address)", "0x59bf1abe"),
    ("balanceOf(address)", "0x70a08231"),
    ("isBlacklisted(address)", "0xfe575a87"),
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("transferFrom(address,address,uint256)", "0x23b872dd"),
    ("approve(address,uint256)", "0x095ea7b3"),
])
def test_selectors(sig, expected):
    assert abi.selector(sig) == expected


def test_registry_selectors_and_topics():
    assert issuers.SEL_TETHER_IS_BLACKLISTED == "0xe47d6060" and issuers.SEL_TETHER_STATUS == "0x59bf1abe"
    assert issuers.SEL_CIRCLE_IS_BLACKLISTED == "0xfe575a87" and issuers.SEL_BALANCE_OF == "0x70a08231"
    assert issuers.TOPIC_ADDED_BLACKLIST == "0x42e160154868087d6bfdc0ca23d96a1c1cfa32f1b72ba9ba27b69b98a0d819dc"
    assert issuers.TOPIC_BLACKLISTED == abi.topic("Blacklisted(address)")
    assert set(signals.TOKEN_MOVES) == {"0xa9059cbb", "0x23b872dd", "0x095ea7b3"}


def _eip55(addr: str) -> str:
    h = abi.keccak256(addr[2:].lower().encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c.lower() for i, c in enumerate(addr[2:]))


def test_contract_registry():
    keys = {c.key for c in issuers.CONTRACTS}
    assert {"tether-usdt-ethereum", "tether-usdt-tron", "circle-usdc-ethereum"} <= keys
    eth_usdt = issuers.contract_by_id("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7")
    eth_usdc = issuers.contract_by_id("ethereum", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    assert eth_usdt.issuer == "Tether" and not eth_usdt.address_indexed and eth_usdt.status_selector == "0x59bf1abe"
    assert eth_usdc.issuer == "Circle" and eth_usdc.address_indexed and eth_usdc.blacklist_selector == "0xfe575a87"
    for c in issuers.CONTRACTS:
        assert c.decimals == 6
        if c.is_tron:
            assert abi.is_tron_address(c.contract)
        else:  # every EVM contract is written with a valid EIP-55 checksum (catches a mistyped character)
            assert c.contract == _eip55(c.contract), c.key
    assert issuers.contracts_for("tron", {"USDC"}) == []
    assert [c.symbol for c in issuers.contracts_for("ethereum")] == ["USDT", "USDC"]
    # entity names match the issuer levers of app/tracing/freeze.py
    from app.tracing.freeze import STABLECOIN_ISSUER

    assert set(issuers.ISSUER_ENTITY.values()) == set(STABLECOIN_ISSUER.values())


def test_encode_and_decode():
    who = bytes.fromhex("11" * 20)
    data = abi.encode_call("isBlackListed(address)", who)
    assert data == "0xe47d6060" + "0" * 24 + "11" * 20 and len(data) == 2 + 8 + 64
    assert abi.encode_call(issuers.SEL_BALANCE_OF, who).startswith("0x70a08231")
    assert abi.decode_bool("0x" + "0" * 63 + "1") is True and abi.decode_bool("0x" + "0" * 64) is False
    with pytest.raises(ValueError):
        abi.decode_bool("0x")  # empty return data (no such function / not a contract) is an error, not False
    with pytest.raises(ValueError):
        abi.decode_bool("0x" + "0" * 63 + "2")
    assert abi.decode_uint(hex(1_359_899_028)) == 1_359_899_028
    assert abi.word_address("0x" + "0" * 24 + "AB" * 20) == "0x" + "ab" * 20
    with pytest.raises(ValueError):
        abi.address_word(b"\x00" * 19)


def test_decimals():
    assert issuers.units(1_359_899_028, 6) == Decimal("1359.899028")
    assert issuers.units(0, 6) == 0
    assert issuers.units(10**6, 6) == Decimal(1)


def test_tron_address_conversion():
    assert abi.tron_to_hex(USDT_TRON) == USDT_TRON_HEX
    assert abi.hex_to_tron(USDT_TRON_HEX) == USDT_TRON
    assert abi.hex_to_tron("0x" + USDT_TRON_HEX[2:]) == USDT_TRON  # event results print 0x + 20 bytes
    assert abi.hex_to_tron("0x" + "0" * 24 + USDT_TRON_HEX[2:]) == USDT_TRON  # a padded word
    assert abi.tron_bytes(USDT_TRON).hex() == USDT_TRON_HEX[2:]
    assert abi.same_tron(USDT_TRON, "0x" + USDT_TRON_HEX[2:]) and not abi.same_tron(USDT_TRON, None)
    # round trip of a synthetic account
    synthetic = abi.hex_to_tron("41" + "22" * 20)
    assert synthetic.startswith("T") and abi.is_tron_address(synthetic) and abi.tron_to_hex(synthetic) == "41" + "22" * 20
    # the existing provider helper agrees
    from app.providers.tron import _hex_to_base58

    assert _hex_to_base58(USDT_TRON_HEX) == USDT_TRON
    bad = USDT_TRON[:-1] + ("u" if USDT_TRON[-1] != "u" else "v")
    assert not abi.is_tron_address(bad)  # checksum mismatch
    with pytest.raises(ValueError):
        abi.b58check_decode("0OIl")


def test_normalise_wallet():
    assert issuers.normalise_wallet("ethereum", " 0x" + "AB" * 20 + " ") == "0x" + "ab" * 20
    assert issuers.normalise_wallet("tron", USDT_TRON) == USDT_TRON
    for chain, bad in (("ethereum", "0x1234"), ("tron", "0x" + "ab" * 20), ("bitcoin", "bc1qxyz"),
                       ("ethereum", "ASSERTED_PENDING")):
        with pytest.raises(ValueError):
            issuers.normalise_wallet(chain, bad)


def test_eip55_checksum_of_watched_wallets():
    usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    assert abi.to_checksum(usdt.lower()) == usdt == _eip55(usdt)
    assert abi.checksum_ok(usdt) and abi.checksum_ok(usdt.lower()) and abi.checksum_ok("0x" + usdt[2:].upper())
    # one mistyped character in a mixed-case address breaks the checksum: refused, never checked as another wallet
    typo = usdt[:5] + ("8" if usdt[5] != "8" else "9") + usdt[6:]
    assert not abi.checksum_ok(typo)
    flipped = usdt[:3] + usdt[3].swapcase() + usdt[4:]  # same wallet, wrong casing
    assert not abi.checksum_ok(flipped)
    assert issuers.normalise_wallet("ethereum", usdt) == usdt.lower()
    with pytest.raises(ValueError, match="EIP-55"):
        issuers.normalise_wallet("ethereum", typo)
    with pytest.raises(ValueError, match="EIP-55"):
        issuers.normalise_wallet("base", flipped)
    assert issuers.normalise_wallet("ethereum", flipped, checksum=False) == usdt.lower()  # the trace's own rows
