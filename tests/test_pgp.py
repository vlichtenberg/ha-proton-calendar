"""Tests for the minimal OpenPGP implementation, using GnuPG-generated fixtures."""

from __future__ import annotations

import pytest

from custom_components.proton_calendar.proton import pgp

from .conftest import load_fixture_bytes, load_fixture_text

PASSPHRASE = b"test-pass"


def _new_packet(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 192:
        header = bytes([length])
    elif length < 8384:
        length -= 192
        header = bytes([(length >> 8) + 192, length & 0xFF])
    else:
        header = b"\xff" + len(body).to_bytes(4, "big")
    return bytes([0xC0 | tag]) + header + body


def test_unlock_ecc_key() -> None:
    keys = pgp.unlock_keys(load_fixture_text("ecc_secret.asc"), PASSPHRASE)
    assert {k.algo for k in keys} == {pgp.ALGO_EDDSA_LEGACY, pgp.ALGO_ECDH}
    assert all(k.unlocked for k in keys)


def test_wrong_passphrase_is_rejected() -> None:
    with pytest.raises(pgp.PGPError):
        pgp.unlock_keys(load_fixture_text("ecc_secret.asc"), b"nope")


def test_decrypt_ecc_message() -> None:
    keys = pgp.unlock_keys(load_fixture_text("ecc_secret.asc"), PASSPHRASE)
    plain = pgp.decrypt_message(load_fixture_text("ecc_message.asc"), keys)
    assert plain == b"BEGIN:VCALENDAR\r\nhello ecc\r\nEND:VCALENDAR\r\n"


def test_decrypt_rsa_message() -> None:
    keys = pgp.unlock_keys(load_fixture_text("rsa_secret.asc"), PASSPHRASE)
    assert pgp.decrypt_message(load_fixture_text("rsa_message.asc"), keys) == b"hello rsa"


def test_decrypt_with_wrong_key_fails() -> None:
    keys = pgp.unlock_keys(load_fixture_text("rsa_secret.asc"), PASSPHRASE)
    with pytest.raises(pgp.PGPError):
        pgp.decrypt_message(load_fixture_text("ecc_message.asc"), keys)


def test_decrypt_split_message_with_partial_lengths() -> None:
    """Proton stores key packet and data packet separately (like event parts)."""
    keys = pgp.unlock_keys(load_fixture_text("ecc_secret.asc"), PASSPHRASE)
    packets = pgp.parse_packets(load_fixture_bytes("ecc_large.gpg"))
    assert [p.tag for p in packets] == [pgp.TAG_PKESK, pgp.TAG_SEIPD]
    plain = pgp.decrypt_split(
        _new_packet(pgp.TAG_PKESK, packets[0].body),
        _new_packet(pgp.TAG_SEIPD, packets[1].body),
        keys,
    )
    assert plain == load_fixture_bytes("large_plain.txt")


def test_tampered_ciphertext_is_detected() -> None:
    keys = pgp.unlock_keys(load_fixture_text("ecc_secret.asc"), PASSPHRASE)
    packets = pgp.parse_packets(load_fixture_bytes("ecc_large.gpg"))
    body = bytearray(packets[1].body)
    body[500] ^= 0x01
    with pytest.raises(pgp.PGPError):
        pgp.decrypt_split(
            _new_packet(pgp.TAG_PKESK, packets[0].body),
            _new_packet(pgp.TAG_SEIPD, bytes(body)),
            keys,
        )


def test_verify_cleartext() -> None:
    text = pgp.verify_cleartext(
        load_fixture_text("ecc_clearsigned.asc"), load_fixture_text("ecc_public.asc")
    )
    assert text == "line one  \n- dash line\nlast"


def test_verify_cleartext_rejects_tampering() -> None:
    signed = load_fixture_text("ecc_clearsigned.asc").replace("last", "lost")
    with pytest.raises(pgp.PGPError):
        pgp.verify_cleartext(signed, load_fixture_text("ecc_public.asc"))
