"""Tests for Proton SRP, using vectors from Proton's own client libraries."""

from __future__ import annotations

import base64
import json
import secrets

import pytest

from custom_components.proton_calendar.proton import srp

from .conftest import load_fixture_text

# From ProtonMail/proton-python-client (proton/srp/testdata.py)
VERIFIER_VECTORS = [
    {
        "Password": "test",
        "Modulus": "1B64DF29DEDD8656245DB7EEE751442AD9CF1DAFC5A71A94076385C2FBF9FA7AD63E94CB365EC94EBA5BE131CF63D3930CAC4755DE6D0625C24DD9A906551D216601222EBA94FF50C78B8B26DBF27636F4019F1700BA091287462CFFAD4F88B22D66BBF8993090865E46D077ECF1DB78CB2AB0D036AD786B046B5D93BD473C95779914CB93F607FD7EFB9D34161951263CE794BF181FB301EE444D170999EAFF9427CC4151BD91A755F1A184009C1418B16EEC7BFC2D5F88D42B38A4CC176B73EAB132FE37DD7E1162DCA1D13E81A6F10F090DE77EB8CC492CD0B19BB6FC151F5B4AD56B14308D582D86471390C4223400AEE3D5E94C973FB997D59F8A9F309F",
        "Verifier": "rhmWw1f4YsGq/cVgIePVSaot9Zj2kGNLxIgPytirz9/Nd8X8a28ZvFnWMQD0Jj8IgJPfO4EsI2nU5NuFqIbPI4OKs6s0nWvEHXkdtzxT1n451MGThvZ6o7I+0Ofi1Dh6Rgkv3MxVL/6cNev3EDyhcvh5w9hUIOk5OfRDcFMKv8ht5OYI5a/++m1++x58LQyrrTsRMMIcvDFXsjmMj4Ch3leP02S56cxDl6IQTosU+JcXGHsgNDf90aDnlsDFMGt6As1FSQm8bw0Yat+P02IZrXURQKsMLOKxdwb8xWySVymXAyjcJ7Z9ZabGjCX6Lelo9Wiz0hIEGE7nnOeVwzJKaA==",
        "Salt": "Jl54BOeNTVl8Ng==",
    },
]

# From ProtonMail/go-srp (srp_test.go)
GO_SRP_SIGNED_MODULUS = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----"""


@pytest.mark.parametrize("vector", VERIFIER_VECTORS)
def test_password_hash_matches_proton_verifier(vector: dict[str, str]) -> None:
    modulus = bytes.fromhex(vector["Modulus"])
    hashed = srp.hash_password(
        4, vector["Password"].encode(), base64.b64decode(vector["Salt"]), modulus
    )
    n = int.from_bytes(modulus, "little")
    verifier = pow(2, int.from_bytes(hashed, "little"), n).to_bytes(256, "little")
    assert base64.b64encode(verifier).decode() == vector["Verifier"]


def test_signed_modulus_from_go_srp() -> None:
    assert len(srp.read_modulus(GO_SRP_SIGNED_MODULUS)) == 256


def test_live_signed_modulus() -> None:
    signed = json.loads(load_fixture_text("proton_modulus.json"))["Modulus"]
    assert len(srp.read_modulus(signed)) == 256


def test_tampered_modulus_is_rejected() -> None:
    tampered = GO_SRP_SIGNED_MODULUS.replace("W2z5HBi8", "W2z5HBi9")
    with pytest.raises(srp.SRPError):
        srp.read_modulus(tampered)


def test_unsupported_auth_version() -> None:
    with pytest.raises(srp.SRPError):
        srp.hash_password(2, b"pw", b"salt", b"\x00" * 256)


def test_handshake_against_simulated_server() -> None:
    """Run the server side of SRP-6a and check both proofs agree."""
    password = b"correct horse battery staple"
    salt = secrets.token_bytes(10)
    modulus_bytes = srp.read_modulus(GO_SRP_SIGNED_MODULUS)
    n = int.from_bytes(modulus_bytes, "little")
    x = int.from_bytes(srp.hash_password(4, password, salt, modulus_bytes), "little")
    v = pow(2, x, n)
    k = int.from_bytes(srp.expand_hash((2).to_bytes(256, "little") + modulus_bytes), "little") % n
    b = secrets.randbelow(n - 2) + 1
    server_ephemeral = ((k * v + pow(2, b, n)) % n).to_bytes(256, "little")

    proofs = srp.generate_proofs(
        4,
        password,
        base64.b64encode(salt).decode(),
        GO_SRP_SIGNED_MODULUS,
        base64.b64encode(server_ephemeral).decode(),
    )

    a_int = int.from_bytes(proofs.client_ephemeral, "little")
    u = int.from_bytes(srp.expand_hash(proofs.client_ephemeral + server_ephemeral), "little")
    shared = pow(a_int * pow(v, u, n), b, n).to_bytes(256, "little")
    expected_client_proof = srp.expand_hash(proofs.client_ephemeral + server_ephemeral + shared)
    assert proofs.client_proof == expected_client_proof
    assert proofs.expected_server_proof == srp.expand_hash(
        proofs.client_ephemeral + expected_client_proof + shared
    )


def test_mailbox_password_shape() -> None:
    passphrase = srp.mailbox_password(b"password", b"0123456789abcdef")
    assert len(passphrase) == 31
    assert passphrase == srp.mailbox_password(b"password", b"0123456789abcdef")
    assert passphrase != srp.mailbox_password(b"password", b"fedcba9876543210")
