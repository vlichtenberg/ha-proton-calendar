"""Proton's SRP-6a variant and password hashing (port of ProtonMail/go-srp)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import secrets

import bcrypt

from .pgp import PGPError, verify_cleartext

BIT_LENGTH = 2048
BYTE_LENGTH = BIT_LENGTH // 8

# Proton's public key used to sign SRP moduli (from go-srp).
MODULUS_PUBKEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
    "xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\n"
    "L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\n"
    "BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\n"
    "MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\n"
    "Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\n"
    "kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\n"
    "hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\n"
    "WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\n"
    "=Y4Mw\n"
    "-----END PGP PUBLIC KEY BLOCK-----"
)

_STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class SRPError(Exception):
    """Raised when the SRP handshake cannot be completed safely."""


def _bcrypt_b64(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=").translate(bytes.maketrans(_STD_B64, _BCRYPT_B64))


def _bcrypt(password: bytes, encoded_salt: bytes) -> bytes:
    # bcrypt only uses the first 72 bytes; newer bcrypt releases refuse longer input.
    hashed = bcrypt.hashpw(password[:72], b"$2y$10$" + encoded_salt[:22])
    # Same algorithm, but Proton hashes the "$2y$" prefix into the SRP secret.
    return b"$2y$" + hashed[4:]


def expand_hash(data: bytes) -> bytes:
    """Proton's 2048-bit hash: four SHA-512 digests with a counter suffix."""
    return b"".join(hashlib.sha512(data + bytes([i])).digest() for i in range(4))


def mailbox_password(password: bytes, key_salt: bytes) -> bytes:
    """Derive the passphrase that unlocks the user's private keys."""
    if not key_salt:
        return password
    return _bcrypt(password, _bcrypt_b64(key_salt))[-31:]


def hash_password(version: int, password: bytes, salt: bytes, modulus: bytes) -> bytes:
    """Hash the login password (auth versions 3 and 4 only)."""
    if version not in (3, 4):
        raise SRPError(
            f"Unsupported auth version {version}; log in once via the Proton web app to upgrade it"
        )
    crypted = _bcrypt(password, _bcrypt_b64(salt + b"proton"))
    return expand_hash(crypted + modulus)


def _to_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _from_int(value: int) -> bytes:
    return value.to_bytes(BYTE_LENGTH, "little")


def read_modulus(signed_modulus: str) -> bytes:
    """Verify Proton's signature on the modulus and return its raw bytes."""
    try:
        text = verify_cleartext(signed_modulus, MODULUS_PUBKEY)
    except PGPError as err:
        raise SRPError("Server sent an invalid SRP modulus signature") from err
    return base64.b64decode(text.strip())


@dataclass
class Proofs:
    """Values exchanged with the server during SRP authentication."""

    client_ephemeral: bytes
    client_proof: bytes
    expected_server_proof: bytes


def generate_proofs(
    version: int,
    password: bytes,
    salt_b64: str,
    signed_modulus: str,
    server_ephemeral_b64: str,
) -> Proofs:
    """Compute the client side of Proton's SRP handshake."""
    modulus_bytes = read_modulus(signed_modulus)
    salt = base64.b64decode(salt_b64)
    server_ephemeral = base64.b64decode(server_ephemeral_b64)
    hashed_password = hash_password(version, password, salt, modulus_bytes)

    modulus = _to_int(modulus_bytes)
    generator = 2
    big_b = _to_int(server_ephemeral)
    if modulus.bit_length() != BIT_LENGTH:
        raise SRPError("SRP modulus has incorrect size")
    if modulus % 8 != 3:
        raise SRPError("SRP modulus is not 3 mod 8")
    if not 1 < big_b < modulus - 1:
        raise SRPError("SRP server ephemeral is out of bounds")
    if pow(generator, (modulus - 1) // 2, modulus) != modulus - 1:
        raise SRPError("SRP modulus is not a safe prime")

    multiplier = _to_int(expand_hash(_from_int(generator) + _from_int(modulus))) % modulus
    if not 1 < multiplier < modulus - 1:
        raise SRPError("SRP multiplier is out of bounds")

    while True:
        secret = secrets.randbelow(modulus - 1)
        if secret <= BIT_LENGTH * 2:
            continue
        client_ephemeral = _from_int(pow(generator, secret, modulus))
        scramble = _to_int(expand_hash(client_ephemeral + server_ephemeral))
        if scramble != 0:
            break

    exponent = _to_int(hashed_password)
    base = (big_b - multiplier * pow(generator, exponent, modulus)) % modulus
    shared = _from_int(pow(base, (scramble * exponent + secret) % (modulus - 1), modulus))

    client_proof = expand_hash(client_ephemeral + server_ephemeral + shared)
    server_proof = expand_hash(client_ephemeral + client_proof + shared)
    return Proofs(client_ephemeral, client_proof, server_proof)
