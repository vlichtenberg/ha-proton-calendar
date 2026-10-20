"""Minimal, read-only OpenPGP implementation for Proton data.

Proton encrypts everything with OpenPGP. To avoid depending on unmaintained
Python OpenPGP libraries this module implements exactly the subset needed to
*read* Proton calendar data, on top of ``cryptography``:

* armor decoding and binary packet parsing (old and new format, partial lengths)
* v4 secret key packets (RSA, ECDH Curve25519, EdDSA Ed25519) locked with
  S2K (simple, salted, iterated+salted, Argon2) and CFB
* public key encrypted session key packets (RSA and ECDH Curve25519)
* symmetrically encrypted integrity protected data (SEIPD v1, with MDC)
* compressed (ZIP, ZLIB, BZip2) and literal data packets
* verification of the EdDSA clear-signed SRP modulus

Signing and encryption are intentionally not implemented.
"""

from __future__ import annotations

import base64
import bz2
from dataclasses import dataclass, field
import hashlib
import hmac
import struct
import zlib

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class PGPError(Exception):
    """Raised when OpenPGP data cannot be parsed or decrypted."""


# Packet tags
TAG_PKESK = 1
TAG_SIGNATURE = 2
TAG_SECRET_KEY = 5
TAG_PUBLIC_KEY = 6
TAG_SECRET_SUBKEY = 7
TAG_COMPRESSED = 8
TAG_LITERAL = 11
TAG_USER_ID = 13
TAG_PUBLIC_SUBKEY = 14
TAG_SEIPD = 18
TAG_MDC = 19

# Public key algorithms
ALGO_RSA = (1, 2, 3)
ALGO_ECDH = 18
ALGO_EDDSA_LEGACY = 22

# Curve OIDs (DER content bytes, without tag/length)
OID_CURVE25519 = bytes.fromhex("2b060104019755010501")
OID_ED25519 = bytes.fromhex("2b06010401da470f01")

_HASHES = {
    1: hashlib.md5,
    2: hashlib.sha1,
    3: lambda: hashlib.new("ripemd160"),
    8: hashlib.sha256,
    9: hashlib.sha384,
    10: hashlib.sha512,
    11: hashlib.sha224,
}

# symmetric algorithm id -> key size in bytes (AES only)
_SYM_KEY_SIZES = {7: 16, 8: 24, 9: 32}


def _aes_cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CFB decryption built on ECB (CFB is deprecated in ``cryptography``).

    In CFB the keystream block i is E(C[i-1]) with C[-1] = IV, so the whole
    keystream can be computed in one ECB pass over the known ciphertext.
    """
    if not ciphertext:
        return b""
    blocks = (len(ciphertext) + 15) // 16
    feed = (iv + ciphertext)[: blocks * 16].ljust(blocks * 16, b"\x00")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    keystream = encryptor.update(feed) + encryptor.finalize()
    size = len(ciphertext)
    mixed = int.from_bytes(ciphertext, "big") ^ int.from_bytes(keystream[:size], "big")
    return mixed.to_bytes(size, "big")


# --------------------------------------------------------------------------- armor


def dearmor(text: str | bytes) -> bytes:
    """Decode an ASCII-armored OpenPGP block into binary packets."""
    if isinstance(text, bytes):
        text = text.decode("ascii")
    lines = text.replace("\r\n", "\n").strip().split("\n")
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("-----BEGIN PGP"))
    except StopIteration as err:
        raise PGPError("No armor header found") from err
    body: list[str] = []
    in_headers = True
    for raw_line in lines[start + 1 :]:
        line = raw_line.strip()
        if line.startswith("-----END PGP"):
            break
        if in_headers:
            # Armor headers are "Key: Value" lines terminated by a blank line.
            if not line:
                in_headers = False
                continue
            if ": " in line:
                continue
            in_headers = False
        if not line:
            continue
        if line.startswith("=") and len(line) == 5:
            # CRC24 checksum, optional and not verified.
            continue
        body.append(line)
    try:
        return base64.b64decode("".join(body))
    except ValueError as err:
        raise PGPError("Invalid armor body") from err


def to_binary(data: str | bytes) -> bytes:
    """Return binary OpenPGP data from armored or binary input."""
    if isinstance(data, str):
        return dearmor(data)
    if data.lstrip().startswith(b"-----BEGIN PGP"):
        return dearmor(data)
    return data


# -------------------------------------------------------------------------- packets


@dataclass
class Packet:
    """A single OpenPGP packet."""

    tag: int
    body: bytes


def parse_packets(data: bytes) -> list[Packet]:
    """Split binary OpenPGP data into packets."""
    packets: list[Packet] = []
    pos = 0
    size = len(data)
    while pos < size:
        header = data[pos]
        pos += 1
        if not header & 0x80:
            raise PGPError("Invalid packet header")
        if header & 0x40:
            tag = header & 0x3F
            body = bytearray()
            while True:
                length, pos, partial = _new_length(data, pos)
                body += data[pos : pos + length]
                pos += length
                if not partial:
                    break
            packets.append(Packet(tag, bytes(body)))
        else:
            tag = (header >> 2) & 0x0F
            length_type = header & 0x03
            if length_type == 0:
                length = data[pos]
                pos += 1
            elif length_type == 1:
                (length,) = struct.unpack(">H", data[pos : pos + 2])
                pos += 2
            elif length_type == 2:
                (length,) = struct.unpack(">I", data[pos : pos + 4])
                pos += 4
            else:
                length = size - pos
            packets.append(Packet(tag, data[pos : pos + length]))
            pos += length
        if pos > size:
            raise PGPError("Truncated packet")
    return packets


def _new_length(data: bytes, pos: int) -> tuple[int, int, bool]:
    first = data[pos]
    if first < 192:
        return first, pos + 1, False
    if first < 224:
        return ((first - 192) << 8) + data[pos + 1] + 192, pos + 2, False
    if first == 255:
        (length,) = struct.unpack(">I", data[pos + 1 : pos + 5])
        return length, pos + 5, False
    return 1 << (first & 0x1F), pos + 1, True


class _Reader:
    """Sequential reader over a packet body."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise PGPError("Unexpected end of packet")
        out = self.data[self.pos : self.pos + count]
        self.pos += count
        return out

    def byte(self) -> int:
        return self.read(1)[0]

    def uint16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def uint32(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def mpi_bytes(self) -> bytes:
        bits = self.uint16()
        return self.read((bits + 7) // 8)

    def mpi(self) -> int:
        return int.from_bytes(self.mpi_bytes(), "big")

    def rest(self) -> bytes:
        out = self.data[self.pos :]
        self.pos = len(self.data)
        return out


# ----------------------------------------------------------------------------- keys


@dataclass
class SecretKey:
    """A v4 (sub)key packet. Secret parameters are populated after unlocking."""

    algo: int
    fingerprint: bytes
    public: dict
    s2k_usage: int
    protected: bytes
    is_subkey: bool
    secret: dict = field(default_factory=dict)

    @property
    def key_id(self) -> bytes:
        return self.fingerprint[-8:]

    @property
    def can_decrypt(self) -> bool:
        return self.algo in ALGO_RSA or self.algo == ALGO_ECDH

    @property
    def unlocked(self) -> bool:
        return bool(self.secret)


def _parse_key_packet(body: bytes, is_subkey: bool) -> SecretKey:
    reader = _Reader(body)
    version = reader.byte()
    if version != 4:
        raise PGPError(f"Unsupported key version {version}")
    reader.uint32()  # creation time
    algo = reader.byte()
    public: dict = {}
    if algo in ALGO_RSA:
        public["n"] = reader.mpi()
        public["e"] = reader.mpi()
    elif algo == ALGO_ECDH:
        oid_len = reader.byte()
        public["oid"] = reader.read(oid_len)
        public["point"] = reader.mpi_bytes()
        kdf_len = reader.byte()
        kdf = reader.read(kdf_len)
        public["kdf_hash"] = kdf[1]
        public["kdf_sym"] = kdf[2]
    elif algo in (ALGO_EDDSA_LEGACY, 19):
        oid_len = reader.byte()
        public["oid"] = reader.read(oid_len)
        public["point"] = reader.mpi_bytes()
    else:
        raise PGPError(f"Unsupported public key algorithm {algo}")
    public_body = body[: reader.pos]
    fingerprint = hashlib.sha1(b"\x99" + struct.pack(">H", len(public_body)) + public_body).digest()
    public["raw"] = public_body
    s2k_usage = reader.byte() if reader.pos < len(body) else 0
    return SecretKey(
        algo=algo,
        fingerprint=fingerprint,
        public=public,
        s2k_usage=s2k_usage,
        protected=reader.rest(),
        is_subkey=is_subkey,
    )


def read_keys(data: str | bytes) -> list[SecretKey]:
    """Parse all (sub)key packets from an armored or binary key block."""
    keys = []
    for packet in parse_packets(to_binary(data)):
        if packet.tag in (TAG_SECRET_KEY, TAG_PUBLIC_KEY):
            keys.append(_parse_key_packet(packet.body, is_subkey=False))
        elif packet.tag in (TAG_SECRET_SUBKEY, TAG_PUBLIC_SUBKEY):
            keys.append(_parse_key_packet(packet.body, is_subkey=True))
    if not keys:
        raise PGPError("No key packets found")
    return keys


def _s2k_derive(reader: _Reader, passphrase: bytes, key_size: int) -> bytes:
    s2k_type = reader.byte()
    if s2k_type == 4:
        from cryptography.hazmat.primitives.kdf.argon2 import (
            Argon2id,
        )

        salt = reader.read(16)
        iterations = reader.byte()
        lanes = reader.byte()
        memory = 1 << reader.byte()
        return Argon2id(
            salt=salt,
            length=key_size,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory,
        ).derive(passphrase)

    hash_factory = _HASHES.get(reader.byte())
    if hash_factory is None:
        raise PGPError("Unsupported S2K hash")
    salt = b""
    count = 0
    if s2k_type in (1, 3):
        salt = reader.read(8)
    if s2k_type == 3:
        coded = reader.byte()
        count = (16 + (coded & 15)) << ((coded >> 4) + 6)
    elif s2k_type not in (0, 1):
        raise PGPError(f"Unsupported S2K type {s2k_type}")

    material = salt + passphrase
    count = max(count, len(material))
    out = b""
    preload = 0
    while len(out) < key_size:
        digest = hash_factory()
        digest.update(b"\x00" * preload)
        if s2k_type == 3:
            full, remainder = divmod(count, len(material))
            # Hash in large chunks; hashlib releases the GIL for big buffers.
            chunk_repeat = max(1, 65536 // len(material))
            chunk = material * chunk_repeat
            blocks, tail = divmod(full, chunk_repeat)
            for _ in range(blocks):
                digest.update(chunk)
            digest.update(material * tail)
            digest.update(material[:remainder])
        else:
            digest.update(material)
        out += digest.digest()
        preload += 1
    return out[:key_size]


def unlock_key(key: SecretKey, passphrase: bytes) -> None:
    """Decrypt the secret parameters of ``key`` in place.

    Raises PGPError when the passphrase is wrong.
    """
    if key.unlocked:
        return
    reader = _Reader(key.protected)
    if key.s2k_usage == 0:
        clear = reader.rest()
        clear = clear[:-2]  # two-octet checksum
    elif key.s2k_usage in (254, 255):
        sym = reader.byte()
        key_size = _SYM_KEY_SIZES.get(sym)
        if key_size is None:
            raise PGPError(f"Unsupported key encryption algorithm {sym}")
        sym_key = _s2k_derive(reader, passphrase, key_size)
        iv = reader.read(16)
        clear = _aes_cfb_decrypt(sym_key, iv, reader.rest())
        if key.s2k_usage == 254:
            clear, check = clear[:-20], clear[-20:]
            if not hmac.compare_digest(hashlib.sha1(clear).digest(), check):
                raise PGPError("Wrong passphrase")
        else:
            clear, check = clear[:-2], clear[-2:]
            if (sum(clear) & 0xFFFF) != struct.unpack(">H", check)[0]:
                raise PGPError("Wrong passphrase")
    else:
        raise PGPError(f"Unsupported S2K usage {key.s2k_usage}")

    secret_reader = _Reader(clear)
    if key.algo in ALGO_RSA:
        key.secret = {
            "d": secret_reader.mpi(),
            "p": secret_reader.mpi(),
            "q": secret_reader.mpi(),
            "u": secret_reader.mpi(),
        }
    elif key.algo == ALGO_ECDH:
        key.secret = {"scalar": secret_reader.mpi_bytes()}
    else:
        key.secret = {"seed": secret_reader.mpi_bytes()}


def unlock_keys(data: str | bytes, passphrase: bytes) -> list[SecretKey]:
    """Parse a private key block and unlock all decryption-capable keys.

    Raises PGPError if no key could be unlocked.
    """
    keys = read_keys(data)
    unlocked = []
    for key in keys:
        try:
            unlock_key(key, passphrase)
        except PGPError:
            continue
        unlocked.append(key)
    if not unlocked:
        raise PGPError("Wrong passphrase")
    return unlocked


# ------------------------------------------------------------------- session keys


def _rsa_decrypt(key: SecretKey, ciphertext: int) -> bytes:
    n, e = key.public["n"], key.public["e"]
    p, q, d = key.secret["p"], key.secret["q"], key.secret["d"]
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e, n),
    )
    private = numbers.private_key()
    size = (n.bit_length() + 7) // 8
    return private.decrypt(ciphertext.to_bytes(size, "big"), padding.PKCS1v15())


def _ecdh_decrypt(key: SecretKey, ephemeral: bytes, wrapped: bytes) -> bytes:
    if key.public["oid"] != OID_CURVE25519:
        raise PGPError("Only Curve25519 ECDH keys are supported")
    if len(ephemeral) != 33 or ephemeral[0] != 0x40:
        raise PGPError("Invalid ECDH ephemeral point")
    scalar = key.secret["scalar"].rjust(32, b"\x00")
    # The secret scalar is stored big-endian; X25519 expects little-endian.
    private = x25519.X25519PrivateKey.from_private_bytes(scalar[::-1])
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(ephemeral[1:]))

    kdf_hash = _HASHES.get(key.public["kdf_hash"])
    kek_size = _SYM_KEY_SIZES.get(key.public["kdf_sym"])
    if kdf_hash is None or kek_size is None:
        raise PGPError("Unsupported ECDH KDF parameters")
    oid = key.public["oid"]
    param = (
        bytes([len(oid)])
        + oid
        + bytes([ALGO_ECDH, 3, 1, key.public["kdf_hash"], key.public["kdf_sym"]])
        + b"Anonymous Sender    "
        + key.fingerprint
    )
    digest = kdf_hash()
    digest.update(b"\x00\x00\x00\x01" + shared + param)
    kek = digest.digest()[:kek_size]
    try:
        padded = keywrap.aes_key_unwrap(kek, wrapped)
    except keywrap.InvalidUnwrap as err:
        raise PGPError("ECDH key unwrap failed") from err
    pad = padded[-1]
    if pad == 0 or pad > len(padded) or padded[-pad:] != bytes([pad]) * pad:
        raise PGPError("Invalid ECDH session key padding")
    return padded[:-pad]


def _decode_session_key(raw: bytes) -> tuple[int, bytes]:
    algo, session_key, checksum = raw[0], raw[1:-2], raw[-2:]
    if (sum(session_key) & 0xFFFF) != struct.unpack(">H", checksum)[0]:
        raise PGPError("Session key checksum mismatch")
    if _SYM_KEY_SIZES.get(algo) != len(session_key):
        raise PGPError(f"Unsupported session key algorithm {algo}")
    return algo, session_key


def decrypt_session_key(pkesk: bytes, keys: list[SecretKey]) -> tuple[int, bytes]:
    """Decrypt a PKESK packet body with one of ``keys``."""
    reader = _Reader(pkesk)
    version = reader.byte()
    if version != 3:
        raise PGPError(f"Unsupported PKESK version {version}")
    key_id = reader.read(8)
    algo = reader.byte()
    params = reader.rest()

    candidates = [k for k in keys if k.unlocked and k.can_decrypt and k.algo == algo]
    if key_id != b"\x00" * 8:
        matching = [k for k in candidates if k.key_id == key_id]
        candidates = matching or candidates
    last_error: Exception | None = None
    for key in candidates:
        param_reader = _Reader(params)
        try:
            if algo in ALGO_RSA:
                raw = _rsa_decrypt(key, param_reader.mpi())
            else:
                ephemeral = param_reader.mpi_bytes()
                wrapped = param_reader.read(param_reader.byte())
                raw = _ecdh_decrypt(key, ephemeral, wrapped)
            return _decode_session_key(raw)
        except (PGPError, ValueError) as err:
            last_error = err
    raise PGPError("No matching key to decrypt session key") from last_error


# ------------------------------------------------------------------------- messages


def _decrypt_seipd(body: bytes, sym: int, session_key: bytes) -> bytes:
    if not body or body[0] != 1:
        raise PGPError("Only SEIPD version 1 is supported")
    if sym not in _SYM_KEY_SIZES:
        raise PGPError(f"Unsupported cipher {sym}")
    plain = _aes_cfb_decrypt(session_key, b"\x00" * 16, body[1:])
    prefix, rest = plain[:18], plain[18:]
    if prefix[14:16] != prefix[16:18]:
        raise PGPError("Session key is wrong")
    data, mdc = rest[:-22], rest[-22:]
    if mdc[:2] != b"\xd3\x14":
        raise PGPError("Missing modification detection code")
    expected = hashlib.sha1(prefix + data + b"\xd3\x14").digest()
    if not hmac.compare_digest(expected, mdc[2:]):
        raise PGPError("Modification detected")
    return data


def _unwrap_literal(data: bytes) -> bytes:
    for packet in parse_packets(data):
        if packet.tag == TAG_COMPRESSED:
            algo, payload = packet.body[0], packet.body[1:]
            if algo == 0:
                inner = payload
            elif algo == 1:
                inner = zlib.decompress(payload, -15)
            elif algo == 2:
                inner = zlib.decompress(payload)
            elif algo == 3:
                inner = bz2.decompress(payload)
            else:
                raise PGPError(f"Unsupported compression {algo}")
            return _unwrap_literal(inner)
        if packet.tag == TAG_LITERAL:
            reader = _Reader(packet.body)
            reader.byte()  # format
            reader.read(reader.byte())  # filename
            reader.uint32()  # date
            return reader.rest()
    raise PGPError("No literal data found")


def decrypt_message(data: str | bytes, keys: list[SecretKey]) -> bytes:
    """Decrypt an armored or binary public-key encrypted message."""
    packets = parse_packets(to_binary(data))
    session: tuple[int, bytes] | None = None
    last_error: Exception | None = None
    for packet in packets:
        if packet.tag == TAG_PKESK and session is None:
            try:
                session = decrypt_session_key(packet.body, keys)
            except PGPError as err:
                last_error = err
        elif packet.tag == TAG_SEIPD:
            if session is None:
                raise PGPError("Unable to decrypt session key") from last_error
            return _unwrap_literal(_decrypt_seipd(packet.body, *session))
    raise PGPError("No encrypted data packet found")


def decrypt_split(key_packet: bytes, data_packet: bytes, keys: list[SecretKey]) -> bytes:
    """Decrypt a message whose key packet and data packet are stored separately."""
    return decrypt_message(key_packet + data_packet, keys)


# ----------------------------------------------------------------- clear signatures


def _canonical_text(text: str) -> bytes:
    lines = [line.rstrip(" \t\r") for line in text.split("\n")]
    return "\r\n".join(lines).encode("utf-8")


def read_cleartext(message: str) -> tuple[str, bytes]:
    """Split a clear-signed message into its text and binary signature."""
    lines = message.replace("\r\n", "\n").split("\n")
    try:
        start = lines.index("-----BEGIN PGP SIGNED MESSAGE-----")
        sig_start = lines.index("-----BEGIN PGP SIGNATURE-----")
    except ValueError as err:
        raise PGPError("Not a clear-signed message") from err
    pos = start + 1
    while pos < sig_start and lines[pos].strip():
        pos += 1  # "Hash:" headers
    text_lines = [
        line[2:] if line.startswith("- ") else line for line in lines[pos + 1 : sig_start]
    ]
    signature = dearmor("\n".join(lines[sig_start:]))
    return "\n".join(text_lines), signature


def verify_cleartext(message: str, public_key: str | bytes) -> str:
    """Verify an Ed25519 clear-signed message and return its text."""
    text, signature = read_cleartext(message)
    keys = [k for k in read_keys(public_key) if k.algo == ALGO_EDDSA_LEGACY]
    sig_packets = [p for p in parse_packets(signature) if p.tag == TAG_SIGNATURE]
    if not keys or not sig_packets:
        raise PGPError("Missing signing key or signature")

    for sig_packet in sig_packets:
        reader = _Reader(sig_packet.body)
        if reader.byte() != 4:
            continue
        reader.byte()  # signature type (0x01, canonical text)
        algo = reader.byte()
        hash_algo = reader.byte()
        hashed_len = reader.uint16()
        reader.read(hashed_len)
        hashed_end = reader.pos
        reader.read(reader.uint16())  # unhashed subpackets
        reader.read(2)  # left 16 bits of the hash
        if algo != ALGO_EDDSA_LEGACY or hash_algo not in _HASHES:
            continue
        r = reader.mpi_bytes().rjust(32, b"\x00")
        s = reader.mpi_bytes().rjust(32, b"\x00")

        hashed_part = sig_packet.body[:hashed_end]
        digest = _HASHES[hash_algo]()
        digest.update(_canonical_text(text))
        digest.update(hashed_part)
        digest.update(b"\x04\xff" + struct.pack(">I", len(hashed_part)))
        for key in keys:
            point = key.public["point"]
            if key.public["oid"] != OID_ED25519 or len(point) != 33:
                continue
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(point[1:]).verify(r + s, digest.digest())
            except Exception:
                continue
            return text
    raise PGPError("Invalid signature")


__all__ = [
    "PGPError",
    "SecretKey",
    "dearmor",
    "decrypt_message",
    "decrypt_session_key",
    "decrypt_split",
    "read_keys",
    "unlock_key",
    "unlock_keys",
    "verify_cleartext",
]
