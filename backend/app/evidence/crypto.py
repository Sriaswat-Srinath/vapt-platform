"""Envelope encryption for evidence blobs at rest.

Until now the platform assumed host full-disk encryption and said so (B7).
That assumption is fine for a laptop and wrong for a product: the unredacted
originals are the most sensitive thing stored, and "someone else encrypted the
disk" is not a control this system can point at.

Design, and the reasons for each choice:

  AES-256-GCM        authenticated, so a truncated or tampered file fails to
                     decrypt rather than returning plausible bytes.
  key from the env   EVIDENCE_ENCRYPTION_KEY, 32 bytes base64. Never defaulted
                     and never written to the database, so a database dump is
                     not sufficient to read evidence.
  digest of PLAIN    `content_sha256` stays the digest of the plaintext, so
                     content addressing, deduplication and every existing
                     provenance reference keep working unchanged.
  per-blob nonce     12 random bytes, stored in the file header, never reused.
  file header        a short magic + version + nonce, so a reader can tell an
                     encrypted blob from a plaintext one WITHOUT consulting the
                     database. Mixed stores are therefore readable during a
                     migration, which is the state every real deployment is in
                     at some point.

Disabled by default: an operator who turns encryption on and cannot produce the
key again has lost their evidence, so this is a deliberate decision, not a
default. Existing plaintext blobs stay readable either way.
"""
from __future__ import annotations
import base64
import os
import secrets

MAGIC = b"VAPTENC1"
NONCE_BYTES = 12
KEY_BYTES = 32
HEADER = len(MAGIC) + NONCE_BYTES

ALGORITHM = "aes-256-gcm"
PLAINTEXT = "none"


class EncryptionUnavailable(RuntimeError):
    """Encryption was asked for and cannot be performed. Never degrade to
    writing plaintext when the operator asked for ciphertext."""


def _key() -> bytes:
    raw = os.environ.get("EVIDENCE_ENCRYPTION_KEY", "").strip()
    if not raw:
        raise EncryptionUnavailable(
            "EVIDENCE_ENCRYPTION_KEY is not set. Generate one with "
            "`make evidence-key` and store it where you store your other secrets: "
            "without it, evidence written while encryption was enabled cannot be read.")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:                                 # noqa: BLE001
        raise EncryptionUnavailable(f"EVIDENCE_ENCRYPTION_KEY is not valid base64: {exc}") from exc
    if len(key) != KEY_BYTES:
        raise EncryptionUnavailable(
            f"EVIDENCE_ENCRYPTION_KEY decodes to {len(key)} bytes; {KEY_BYTES} are required")
    return key


def available() -> bool:
    """Whether encryption COULD be performed right now."""
    try:
        _key()
    except EncryptionUnavailable:
        return False
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def enabled() -> bool:
    from ..config import settings
    return bool(settings().evidence_encryption_enabled)


def is_encrypted(data: bytes) -> bool:
    """Told by the FILE, not by the database. A mixed store stays readable."""
    return data[:len(MAGIC)] == MAGIC


def encrypt(plaintext: bytes) -> bytes:
    """Returns MAGIC || nonce || ciphertext-with-tag."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:                               # pragma: no cover
        raise EncryptionUnavailable(
            f"the cryptography package is not installed in this image: {exc}") from exc
    nonce = secrets.token_bytes(NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + nonce + sealed


def decrypt(data: bytes) -> bytes:
    """Returns the plaintext. Raises if the key is wrong or the file was altered."""
    if not is_encrypted(data):
        return data                                          # a plaintext blob
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:                               # pragma: no cover
        raise EncryptionUnavailable(
            f"this blob is encrypted and the cryptography package is missing: {exc}") from exc
    nonce = data[len(MAGIC):HEADER]
    try:
        return AESGCM(_key()).decrypt(nonce, data[HEADER:], MAGIC)
    except Exception as exc:                                 # noqa: BLE001
        raise EncryptionUnavailable(
            "this blob could not be decrypted: the key is wrong, or the file was altered. "
            f"({type(exc).__name__})") from exc


def new_key_base64() -> str:
    """For `make evidence-key`. Printed once; the platform never stores it."""
    return base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode()


def posture() -> str:
    """What `/system/capabilities` reports, in plain words."""
    if not enabled():
        return "none (host full-disk encryption assumed, and NOT verified by this platform)"
    if not available():
        return "ENABLED BUT UNAVAILABLE — writes will fail rather than store plaintext"
    return f"{ALGORITHM} at rest, key from the environment (never stored in the database)"
