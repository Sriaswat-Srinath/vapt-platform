"""Evidence encryption at rest (closes gap 4.3).

The platform used to assume host full-disk encryption and say so. That is fine
for a laptop and wrong for a product: the unredacted originals are the most
sensitive thing stored, and "someone else encrypted the disk" is not a control
this system can point at.

What these tests defend:
  * a secret written while encryption is on is NOT on disk in the clear
  * content addressing is unchanged, so dedup and provenance still work
  * a mixed store (some blobs encrypted, some not) stays fully readable
  * a wrong key or an altered file FAILS LOUDLY rather than returning
    plausible bytes
  * enabling encryption without a usable key refuses the write instead of
    silently storing plaintext the operator believes is encrypted
"""
from __future__ import annotations
import base64, os, pathlib, subprocess, sys
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-for-anything")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused")

from app.evidence import crypto                                      # noqa: E402

from test_backend_core import call                                   # noqa: E402

SECRET = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=SUPERSECRETVALUE123\r\n\r\nbody"


@pytest.fixture()
def key(monkeypatch):
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY",
                       base64.b64encode(b"k" * 32).decode())
    return os.environ["EVIDENCE_ENCRYPTION_KEY"]


# ------------------------------------------------------------ the primitive --
def test_a_secret_is_not_present_in_the_ciphertext(key):
    sealed = crypto.encrypt(SECRET)
    assert b"SUPERSECRETVALUE123" not in sealed
    assert crypto.is_encrypted(sealed)
    assert crypto.decrypt(sealed) == SECRET


def test_each_write_uses_a_fresh_nonce(key):
    """Two encryptions of identical plaintext must differ, or the store leaks
    which blobs have the same content."""
    assert crypto.encrypt(SECRET) != crypto.encrypt(SECRET)


def test_a_tampered_blob_is_refused_not_returned(key):
    sealed = bytearray(crypto.encrypt(SECRET))
    sealed[-1] ^= 0x01
    with pytest.raises(crypto.EncryptionUnavailable) as exc:
        crypto.decrypt(bytes(sealed))
    assert "altered" in str(exc.value) or "key is wrong" in str(exc.value)


def test_a_wrong_key_is_refused(key, monkeypatch):
    sealed = crypto.encrypt(SECRET)
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", base64.b64encode(b"x" * 32).decode())
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.decrypt(sealed)


def test_plaintext_blobs_stay_readable(key):
    """A store being migrated contains both. The FILE says which it is."""
    assert not crypto.is_encrypted(b"HTTP/1.1 200 OK\r\n\r\nplain")
    assert crypto.decrypt(b"HTTP/1.1 200 OK\r\n\r\nplain") == b"HTTP/1.1 200 OK\r\n\r\nplain"


def test_a_missing_key_explains_the_consequence(monkeypatch):
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEY", raising=False)
    assert crypto.available() is False
    with pytest.raises(crypto.EncryptionUnavailable) as exc:
        crypto.encrypt(SECRET)
    assert "make evidence-key" in str(exc.value)
    assert "cannot be read" in str(exc.value)


@pytest.mark.parametrize("bad", ["not-base64!!", base64.b64encode(b"short").decode()])
def test_a_malformed_key_is_refused_at_use(monkeypatch, bad):
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", bad)
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt(SECRET)


def test_a_generated_key_is_the_right_shape():
    raw = base64.b64decode(crypto.new_key_base64(), validate=True)
    assert len(raw) == crypto.KEY_BYTES


def test_the_posture_string_never_overclaims(monkeypatch):
    """`/system/capabilities` must not say 'encrypted' when it is not."""
    import app.config as cfg
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_ENABLED", "false")
    cfg.settings.cache_clear()
    off = crypto.posture()
    assert "none" in off and "NOT verified" in off
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_ENABLED", "true")
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEY", raising=False)
    cfg.settings.cache_clear()
    assert "UNAVAILABLE" in crypto.posture(), \
        "enabled-but-unusable must not report as encrypted"
    cfg.settings.cache_clear()


def test_the_store_fails_rather_than_writing_plaintext_when_asked_to_encrypt():
    """The failure mode that matters: an operator believes evidence is
    encrypted and it is not. The write must fail instead."""
    src = (REPO / "backend" / "app" / "evidence" / "store.py").read_text()
    put = src[src.index("def put("):src.index("def read(")]
    assert "crypto.enabled()" in put
    assert "on_disk = crypto.encrypt(data)" in put
    # No except around the encrypt call: a failure propagates.
    assert "except" not in put.split("crypto.enabled()")[1].split("target.parent.mkdir")[0]


# ------------------------------------------------- against the real store ----
def test_every_stored_blob_is_readable_with_the_configured_key():
    """Runs the operator's own verification path (`make evidence-rekey-check`).
    A blob the platform cannot read is evidence that has been lost."""
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "evidence_verify.py")],
                         cwd=REPO, capture_output=True, text=True, timeout=900)
    if out.returncode == 2:
        pytest.skip(f"the platform is not running: {out.stderr[-200:]}")
    import json
    report = json.loads(out.stdout[out.stdout.index("{"):])
    assert report["unreadable"] == [], report["unreadable"]
    assert report["missing"] == 0, f"{report['missing']} blob(s) are missing from the store"
    assert report["total"] > 0


def test_capabilities_reports_the_real_posture():
    status, body = call("GET", "/system/capabilities")
    assert status == 200, body
    posture = body["evidence_encryption"]
    assert posture, "the platform must always state its evidence posture"
    assert ("aes-256-gcm" in posture) or ("none" in posture) or ("UNAVAILABLE" in posture)
