"""Redaction applied ON WRITE, before anything reaches `evidence.content_redacted`.

This is stage 1 of the two-stage boundary in ADR-0010. The unredacted original
goes to the blob store, behind an admin-only, justification-gated endpoint; the
redacted text is what the UI, the report and (after a second pass in phase 6)
the agent ever see.

Correlation identifiers are KEYED: `ref=hmac:<key_id>:<base32>`. A plain digest
of a secret is brute-forceable for low-entropy values, so one is never emitted.
"""
from __future__ import annotations
import base64
import dataclasses as dc
import hashlib
import hmac
import os
import re

REDACTION_VERSION = "1.0.0"

SECRET_NAME = re.compile(
    r"(token|secret|passwd|password|apikey|api[-_]?key|auth|session|jwt|csrf|signature|private)",
    re.I)
HEADER_LINE = re.compile(r"^([A-Za-z0-9-]+):[ \t]*(.*)$")
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)
BASIC = re.compile(r"\b(Basic|Bearer)\s+([A-Za-z0-9+/=._-]{8,})", re.I)
HIGH_ENTROPY = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
QUERY_PAIR = re.compile(r"([?&])([A-Za-z0-9_.\[\]-]+)=([^&\s\"']*)")
FORM_VALUE = re.compile(r'(name=["\']?([A-Za-z0-9_.\[\]-]+)["\']?[^>]*?value=["\'])([^"\']*)',
                        re.I)


def _key() -> bytes:
    name = os.environ.get("REDACTION_HMAC_KEY_ENV", "REDACTION_HMAC_KEY")
    raw = os.environ.get(name) or ""
    if not raw:
        # Fail closed in the sense that matters: without a key we still redact,
        # we simply cannot offer correlation. We never fall back to a plain hash.
        return b""
    return raw.encode()


def _key_id() -> str:
    return os.environ.get("REDACTION_KEY_ID", "v1")


def ref(value: str) -> str:
    k = _key()
    if not k:
        return "unkeyed"
    digest = hmac.new(k, value.encode("utf-8", "replace"), hashlib.sha256).digest()
    return base64.b32encode(digest).decode().rstrip("=")[:12]


def marker(kind: str, value: str) -> str:
    return f"<redacted:kind={kind},len={len(value)},ref=hmac:{_key_id()}:{ref(value)}>"


@dc.dataclass(slots=True)
class RedactionReport:
    counts: dict[str, int] = dc.field(default_factory=dict)
    version: str = REDACTION_VERSION
    key_id: str = dc.field(default_factory=_key_id)

    def hit(self, kind: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1

    def as_dict(self) -> dict[str, object]:
        return {"counts": dict(self.counts), "redaction_version": self.version,
                "redaction_key_id": self.key_id}


def redact(text: str, *, report: RedactionReport | None = None) -> tuple[str, RedactionReport]:
    """Redact an HTTP request/response or any other evidence text.

    Fails closed: on any internal error the whole value is replaced rather than
    passed through.
    """
    rep = report or RedactionReport()
    if not text:
        return "", rep
    try:
        out_lines: list[str] = []
        for line in text.splitlines(keepends=False):
            m = HEADER_LINE.match(line)
            if m and m.group(1).lower() in SENSITIVE_HEADERS:
                rep.hit(m.group(1).lower())
                out_lines.append(f"{m.group(1)}: {marker(m.group(1).lower(), m.group(2))}")
                continue
            if m and SECRET_NAME.search(m.group(1)):
                rep.hit("secret_named_header")
                out_lines.append(f"{m.group(1)}: {marker('secret_header', m.group(2))}")
                continue
            out_lines.append(line)
        body = "\n".join(out_lines)

        def _pem(mo: re.Match[str]) -> str:
            rep.hit("pem_block")
            return marker("pem_block", mo.group(0))
        body = PEM.sub(_pem, body)

        def _jwt(mo: re.Match[str]) -> str:
            rep.hit("jwt")
            return marker("jwt", mo.group(0))
        body = JWT.sub(_jwt, body)

        def _basic(mo: re.Match[str]) -> str:
            rep.hit("encoded_credential")
            return f"{mo.group(1)} {marker('encoded_credential', mo.group(2))}"
        body = BASIC.sub(_basic, body)

        def _query(mo: re.Match[str]) -> str:
            sep, name, value = mo.group(1), mo.group(2), mo.group(3)
            if value and SECRET_NAME.search(name):
                rep.hit("query_parameter")
                return f"{sep}{name}={marker('query_parameter', value)}"
            return mo.group(0)
        body = QUERY_PAIR.sub(_query, body)

        def _form(mo: re.Match[str]) -> str:
            prefix, name, value = mo.group(1), mo.group(2), mo.group(3)
            if value and SECRET_NAME.search(name):
                rep.hit("form_field")
                return f"{prefix}{marker('form_field', value)}"
            return mo.group(0)
        body = FORM_VALUE.sub(_form, body)

        def _json_secret(mo: re.Match[str]) -> str:
            rep.hit("json_field")
            return f'"{mo.group(1)}": {marker("json_field", mo.group(2))}'
        body = re.sub(r'"([A-Za-z0-9_.-]*(?:token|secret|password|passwd|apikey|api_key|'
                      r'auth|session|jwt|csrf|signature|private)[A-Za-z0-9_.-]*)"\s*:\s*"([^"]*)"',
                      _json_secret, body, flags=re.I)

        def _email(mo: re.Match[str]) -> str:
            rep.hit("email")
            return marker("email", mo.group(0))
        body = EMAIL.sub(_email, body)

        def _entropy(mo: re.Match[str]) -> str:
            value = mo.group(0)
            if value.startswith("<redacted:") or "redacted:kind=" in value:
                return value
            rep.hit("high_entropy")
            return marker("high_entropy", value)
        body = HIGH_ENTROPY.sub(_entropy, body)
        return body, rep
    except Exception:                                      # noqa: BLE001 - fail closed
        rep.hit("redactor_error")
        return "<redacted:kind=whole_value,reason=redactor_error>", rep


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
