"""Finding identity.

Parameter NAMES are included, parameter VALUES are excluded (decision D9):
the same reflected-parameter issue across different payloads collapses to one
finding, while two different parameters stay distinct. Changing this definition
requires a data migration, so it is versioned.
"""
from __future__ import annotations
import hashlib
from urllib.parse import parse_qsl, urlsplit

FINGERPRINT_VERSION = "1.0.0"


def normalize_affected_url(url: str) -> str:
    """Scheme://host:port/path with query KEYS sorted and values dropped."""
    parts = urlsplit(url)
    keys = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    netloc = parts.netloc
    path = parts.path or "/"
    return f"{parts.scheme}://{netloc}{path}" + (f"?{'&'.join(keys)}" if keys else "")


def fingerprint(*, asset_id: str, catalogue_key: str | None, rule_id: str | None,
                affected_url: str, http_method: str, parameter_name: str | None,
                evidence_class: str) -> str:
    parts = urlsplit(affected_url)
    canonical = "|".join([
        str(asset_id),
        (catalogue_key or f"rule:{rule_id or 'unknown'}"),
        (parts.path or "/"),
        http_method.upper(),
        (parameter_name or ""),
        evidence_class,
    ])
    return hashlib.sha256(canonical.encode()).hexdigest()
