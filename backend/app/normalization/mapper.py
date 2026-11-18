"""Raw observation -> NormalizedFinding. A PURE function.

Normalisation never mutates a raw observation, so a historical scan can be
re-normalised with an improved mapper and the delta is auditable (ADR-0002).
"""
from __future__ import annotations
import dataclasses as dc
from . import fingerprint as fp
from . import zap_mapping as zm


@dc.dataclass(frozen=True, slots=True)
class NormalizedFinding:
    catalogue_key: str | None
    evidence_class: str
    title: str
    category: str
    affected_url: str
    http_method: str
    parameter_name: str | None
    severity: str
    confidence: str
    description_md: str | None
    detection_source: str
    adapter_rule_id: str | None
    unmapped: bool
    scanner_evidence: str | None
    fingerprint: str


def normalize_zap_alert(*, asset_id: str, payload: dict, adapter_rule_id: str | None,
                        observed_url: str | None, detection_source: str = "zap_passive"
                        ) -> NormalizedFinding | None:
    """Map one ZAP-shaped alert. Returns None only for an unusable payload."""
    url = observed_url or payload.get("url")
    if not url:
        return None
    catalogue_key, evidence_class = zm.map_plugin(adapter_rule_id or payload.get("pluginId"))
    method = (payload.get("method") or "GET").upper()
    param = payload.get("param") or None
    title = payload.get("name") or (catalogue_key or f"ZAP rule {adapter_rule_id}")
    category = {
        "missing_header": "security_misconfiguration",
        "header_value": "security_misconfiguration",
        "pattern_in_body": "information_disclosure",
        "reflected_input": "injection",
        "missing_form_token": "broken_access_control",
        "unmapped": "unmapped_detection",
    }.get(evidence_class, "unmapped_detection")
    return NormalizedFinding(
        catalogue_key=catalogue_key, evidence_class=evidence_class, title=str(title)[:300],
        category=category, affected_url=fp.normalize_affected_url(str(url)),
        http_method=method, parameter_name=param,
        severity=zm.map_severity(payload.get("risk")),
        confidence=zm.map_confidence(payload.get("confidence")),
        description_md=payload.get("description"), detection_source=detection_source,
        adapter_rule_id=str(adapter_rule_id) if adapter_rule_id else None,
        unmapped=catalogue_key is None,
        scanner_evidence=(payload.get("evidence") or None),
        fingerprint=fp.fingerprint(asset_id=asset_id, catalogue_key=catalogue_key,
                                   rule_id=adapter_rule_id,
                                   affected_url=str(url), http_method=method,
                                   parameter_name=param, evidence_class=evidence_class))
