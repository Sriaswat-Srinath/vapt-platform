"""Phase 7: report assembly, rendering and the analyst dashboard.

Invariant implemented here:
  I10  no report represents synthetic findings as real ones

The invariant is asserted on EVERY artifact format a report produces, not just
the one that is convenient to read: a stakeholder who is handed the PDF must see
the same statement as one who is handed the JSON.
"""
from __future__ import annotations
import html as html_mod
import json, os, pathlib, re, subprocess, sys, urllib.error, urllib.request
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
from app.reporting import renderers                                 # noqa: E402


class _Assembler:
    """The assembler imports SQLAlchemy, which belongs to the API image rather
    than the test host. Its module-level constants are read from source instead,
    so the test still asserts against the SAME text the service renders."""

    _src = (REPO / "backend/app/reporting/assembler.py").read_text()

    def _const(self, name: str) -> str:
        import ast
        for node in ast.parse(self._src).body:
            if isinstance(node, ast.Assign) and node.targets[0].id == name:  # type: ignore[attr-defined]
                return ast.literal_eval(node.value)
        raise AssertionError(f"{name} is not defined in assembler.py")

    def __getattr__(self, name: str):
        return self._const(name)


assembler = _Assembler()

from test_backend_core import call, asset_id                        # noqa: E402,F401

FRONTEND = "http://127.0.0.1:5173"


def _raw(path: str, role: str = "analyst") -> tuple[int, bytes, dict]:
    """Fetch an artifact as bytes (the JSON helper in test_backend_core decodes)."""
    import test_backend_core as core
    tok = core._tokens()[role]
    req = urllib.request.Request(core.BASE + path, method="GET",
                                 headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except urllib.error.URLError as e:
        pytest.skip(f"API not reachable ({e})")


@pytest.fixture(scope="module")
def report(asset_id) -> dict:
    status, body = call("POST", f"/assets/{asset_id}/reports"
                                "?include_states=confirmed,candidate,inconclusive")
    assert status == 201, body
    assert body["state"] == "ready", body
    status, detail = call("GET", f"/reports/{body['id']}")
    assert status == 200, detail
    return detail


# ------------------------------------------------------------- template ------
def test_template_is_declared_with_a_version_and_nine_sections():
    status, body = call("GET", "/report-templates")
    assert status == 200, body
    t = body[0]
    assert t["key"] == assembler.TEMPLATE_KEY
    assert re.fullmatch(r"\d+\.\d+\.\d+", t["version"])
    assert len(t["sections"]) == 9


def test_report_records_the_template_it_was_built_from(report):
    assert report["template_key"] == assembler.TEMPLATE_KEY
    assert report["template_version"] == assembler.TEMPLATE_VERSION
    assert [s["key"] for s in report["sections"]] == [
        "executive_summary", "scope", "methodology", "attack_surface",
        "vulnerability_summary", "findings", "risk_prioritisation",
        "remediation", "limitations"]


# ------------------------------------------- I10 (every artifact format) ------
def _artifact_text(report_id: str, fmt: str) -> str:
    status, data, headers = _raw(f"/reports/{report_id}/artifacts/{fmt}")
    assert status == 200, data[:400]
    if fmt == "pdf":
        assert data[:5] == b"%PDF-", data[:40]
        try:
            out = subprocess.run(["pdftotext", "-", "-"], input=data, capture_output=True)
        except FileNotFoundError:                      # pragma: no cover
            pytest.fail("pdftotext is not installed, so the PDF cannot be read back. "
                        "I10 must be checked on the PDF too: install poppler-utils.")
        if out.returncode != 0:
            pytest.fail("pdftotext could not read the generated PDF: "
                        f"{out.stderr.decode()[:200]}")
        return out.stdout.decode()
    text = data.decode()
    if fmt == "html":
        # The renderer escapes quotes and angle brackets, so compare against the
        # text a reader actually sees. Escaping itself is asserted separately.
        text = html_mod.unescape(text)
    return text


@pytest.mark.parametrize("fmt", ["html", "json", "pdf"])
def test_i10_every_artifact_states_the_target_is_synthetic(report, fmt):
    """I10: a reader of ANY artifact format is told these findings are synthetic."""
    available = {a["format"]: a for a in report["artifacts"]}
    assert fmt in available, f"the report produced no {fmt} artifact at all"
    if available[fmt]["unavailable_reason"]:
        pytest.fail(f"{fmt} artifact is unavailable: {available[fmt]['unavailable_reason']}. "
                    "An unavailable format is a failure here, not a skip: it was offered.")
    text = _artifact_text(report["id"], fmt)
    assert "MOCK-WEB-001" in text, "the artifact does not name the asset"
    assert "mock_lab" in text or "mock lab" in text.lower(), \
        "the artifact does not carry the mock-lab environment label"
    # The exact synthetic statement, whitespace-insensitive (PDF reflows text).
    norm = re.sub(r"\s+", " ", text)
    assert re.sub(r"\s+", " ", assembler.SYNTHETIC_STATEMENT) in norm, \
        f"the synthetic-lab statement is missing from the {fmt} artifact"


@pytest.mark.parametrize("fmt", ["html", "json", "pdf"])
def test_i10_every_artifact_carries_a_non_empty_limitations_section(report, fmt):
    text = _artifact_text(report["id"], fmt)
    norm = re.sub(r"\s+", " ", text)
    assert "Limitations of this assessment" in norm
    items = next(s for s in report["sections"] if s["key"] == "limitations")["data"]["items"]
    assert items, "the limitations section is empty"
    for item in items:
        assert re.sub(r"\s+", " ", item) in norm, \
            f"limitation missing from the {fmt} artifact: {item[:60]}…"


def test_i10_limitations_are_derived_from_what_actually_happened(report):
    """Not boilerplate: the text must reflect this run's real coverage."""
    items = next(s for s in report["sections"] if s["key"] == "limitations")["data"]["items"]
    joined = " ".join(items)
    assert assembler.SYNTHETIC_STATEMENT in items
    assert re.search(r"\d+ of \d+ assessment\(s\) in this report ran in FIXTURE mode", joined), \
        "fixture-mode assessments are not disclosed"
    assert "No live scan of the target was performed" in joined
    assert "No active or intrusive testing was performed" in joined


def test_report_does_not_claim_a_live_scan_it_did_not_run(report):
    meth = next(s for s in report["sections"] if s["key"] == "methodology")["data"]
    modes = {a["mode"] for a in meth["assessments"]}
    if modes == {"fixture"}:
        text = _artifact_text(report["id"], "html")
        assert "No live scan of the target was performed" in re.sub(r"\s+", " ", text)


# --------------------------------------------------------- determinism -------
def test_regeneration_over_the_same_data_is_byte_identical(asset_id):
    """Two reports over the same inputs differ only in identity and timestamp."""
    q = "?include_states=confirmed"
    a = call("POST", f"/assets/{asset_id}/reports{q}")[1]
    b = call("POST", f"/assets/{asset_id}/reports{q}")[1]
    ja = json.loads(_artifact_text(a["id"], "json"))
    jb = json.loads(_artifact_text(b["id"], "json"))
    for doc in (ja, jb):
        for volatile in ("report_id", "generated_at"):
            doc["report"].pop(volatile, None)
        for s in doc["sections"]:
            s["data"].pop("generated_at", None)
    assert ja == jb, "report assembly is not deterministic over identical inputs"


def test_html_and_json_hashes_are_recorded(report):
    for art in report["artifacts"]:
        if art["unavailable_reason"]:
            continue
        assert re.fullmatch(r"[0-9a-f]{64}", art["sha256"] or ""), art
        status, data, _ = _raw(f"/reports/{report['id']}/artifacts/{art['format']}")
        assert status == 200
        assert renderers.sha256(data) == art["sha256"], \
            f"the stored digest does not match the served {art['format']} bytes"


# ------------------------------------------------------------- escaping ------
def test_scanner_controlled_text_is_escaped_not_rendered_as_markup(report):
    """A scanner finding that contains markup must not become markup in the report.

    Rendered from a REAL report's sections with scanner-controlled fields
    poisoned, so the assertion covers the renderer the service actually uses.
    """
    payload = "<script>alert(1)</script>"
    sections = json.loads(json.dumps(report["sections"]))
    for sec in sections:
        if sec["key"] == "findings":
            for f in sec["data"]["findings"]:
                f["title"] = payload
                f["affected_url"] = payload
                for ev in f.get("evidence", []):
                    ev["content"] = payload
    out = renderers.render_html(
        asset={"asset_identifier": payload, "hostname": payload, "port": 3000,
               "environment": "mock_lab"},
        sections=sections,
        meta={"title": payload, "generated_at": "x", "template_key": "k",
              "template_version": "1.0.0", "report_id": report["id"],
              "synthetic_statement": assembler.SYNTHETIC_STATEMENT}).decode()
    assert payload not in out, "scanner-controlled markup reached the report as markup"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out, \
        "the payload is absent entirely; the test is not exercising the renderer"


def test_pdf_failure_is_reported_not_raised(monkeypatch):
    """A missing PDF stack must degrade to a recorded reason, never an exception."""
    import builtins
    real = builtins.__import__

    def boom(name, *a, **k):
        if name == "weasyprint":
            raise ModuleNotFoundError("No module named 'weasyprint'")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", boom)
    data, reason = renderers.render_pdf(b"<html><body>x</body></html>")
    assert data is None and reason and "unavailable" in reason.lower()


# ------------------------------------------------------- evidence pinning ----
def test_report_pins_evidence_by_reference_without_copying_blobs(report):
    assert report["evidence_pinned"] > 0, "no evidence was pinned to the report"
    assert report["pins_blob"] is False, \
        "the report took a blob-level pin; evidence must be referenced, not copied"


# ------------------------------------------------------------- dashboard -----
def _frontend(path: str = "/") -> tuple[int, bytes, dict]:
    try:
        with urllib.request.urlopen(FRONTEND + path, timeout=15) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except urllib.error.URLError as e:
        pytest.skip(f"dashboard not reachable at {FRONTEND} ({e}); "
                    "run `make frontend-up && make frontend-publish`")


def test_dashboard_is_served_with_its_security_headers():
    status, body, headers = _frontend("/")
    assert status == 200
    assert b"<div id=\"root\">" in body or b"id=root" in body
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_dashboard_proxies_the_api_on_its_own_origin():
    status, body, _ = _frontend("/api/v1/system/health")
    assert status == 200 and json.loads(body)["status"] == "ok"


def test_dashboard_api_proxy_still_requires_authentication():
    status, _, _ = _frontend("/api/v1/assets")
    assert status == 401, "the dashboard's proxy must not bypass authentication"


def test_dashboard_bundle_contains_no_token_and_no_external_origin():
    status, body, _ = _frontend("/")
    assert status == 200
    html_text = body.decode()
    srcs = re.findall(r'src="([^"]+)"', html_text) + re.findall(r'href="([^"]+)"', html_text)
    for s in srcs:
        assert not s.startswith("http"), f"the dashboard loads an external resource: {s}"
    for s in srcs:
        if s.endswith(".js"):
            _, js, _ = _frontend(s)
            assert b"vapt_01" not in js, "a token is baked into the dashboard bundle"
            assert b"localStorage" not in js, \
                "the bundle references localStorage; the token must be session-only"
