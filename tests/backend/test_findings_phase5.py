"""Phase 5: normalisation, fingerprinting, redaction, validation, CVSS.

Invariants implemented here:
  I6  no finding becomes confirmed solely through LLM output
  I7  no referenced evidence blob is purged
"""
from __future__ import annotations
import json, os, pathlib, subprocess, sys, time
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
from app.evidence import redaction                                    # noqa: E402
from app.normalization import fingerprint as fp, mapper, zap_mapping  # noqa: E402
from app.risk import cvss                                             # noqa: E402
from app.validation.engine import ValidationInputs, classify          # noqa: E402

from test_backend_core import call, asset_id                           # noqa: E402,F401


def _psql(sql: str) -> str:
    out = subprocess.run(["bash", "-lc",
        'set -a; . ./.env; set +a; docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" vapt_postgres '
        'psql -h 172.30.21.40 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc ' + json.dumps(sql)],
        cwd=REPO, capture_output=True, text=True)
    return out.stdout + out.stderr


# ---------------------------------------------------------- fingerprinting ----
def test_values_do_not_affect_identity_but_parameter_names_do():
    common = dict(asset_id="A", catalogue_key="reflected-xss", rule_id="40012",
                  http_method="GET", evidence_class="reflected_input")
    a = fp.fingerprint(affected_url="http://h:3000/s?q=apple", parameter_name=None, **common)
    b = fp.fingerprint(affected_url="http://h:3000/s?q=ORANGE", parameter_name=None, **common)
    c = fp.fingerprint(affected_url="http://h:3000/s?q=apple", parameter_name="q", **common)
    d = fp.fingerprint(affected_url="http://h:3000/s?q=apple", parameter_name="other", **common)
    assert a == b, "different parameter VALUES must collapse to one finding"
    assert a != c and c != d, "different parameter NAMES must stay distinct"


def test_evidence_class_change_reopens_identity():
    common = dict(asset_id="A", catalogue_key="x", rule_id="1", affected_url="http://h/1",
                  http_method="GET", parameter_name=None)
    assert fp.fingerprint(evidence_class="missing_header", **common) != \
           fp.fingerprint(evidence_class="reflected_input", **common)


def test_affected_url_drops_values_and_sorts_keys():
    assert fp.normalize_affected_url("http://h:3000/p?b=2&a=SECRET") == "http://h:3000/p?a&b"


# ------------------------------------------------------------- redaction ------
@pytest.mark.parametrize("secret,text", [
    ("SECRET123", "GET /x?token=SECRET123 HTTP/1.1"),
    ("hunter2", '{"password":"hunter2"}'),
    ("abc123def456ghi", "Cookie: session=abc123def456ghi"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig12345",
     "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig12345"),
    ("a@b.example", "contact: a@b.example"),
])
def test_secrets_never_survive_redaction(secret, text):
    out, report = redaction.redact(text)
    assert secret not in out, f"{secret!r} survived redaction: {out}"
    assert report.counts, "nothing was recorded as redacted"


def test_benign_values_survive():
    out, _ = redaction.redact("X-Request-Id: plain-value-42\nContent-Type: text/html")
    assert "plain-value-42" in out and "text/html" in out


def test_correlation_refs_are_keyed_not_plain_hashes():
    import hashlib
    value = "SECRET123"
    out, _ = redaction.redact(f"GET /x?token={value} HTTP/1.1")
    assert "ref=hmac:" in out
    assert hashlib.sha256(value.encode()).hexdigest()[:12] not in out, \
        "a plain digest of the secret was emitted"


def test_same_secret_correlates_and_different_secrets_do_not():
    a, _ = redaction.redact("Cookie: session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    b, _ = redaction.redact("Cookie: session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    c, _ = redaction.redact("Cookie: session=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    assert a == b and a != c


def test_redactor_failure_fails_closed(monkeypatch):
    monkeypatch.setattr(redaction, "HEADER_LINE", None)     # force an internal error
    out, report = redaction.redact("Authorization: Bearer secret-value-here")
    assert "secret-value-here" not in out
    assert "redactor_error" in report.counts


# -------------------------------------------------------------- mapping -------
def test_unmapped_rule_is_kept_not_dropped():
    n = mapper.normalize_zap_alert(asset_id="A", payload={"pluginId": "99999", "risk": "High"},
                                   adapter_rule_id="99999", observed_url="http://h/1")
    assert n is not None and n.unmapped is True
    assert n.catalogue_key is None and n.category == "unmapped_detection"


def test_severity_and_confidence_mapping_is_versioned():
    assert zap_mapping.MAPPING_VERSION
    assert zap_mapping.map_severity("Medium") == "medium"
    assert zap_mapping.map_severity(None) == "low", "an unknown risk must not inflate severity"
    assert zap_mapping.map_confidence("Confirmed") == "confirmed_by_tool"


# ------------------------------------------------------------- validation -----
def _v(**kw) -> str:
    return classify(ValidationInputs(**kw)).state


def test_negative_evidence_requires_complete_coverage():
    base = dict(evidence_class="missing_header", content_types=("text/html",),
                response_count=2, distinct_urls=2, header_absent_count=2,
                has_response_evidence=True)
    assert _v(coverage_complete=True, **base) == "confirmed"
    assert _v(coverage_complete=False, **base) == "inconclusive"


def test_positive_evidence_confirms_regardless_of_coverage():
    base = dict(evidence_class="reflected_input", evidence_found_in_body=True, html_context=True,
                reflected_unencoded=True, has_request_evidence=True, has_response_evidence=True)
    assert _v(coverage_complete=True, **base) == "confirmed"
    assert _v(coverage_complete=False, **base) == "confirmed"


def test_all_five_states_are_reachable():
    states = {
        _v(evidence_class="missing_header", coverage_complete=True, content_types=("text/html",),
           response_count=1, distinct_urls=1, header_absent_count=1, has_response_evidence=True),
        _v(evidence_class="missing_header", coverage_complete=True, content_types=("text/html",),
           header_present_count=1, has_response_evidence=True),
        _v(evidence_class="missing_header", coverage_complete=False, content_types=("text/html",),
           response_count=1, distinct_urls=1, header_absent_count=1, has_response_evidence=True),
        _v(evidence_class="missing_header", coverage_complete=True,
           content_types=("application/json",), has_response_evidence=True),
        _v(evidence_class="unmapped", coverage_complete=True),
    }
    assert states == {"confirmed", "false_positive", "inconclusive", "not_applicable", "candidate"}


def test_a_rule_error_never_confirms():
    out = classify(ValidationInputs(evidence_class="missing_header", coverage_complete=True,
                                    content_types=None))  # type: ignore[arg-type]
    assert out.state == "candidate"


# ------------------------------------------------------------------ cvss ------
def test_cvss_is_parsed_not_invented():
    ok = cvss.attach_from_catalogue(version="3.1",
                                    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    base=5.0)
    assert ok.valid and ok.source == "catalogue" and ok.base == 5.0
    bad = cvss.attach_from_catalogue(version="3.1", vector="NOT-A-VECTOR", base=5.0)
    assert not bad.valid and bad.vector is None
    out_of_range = cvss.attach_from_catalogue(version="3.1", vector=None, base=11.0)
    assert not out_of_range.valid
    none = cvss.attach_from_catalogue(version=None, vector=None, base=None)
    assert not none.valid and "stays null" in none.reason


# ------------------------------------------------- live stack: the pipeline ---
def _completed_job(asset_id: str) -> dict:
    status, jobs = call("GET", f"/assessments?asset_id={asset_id}")
    assert status == 200
    done = [j for j in jobs if j["state"] == "completed" and j["mode"] == "fixture"]
    if not done:
        status, job = call("POST", f"/assets/{asset_id}/assessments?mode=fixture",
                           role="analyst", body={"profile_key": "mock-passive"})
        assert status == 201, job
        for _ in range(40):
            s, j = call("GET", f"/assessments/{job['id']}")
            if j["state"] in ("completed", "failed", "blocked"):
                assert j["state"] == "completed", j
                return j
            time.sleep(1)
        pytest.fail("assessment did not finish")
    return done[0]


def test_findings_span_multiple_validation_states(asset_id):
    _completed_job(asset_id)
    status, summary = call("GET", f"/assets/{asset_id}/findings/summary")
    assert status == 200
    states = summary["by_validation_state"]
    assert summary["total"] > 0
    assert states.get("confirmed", 0) > 0, states
    assert states.get("false_positive", 0) > 0, "the engine confirmed everything: it is not discriminating"
    assert states.get("not_applicable", 0) > 0, states
    assert summary["unmapped_detections"] > 0, "an unmapped rule should be surfaced, not dropped"


def test_every_finding_has_provenance_and_a_validation_record(asset_id):
    _completed_job(asset_id)
    status, findings = call("GET", f"/findings?asset_id={asset_id}&limit=50")
    assert status == 200 and findings
    for f in findings[:8]:
        s, detail = call("GET", f"/findings/{f['id']}")
        assert s == 200
        assert detail["provenance"], f"{f['id']} has no raw observation provenance"
        assert all(p["payload_sha256"] for p in detail["provenance"])
        assert detail["validation_history"], f"{f['id']} has no validation history"
        assert detail["validation"]["rule_id"] and detail["validation"]["rule_version"]
        assert detail["risk"] is not None


def test_cvss_and_priority_are_separate_and_priority_is_absent(asset_id):
    _completed_job(asset_id)
    status, findings = call("GET", f"/findings?asset_id={asset_id}&limit=50")
    mapped = [f for f in findings if f["catalogue_key"]]
    assert mapped
    s, detail = call("GET", f"/findings/{mapped[0]['id']}")
    risk = detail["risk"]
    assert "cvss" in risk and "priority_score" in risk
    assert risk["priority_score"] is None, "the MVP must not compute a prioritisation score"
    assert risk["formula_version"] is None
    assert risk["epss"] is None and risk["kev_listed"] is False, \
        "absent threat intelligence must be null, never estimated"
    if risk["cvss"]["base"] is not None:
        assert risk["cvss"]["source"] == "catalogue"


def test_evidence_is_redacted_for_analysts_and_raw_requires_admin_plus_justification(asset_id):
    _completed_job(asset_id)
    status, findings = call("GET", f"/findings?asset_id={asset_id}&limit=50")
    for f in findings:
        s, detail = call("GET", f"/findings/{f['id']}")
        if detail["evidence"]:
            ev = detail["evidence"][0]
            break
    else:
        pytest.skip("no evidence stored")
    s, body = call("GET", f"/evidence/{ev['id']}/content")
    assert s == 200 and body["redacted"] is True
    assert body["redaction_version"]
    s, _ = call("GET", f"/evidence/{ev['id']}/content?raw=true", role="analyst")
    assert s == 403, "an analyst must not read the unredacted original"
    s, body = call("GET", f"/evidence/{ev['id']}/content?raw=true", role="admin")
    assert s == 400, "a justification must be required"
    s, body = call("GET", f"/evidence/{ev['id']}/content?raw=true"
                          "&justification=verifying+the+finding+for+the+report", role="admin")
    assert s == 200 and body["redacted"] is False and body["content_sha256"]


def test_raw_evidence_access_is_audited():
    s, rows = call("GET", "/audit?limit=100", role="approver")
    assert s == 200
    assert any(r["action"] == "raw_evidence_accessed" for r in rows), \
        "reading unredacted evidence was not audited"


def test_revalidation_is_idempotent(asset_id):
    job = _completed_job(asset_id)
    s, first = call("POST", f"/assessments/{job['id']}/revalidate", role="analyst")
    assert s == 200, first
    s, second = call("POST", f"/assessments/{job['id']}/revalidate", role="analyst")
    assert s == 200
    assert second["stats"]["findings_new"] == 0, "re-running created duplicate findings"
    assert first["stats"]["confirmed"] == second["stats"]["confirmed"]


# ---- I6: no finding becomes confirmed solely through LLM output ---------------
def test_an_agent_can_never_write_a_validation_event():
    """Invariant I6, enforced by a database CHECK rather than by convention."""
    out = _psql("insert into validation_events "
                "(id, finding_id, at, to_state, actor_kind, actor_id) "
                "select gen_random_uuid(), id, now(), 'confirmed', 'agent', 'llm' "
                "from findings limit 1")
    assert "ck_validation_actor_not_agent" in out or "violates check constraint" in out, out


def test_validation_events_are_append_only_so_the_automated_result_survives():
    assert "append-only" in _psql("update validation_events set to_state='confirmed'")
    assert "append-only" in _psql("delete from validation_events")


def test_a_human_override_requires_a_justification_and_preserves_history(asset_id):
    _completed_job(asset_id)
    s, findings = call("GET", f"/findings?asset_id={asset_id}&validation_state=confirmed")
    assert s == 200 and findings
    fid = findings[0]["id"]
    s, before = call("GET", f"/findings/{fid}")
    automated = [h for h in before["validation_history"] if h["actor_kind"] == "system"]
    assert automated, "no automated classification to preserve"
    s, body = call("POST", f"/findings/{fid}/analyst-classification"
                           "?to_state=false_positive&justification=short", role="analyst")
    assert s == 400, "a short justification must be refused"
    s, body = call("POST", f"/findings/{fid}/analyst-classification?to_state=false_positive"
                           "&justification=verified+manually+against+the+stored+response",
                   role="analyst")
    assert s == 200, body
    s, after = call("GET", f"/findings/{fid}")
    assert after["validation"]["state"] == "false_positive"
    kinds = [h["actor_kind"] for h in after["validation_history"]]
    assert "system" in kinds and "human" in kinds, \
        "the automated result must coexist with the human override"
    human = [h for h in after["validation_history"] if h["actor_kind"] == "human"][-1]
    assert human["justification"]
    # restore for other tests
    call("POST", f"/findings/{fid}/analyst-classification?to_state=confirmed"
                 "&justification=restoring+the+engine+classification+after+the+test", role="analyst")


def test_a_database_level_human_event_without_justification_is_refused():
    out = _psql("insert into validation_events (id, finding_id, at, to_state, actor_kind) "
                "select gen_random_uuid(), id, now(), 'confirmed', 'human' from findings limit 1")
    assert "ck_validation_human_requires_justification" in out or "violates check" in out, out


# ---- I7: no referenced evidence blob is purged -------------------------------
def test_a_referenced_blob_cannot_be_deleted(asset_id):
    """Invariant I7, exercised against the real store and the real references."""
    _completed_job(asset_id)
    out = subprocess.run(["bash", "-lc",
        'set -a; . ./.env; set +a; docker run --rm --network vapt_core '
        '-v vapt_evidence:/var/lib/vapt/evidence '
        '-e DATABASE_URL="postgresql+psycopg://$POSTGRES_USER:$POSTGRES_PASSWORD@172.30.21.40:5432/$POSTGRES_DB" '
        '-e SECRET_KEY="$SECRET_KEY" -e EVIDENCE_BLOB_ROOT=/var/lib/vapt/evidence '
        '-e REDACTION_HMAC_KEY="$REDACTION_HMAC_KEY" vapt-api:dev python -c "'
        'from sqlalchemy import select;'
        'from app.db import session_factory;'
        'from app import models;'
        'from app.evidence import store;'
        's=session_factory()();'
        'ev=s.execute(select(models.Evidence).where(models.Evidence.blob_id.isnot(None))).scalars().first();'
        'print(\\"refs\\", store.active_reference_count(s, ev.blob_id));'
        'r=None;'
        'exec(\\"try:\\\\n store.delete_if_unreferenced(s, ev.blob_id)\\\\n print(\\\\\\"DELETED\\\\\\")\\\\nexcept store.BlobStillReferenced as e:\\\\n print(\\\\\\"REFUSED\\\\\\", e)\\");'
        's.close()"'], cwd=REPO, capture_output=True, text=True, timeout=180)
    combined = out.stdout + out.stderr
    assert "REFUSED" in combined, combined
    assert "DELETED" not in combined, "a referenced blob was deleted"


def test_a_blob_reference_cannot_be_created_while_a_purge_is_in_flight():
    """The database guard that makes the pre-unlink reference recount durable."""
    blob = _psql("select id from evidence_blobs where state='present' limit 1").strip()
    if not blob or "ERROR" in blob:
        pytest.skip("no blob available")
    finding = _psql("select id from findings limit 1").strip()
    _psql(f"update evidence_blobs set state='pending_delete' where id='{blob}'")
    try:
        out = _psql("insert into evidence (id, finding_id, blob_id, kind, label, collected_at, "
                    f"collected_by) values (gen_random_uuid(),'{finding}','{blob}',"
                    "'http_response','probe',now(),'system')")
        assert "purge is in flight" in out or "violates check" in out, out
    finally:
        _psql(f"update evidence_blobs set state='present' where id='{blob}'")
