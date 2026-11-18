"""Report renderers: JSON, HTML and PDF.

HTML and JSON are always available. PDF is attempted with WeasyPrint and, when
its native libraries are absent, the artifact is recorded as unavailable with a
reason — it never blocks the report (decision D5).
"""
from __future__ import annotations
import hashlib
import html
import json
from typing import Any

RENDERER_VERSION = "1.0.0"


def _esc(v: Any) -> str:
    """Escape everything. Evidence is scanner-controlled text, so it is rendered
    as escaped text and never as markup — the one place an XSS in our own report
    would be self-inflicted."""
    return html.escape("" if v is None else str(v), quote=True)


def render_json(*, asset: dict, sections: list[dict], meta: dict) -> bytes:
    doc = {"report": meta, "asset": asset, "sections": sections,
           "renderer_version": RENDERER_VERSION}
    return json.dumps(doc, indent=2, default=str).encode()


def _severity_pill(sev: str) -> str:
    return f'<span class="pill sev-{_esc(sev)}">{_esc(sev)}</span>'


def _state_pill(state: str) -> str:
    return f'<span class="pill st-{_esc(state)}">{_esc(state.replace("_", " "))}</span>'


def render_html(*, asset: dict, sections: list[dict], meta: dict) -> bytes:
    by_key = {s["key"]: s for s in sections}
    ex = by_key["executive_summary"]["data"]
    out: list[str] = []
    a = out.append
    a("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    a(f"<title>{_esc(meta['title'])}</title>")
    a("""<style>
    :root{--ink:#16202b;--muted:#5b6673;--rule:#dfe4ea;--bg:#fff;--soft:#f5f7f9;
          --crit:#8f1430;--high:#b3401a;--med:#9a6508;--low:#2b6a7a;--info:#5b6673;
          --ok:#14675c;--bad:#8f1430;--warn:#8a5a0a}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 -apple-system,
         BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
    .wrap{max-width:860px;margin:0 auto;padding:32px 28px 72px}
    h1{font-size:26px;margin:0 0 6px;line-height:1.2}
    h2{font-size:18px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
    h3{font-size:15px;margin:22px 0 6px}
    p{margin:8px 0}
    .sub{color:var(--muted);font-size:13px}
    .banner{background:var(--soft);border-left:4px solid var(--warn);padding:12px 14px;
            margin:16px 0;font-size:13px}
    table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}
    th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--rule);
          vertical-align:top}
    th{background:var(--soft);font-weight:600}
    .num{text-align:right;font-variant-numeric:tabular-nums}
    .pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;
          font-weight:600;text-transform:uppercase;letter-spacing:.03em}
    .sev-critical{background:#f6dde3;color:var(--crit)}
    .sev-high{background:#fae3d9;color:var(--high)}
    .sev-medium{background:#fbf0d8;color:var(--med)}
    .sev-low{background:#dcedf1;color:var(--low)}
    .sev-informational{background:#eceff2;color:var(--info)}
    .st-confirmed{background:#d9ece7;color:var(--ok)}
    .st-false_positive{background:#eceff2;color:var(--muted)}
    .st-inconclusive{background:#fbf0d8;color:var(--warn)}
    .st-not_applicable{background:#eceff2;color:var(--muted)}
    .st-candidate{background:#e6e9f5;color:#3b4a8c}
    pre{background:var(--soft);border:1px solid var(--rule);border-radius:3px;padding:9px 11px;
        overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
    .finding{border:1px solid var(--rule);border-radius:4px;padding:14px 16px;margin:14px 0}
    .kv{display:grid;grid-template-columns:150px 1fr;gap:3px 12px;font-size:13px;margin:8px 0}
    .kv dt{color:var(--muted)}
    .kv dd{margin:0}
    ul{margin:8px 0;padding-left:20px}
    li{margin:4px 0}
    .foot{margin-top:40px;padding-top:12px;border-top:1px solid var(--rule);
          color:var(--muted);font-size:12px}
    @media print{.wrap{max-width:none;padding:0}h2{page-break-after:avoid}
                 .finding{page-break-inside:avoid}}
    </style></head><body><div class="wrap">""")
    a(f"<h1>{_esc(meta['title'])}</h1>")
    a(f"<p class=\"sub\">Asset <strong>{_esc(asset['asset_identifier'])}</strong> — "
      f"{_esc(asset['hostname'])}:{_esc(asset['port'])} · environment "
      f"<strong>{_esc(asset['environment'])}</strong> · generated "
      f"{_esc(meta['generated_at'])} · template {_esc(meta['template_key'])} "
      f"{_esc(meta['template_version'])}</p>")
    a(f"<div class=\"banner\"><strong>Synthetic lab assessment.</strong> "
      f"{_esc(ex['synthetic_statement'])}</div>")

    # ---- executive summary
    a("<h2>Executive summary</h2>")
    a(f"<p>{_esc(ex['findings_reported'])} finding(s) are reported here out of "
      f"{_esc(ex['findings_total'])} recorded for this asset, from "
      f"{_esc(ex['assessments'])} assessment(s) of which {_esc(ex['live_assessments'])} "
      f"ran against the live target.</p>")
    a("<table><tr><th>Validation state</th><th class=\"num\">Count</th></tr>")
    for k, v in sorted(ex["by_validation_state"].items()):
        a(f"<tr><td>{_state_pill(k)}</td><td class=\"num\">{_esc(v)}</td></tr>")
    a("</table>")
    a("<table><tr><th>Severity (reported)</th><th class=\"num\">Count</th></tr>")
    for k in ("critical", "high", "medium", "low", "informational"):
        if k in ex["by_severity"]:
            a(f"<tr><td>{_severity_pill(k)}</td><td class=\"num\">"
              f"{_esc(ex['by_severity'][k])}</td></tr>")
    a("</table>")

    # ---- scope
    sc = by_key["scope"]["data"]
    a("<h2>Scope</h2><dl class=\"kv\">")
    for label, value in (("Asset", sc["asset"]["identifier"]),
                         ("Hostname", f"{sc['asset']['hostname']}:{sc['asset']['port']}"),
                         ("Protocol", sc["asset"]["protocol"]),
                         ("Environment", sc["asset"]["environment"])):
        a(f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>")
    g = sc["grant"]
    a(f"<dt>Authorisation</dt><dd>{_esc(g['document_ref']) if g else 'none'}"
      f"{' — document state <strong>' + _esc(g['document_state']) + '</strong>, grant state <strong>' + _esc(g['state']) + '</strong>' if g else ''}</dd>")
    a("</dl>")
    a("<table><tr><th>Rule</th><th>Host</th><th>Port</th><th>Path prefix</th>"
      "<th>Methods</th><th>Reason</th></tr>")
    for r in sc["rules"]:
        a(f"<tr><td>{_esc(r['kind'])}</td><td>{_esc(r['host_pattern'])}</td>"
          f"<td>{_esc(r['port'])}</td><td>{_esc(r['path_prefix'])}</td>"
          f"<td>{_esc(', '.join(r['method_allowlist'] or []) or '—')}</td>"
          f"<td>{_esc(r['reason'])}</td></tr>")
    a("</table>")

    # ---- methodology
    me = by_key["methodology"]["data"]
    a("<h2>Scan methodology</h2>")
    a("<table><tr><th>Assessment</th><th>Mode</th><th>Profile</th><th>Adapter</th>"
      "<th>State</th><th>Coverage</th><th class=\"num\">Observations</th></tr>")
    for j in me["assessments"]:
        a(f"<tr><td>{_esc(j['id'][:8])}</td><td>{_esc(j['mode'])}</td>"
          f"<td>{_esc(j['profile_key'])}</td><td>{_esc(j['adapter'])}</td>"
          f"<td>{_esc(j['state'])} ({_esc(j['stop_reason'])})</td>"
          f"<td>{'complete' if j['coverage_complete'] else 'PARTIAL'}</td>"
          f"<td class=\"num\">{_esc(j['observations'])}</td></tr>")
    a("</table>")
    a("<h3>Test classes excluded by policy</h3><ul>")
    for x in me["excluded_test_classes"]:
        a(f"<li>{_esc(x)}</li>")
    a("</ul>")

    # ---- attack surface
    su = by_key["attack_surface"]["data"]
    a("<h2>Discovered attack surface</h2>")
    a("<table><tr><th>Measure</th><th class=\"num\">Count</th></tr>")
    for k, v in su["counts"].items():
        a(f"<tr><td>{_esc(k.replace('_', ' '))}</td><td class=\"num\">{_esc(v)}</td></tr>")
    for k, v in su["by_assessment"].items():
        a(f"<tr><td>endpoints — {_esc(k)}</td><td class=\"num\">{_esc(v)}</td></tr>")
    a("</table>")
    if su["auth_entry_points"]:
        a("<h3>Authentication entry points</h3><ul>")
        for e in su["auth_entry_points"]:
            a(f"<li><code>{_esc(e['path'])}</code> — {_esc(e['kind'])}</li>")
        a("</ul>")

    # ---- vulnerability summary
    vs = by_key["vulnerability_summary"]["data"]
    a("<h2>Vulnerability summary</h2>")
    a("<table><tr><th>Finding</th><th>Severity</th><th>CVSS</th><th>State</th>"
      "<th>Affected URL</th></tr>")
    for r in vs["rows"]:
        a(f"<tr><td>{_esc(r['title'])}</td><td>{_severity_pill(r['severity'])}</td>"
          f"<td class=\"num\">{_esc(r['cvss_base']) if r['cvss_base'] is not None else '—'}</td>"
          f"<td>{_state_pill(r['validation_state'])}</td>"
          f"<td><code>{_esc(r['affected_url'])}</code></td></tr>")
    a("</table>")

    # ---- individual findings
    a("<h2>Individual findings</h2>")
    for f in by_key["findings"]["data"]["findings"]:
        a("<div class=\"finding\">")
        a(f"<h3>{_esc(f['title'])} {_severity_pill(f['severity'])} "
          f"{_state_pill(f['validation_state'])}</h3>")
        a("<dl class=\"kv\">")
        a(f"<dt>Affected URL</dt><dd><code>{_esc(f['affected_url'])}</code></dd>")
        a(f"<dt>Method</dt><dd>{_esc(f['http_method'])}</dd>")
        if f["parameter_name"]:
            a(f"<dt>Parameter</dt><dd><code>{_esc(f['parameter_name'])}</code></dd>")
        a(f"<dt>Category</dt><dd>{_esc(f['category'])}</dd>")
        a(f"<dt>Scanner confidence</dt><dd>{_esc(f['confidence'])}</dd>")
        cv = f["cvss"] or {}
        a(f"<dt>CVSS</dt><dd>{_esc(cv.get('base')) if cv.get('base') is not None else '—'}"
          f"{' · <code>' + _esc(cv.get('vector')) + '</code>' if cv.get('vector') else ''}"
          f"{' · source ' + _esc(cv.get('source')) if cv.get('source') else ''}</dd>")
        a(f"<dt>Validation</dt><dd>{_esc(f['validation_rule_id'])} "
          f"v{_esc(f['validation_rule_version'])}</dd>")
        a(f"<dt>Coverage</dt><dd>{'complete' if f['coverage_complete'] else 'PARTIAL — absence is not proven'}</dd>")
        a(f"<dt>Occurrences</dt><dd>{_esc(f['occurrence_count'])}</dd>")
        if f["unmapped_rule_id"]:
            a(f"<dt>Unmapped rule</dt><dd>{_esc(f['unmapped_rule_id'])} — no catalogue entry, "
              f"so no CVSS</dd>")
        a("</dl>")
        if f["description_md"]:
            a(f"<p>{_esc(f['description_md'])}</p>")
        if f["remediation_md"]:
            a(f"<h4>Remediation</h4><p>{_esc(f['remediation_md'])}</p>")
        if f["evidence"]:
            a("<h4>Evidence (redacted)</h4>")
            for e in f["evidence"]:
                a(f"<p class=\"sub\">{_esc(e['kind'])} — {_esc(e['label'])} · redaction "
                  f"v{_esc(e['redaction_version'])}</p>")
                a(f"<pre>{_esc((e['content_redacted'] or '')[:1800])}</pre>")
        if f["provenance"]:
            a("<h4>Provenance</h4><ul>")
            for pv in f["provenance"]:
                a(f"<li>{_esc(pv['adapter'])} {_esc(pv['adapter_version'])} rule "
                  f"{_esc(pv['rule_id'])} · payload sha256 "
                  f"<code>{_esc(pv['payload_sha256'][:16])}…</code></li>")
            a("</ul>")
        if f["validation_history"]:
            a("<h4>Validation history</h4><table><tr><th>Actor</th><th>From</th><th>To</th>"
              "<th>Rule</th><th>Note</th></tr>")
            for h in f["validation_history"]:
                a(f"<tr><td>{_esc(h['actor_kind'])}</td><td>{_esc(h['from_state'])}</td>"
                  f"<td>{_esc(h['to_state'])}</td><td>{_esc(h['rule_id'])}</td>"
                  f"<td>{_esc(h['justification'] or h['note'])}</td></tr>")
            a("</table>")
        a("</div>")

    # ---- risk prioritisation
    rp = by_key["risk_prioritisation"]["data"]
    a("<h2>Risk prioritisation</h2>")
    a(f"<p class=\"sub\">{_esc(rp['method'])}</p>")
    a("<table><tr><th>Finding</th><th>Severity</th><th>CVSS base</th><th>CVSS vector</th>"
      "<th>Platform priority</th></tr>")
    for r in rp["rows"]:
        a(f"<tr><td>{_esc(r['title'])}</td><td>{_severity_pill(r['severity'])}</td>"
          f"<td class=\"num\">{_esc(r['cvss_base']) if r['cvss_base'] is not None else '—'}</td>"
          f"<td><code>{_esc(r['cvss_vector']) if r['cvss_vector'] else '—'}</code></td>"
          f"<td>{_esc(r['priority_score']) if r['priority_score'] is not None else 'not computed'}</td></tr>")
    a("</table>")

    # ---- remediation
    rm = by_key["remediation"]["data"]
    a("<h2>Remediation recommendations</h2>")
    if rm["items"]:
        a("<table><tr><th>Finding</th><th>Severity</th><th>Recommendation</th></tr>")
        for r in rm["items"]:
            a(f"<tr><td>{_esc(r['title'])}</td><td>{_severity_pill(r['severity'])}</td>"
              f"<td>{_esc(r['remediation_md'])}</td></tr>")
        a("</table>")
    else:
        a("<p>No remediation text is available for the reported findings.</p>")

    # ---- limitations
    a("<h2>Limitations of this assessment</h2><ul>")
    for item in by_key["limitations"]["data"]["items"]:
        a(f"<li>{_esc(item)}</li>")
    a("</ul>")
    a(f"<p class=\"foot\">Generated by the VAPT platform · report {_esc(meta['report_id'])} · "
      f"renderer {_esc(RENDERER_VERSION)} · all figures read back from stored assessment data.</p>")
    a("</div></body></html>")
    return "".join(out).encode()


def render_pdf(html_bytes: bytes) -> tuple[bytes | None, str | None]:
    """Returns (pdf_bytes, unavailable_reason). Never raises."""
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:                              # noqa: BLE001
        return None, (f"PDF rendering is unavailable in this image "
                      f"({type(exc).__name__}: {exc}). HTML and JSON are unaffected.")
    try:
        return HTML(string=html_bytes.decode()).write_pdf(), None
    except Exception as exc:                              # noqa: BLE001
        return None, f"PDF rendering failed ({type(exc).__name__}: {exc})"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
