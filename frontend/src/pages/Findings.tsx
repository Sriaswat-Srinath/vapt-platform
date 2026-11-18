import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Card, Empty, EvidenceBlock, Pill, SEVERITY_ORDER, Stat } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

const STATES = ["confirmed", "candidate", "inconclusive", "false_positive", "not_applicable"];

function EvidenceItem({ id, label, kind, redaction }: { id: string; label: string; kind: string; redaction: { counts?: Record<string, number> } | null }) {
  const [open, setOpen] = useState(false);
  const content = useQuery({ queryKey: ["evidence", id], queryFn: () => api.evidence(id), enabled: open });
  const counts = Object.entries(redaction?.counts ?? {}).filter(([, n]) => n > 0);
  return (
    <div className="evidence-item">
      <button type="button" className="link" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} {label} <span className="sub">({kind.replace(/_/g, " ")})</span>
      </button>
      {counts.length > 0 && (
        <span className="sub"> redacted: {counts.map(([k, n]) => `${k}×${n}`).join(", ")}</span>
      )}
      {open && (content.isLoading
        ? <Empty>Loading…</Empty>
        : <EvidenceBlock text={content.data?.content ?? "(no stored content)"} />)}
    </div>
  );
}

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.finding(id) });
  if (q.isLoading) return <Card title="Finding"><Empty>Loading…</Empty></Card>;
  const f = q.data;
  if (!f) return null;
  return (
    <Card title={f.title} actions={<button type="button" onClick={onClose}>Close</button>}>
      <div className="stats">
        <Stat label="Severity" value={<Pill kind="sev" value={f.severity} />} />
        <Stat label="Validation" value={<Pill kind="state" value={f.validation.state} />} />
        <Stat label="Confidence" value={f.confidence} />
        <Stat label="CVSS base" value={f.risk?.cvss.base ?? "—"} />
        <Stat label="Occurrences" value={f.occurrence_count} />
      </div>

      <table className="kv">
        <tbody>
          <tr><td>URL</td><td><code>{f.http_method} {f.affected_url}</code></td></tr>
          <tr><td>Parameter</td><td>{f.parameter_name ? <code>{f.parameter_name}</code> : "—"}</td></tr>
          <tr><td>Category</td><td>{f.category.replace(/_/g, " ")}</td></tr>
          <tr><td>Fingerprint</td><td><code className="mono-sm">{f.fingerprint}</code></td></tr>
          <tr><td>Coverage</td><td className={f.coverage_complete ? "" : "warn"}>{f.coverage_complete ? "complete" : "partial — absence of a finding proves nothing"}</td></tr>
          {f.unmapped_rule_id && <tr><td>Unmapped rule</td><td className="warn"><code>{f.unmapped_rule_id}</code> — no catalogue entry, severity not asserted</td></tr>}
        </tbody>
      </table>

      {f.risk && (
        <>
          <h3>Risk</h3>
          <table className="kv">
            <tbody>
              <tr><td>CVSS</td><td>
                {f.risk.cvss.base !== null
                  ? <>{f.risk.cvss.base} <code className="mono-sm">{f.risk.cvss.vector}</code> <span className="sub">({f.risk.cvss.source}, v{f.risk.cvss.version})</span></>
                  : <span className="sub">not asserted{f.risk.cvss_reason ? ` — ${f.risk.cvss_reason}` : ""}</span>}
              </td></tr>
              <tr><td>EPSS / KEV</td><td className="sub">{f.risk.epss ?? "not in MVP"} / {f.risk.kev_listed ? "listed" : "not in MVP"}</td></tr>
              <tr><td>Priority score</td><td className="sub">{f.risk.priority_score ?? "no priority formula in the MVP"}</td></tr>
            </tbody>
          </table>
        </>
      )}

      {f.validation.rule_id && (
        <p className="note">
          Validation state <strong>{f.validation.state}</strong> was set by deterministic rule{" "}
          <code>{f.validation.rule_id}</code> v{f.validation.rule_version}. No model decided it.
        </p>
      )}

      {f.description_md && <><h3>Description</h3><p>{f.description_md}</p></>}
      {f.remediation_md && <><h3>Remediation</h3><p>{f.remediation_md}</p></>}

      <h3>Provenance</h3>
      <table>
        <thead><tr><th>Adapter</th><th>Adapter rule</th><th>Payload digest</th><th>Captured</th></tr></thead>
        <tbody>
          {f.provenance.map((p) => (
            <tr key={p.raw_observation_id}>
              <td>{p.adapter}{p.adapter_version ? ` ${p.adapter_version}` : ""}</td>
              <td><code>{p.adapter_rule_id ?? "—"}</code></td>
              <td><code className="mono-sm">{p.payload_sha256.slice(0, 16)}…</code></td>
              <td className="sub">{new Date(p.captured_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Evidence</h3>
      {f.evidence.length === 0 ? <Empty>No evidence attached.</Empty> : f.evidence.map((e) => (
        <EvidenceItem key={e.id} id={e.id} label={e.label} kind={e.kind} redaction={e.redaction_report} />
      ))}

      <h3>Validation history</h3>
      <ol className="history">
        {f.validation_history.map((h, i) => (
          <li key={i}>
            <span className="sub">{new Date(h.at).toLocaleString()}</span>{" "}
            {h.from_state ? `${h.from_state} → ` : ""}<strong>{h.to_state}</strong>{" "}
            <span className="sub">by {h.actor_kind}{h.rule_id ? ` / ${h.rule_id}` : ""}</span>
            {h.justification ? <> — {h.justification}</> : null}
          </li>
        ))}
      </ol>
    </Card>
  );
}

export default function Findings() {
  const { asset } = usePrimaryAsset();
  const { findingId } = useParams();
  const nav = useNavigate();
  const [state, setState] = useState<string>("");
  const [sev, setSev] = useState<string>("");

  const summary = useQuery({
    queryKey: ["fsummary", asset?.id], queryFn: () => api.findingsSummary(asset!.id), enabled: !!asset,
  });
  const list = useQuery({ queryKey: ["findings", asset?.id], queryFn: () => api.findings(asset!.id), enabled: !!asset });

  if (!asset) return <Empty>Register an asset first.</Empty>;

  const rows = (list.data ?? [])
    .filter((f) => (state ? f.validation_state === state : true))
    .filter((f) => (sev ? f.severity === sev : true))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  return (
    <>
      <header className="page">
        <h1>Findings</h1>
        <p className="sub">Normalised observations with provenance, deterministic validation state and redacted evidence.</p>
      </header>

      {summary.data && (
        <Card title="Summary">
          <div className="stats">
            <Stat label="Total" value={summary.data.total} />
            {STATES.map((s) => (
              <Stat key={s} label={s.replace(/_/g, " ")} value={summary.data!.by_validation_state[s] ?? 0} />
            ))}
            <Stat label="Unmapped" value={summary.data.unmapped_detections}
                  tone={summary.data.unmapped_detections ? "warn" : undefined} />
            <Stat label="Partial coverage" value={summary.data.partial_coverage}
                  tone={summary.data.partial_coverage ? "warn" : undefined} />
          </div>
          <p className="note">{summary.data.note}</p>
        </Card>
      )}

      <Card title="All findings" actions={
        <>
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">all states</option>
            {STATES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
          </select>
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">all severities</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </>
      }>
        {rows.length === 0 ? <Empty>No findings match.</Empty> : (
          <table>
            <thead>
              <tr><th>Severity</th><th>Title</th><th>Location</th><th>State</th><th>Source</th><th>CVSS</th><th>Seen</th></tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={`clickable${findingId === f.id ? " row-selected" : ""}`}
                    onClick={() => nav(findingId === f.id ? "/findings" : `/findings/${f.id}`)}>
                  <td><Pill kind="sev" value={f.severity} /></td>
                  <td>{f.title}</td>
                  <td className="sub">
                    <code>{f.affected_url}</code>{f.parameter_name ? ` · ${f.parameter_name}` : ""}
                  </td>
                  <td><Pill kind="state" value={f.validation_state} /></td>
                  <td className="sub">{f.detection_source.replace(/_/g, " ")}</td>
                  <td className="num">{f.cvss_base ?? "—"}</td>
                  <td className="num">{f.occurrence_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {findingId && <Detail id={findingId} onClose={() => nav("/findings")} />}
    </>
  );
}
