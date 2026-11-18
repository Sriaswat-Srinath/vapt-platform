import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Card, Empty, ErrorBox, Pill, Stat } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

const SELECTABLE = ["confirmed", "candidate", "inconclusive", "false_positive", "not_applicable"];


/** Sections carry structured data, not prose. Lists of statements (limitations,
 *  remediation) are the ones an analyst reads here; everything else is shown as
 *  its stored JSON, escaped — the artifacts are the formatted deliverable. */
function SectionBody({ data }: { data: Record<string, unknown> }) {
  const items = data.items;
  if (Array.isArray(items)) {
    return (
      <ul className="plain">
        {items.map((it, i) =>
          typeof it === "string"
            ? <li key={i}>{it}</li>
            : <li key={i}>
                <strong>{String((it as Record<string, unknown>).title ?? "")}</strong>
                {(it as Record<string, unknown>).severity
                  ? <> — <Pill kind="sev" value={String((it as Record<string, unknown>).severity)} /></>
                  : null}
                {(it as Record<string, unknown>).affected_url
                  ? <> <code>{String((it as Record<string, unknown>).affected_url)}</code></>
                  : null}
                {(it as Record<string, unknown>).remediation_md
                  ? <p className="sub">{String((it as Record<string, unknown>).remediation_md)}</p>
                  : null}
              </li>,
        )}
      </ul>
    );
  }
  return <pre className="body-md">{JSON.stringify(data, null, 2)}</pre>;
}

export default function Reports() {
  const { asset } = usePrimaryAsset();
  const qc = useQueryClient();
  const [states, setStates] = useState<string[]>(["confirmed", "candidate"]);
  const [open, setOpen] = useState<string | null>(null);
  const [dlError, setDlError] = useState<unknown>(null);

  const templates = useQuery({ queryKey: ["templates"], queryFn: api.reportTemplates });
  const list = useQuery({ queryKey: ["reports", asset?.id], queryFn: () => api.reports(asset!.id), enabled: !!asset });
  const detail = useQuery({ queryKey: ["report", open], queryFn: () => api.report(open!), enabled: !!open });

  const generate = useMutation({
    mutationFn: () => api.generateReport(asset!.id, states),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["reports"] }); setOpen(r.id); },
  });

  async function download(id: string, fmt: string) {
    setDlError(null);
    try { await api.downloadArtifact(id, fmt); } catch (e) { setDlError(e); }
  }

  if (!asset) return <Empty>Register an asset first.</Empty>;

  return (
    <>
      <header className="page">
        <h1>Reports</h1>
        <p className="sub">
          Deterministic assembly from stored findings. Every artifact states that the target is a
          synthetic lab asset and lists what the assessment did not cover.
        </p>
      </header>

      <Card title="Generate">
        {templates.data && templates.data.map((t) => (
          <p key={t.key} className="note">
            Template <code>{t.key}</code> v{t.version} — {t.sections.length} sections:{" "}
            {t.sections.join(", ")}
          </p>
        ))}
        <fieldset className="chips">
          <legend>Include validation states</legend>
          {SELECTABLE.map((s) => (
            <label key={s} className="chip">
              <input type="checkbox" checked={states.includes(s)}
                     onChange={(e) => setStates(e.target.checked ? [...states, s] : states.filter((x) => x !== s))} />
              {s.replace(/_/g, " ")}
            </label>
          ))}
        </fieldset>
        <button type="button" onClick={() => generate.mutate()} disabled={generate.isPending || states.length === 0}>
          {generate.isPending ? "Generating…" : "Generate report"}
        </button>
        {generate.isError && <ErrorBox error={generate.error} />}
      </Card>

      <Card title="Generated reports">
        {(list.data ?? []).length === 0 ? <Empty>No reports yet.</Empty> : (
          <table>
            <thead>
              <tr><th>Generated</th><th>Title</th><th>Template</th><th>Filter</th><th>Artifacts</th><th /></tr>
            </thead>
            <tbody>
              {(list.data ?? []).map((r) => (
                <tr key={r.id} className={open === r.id ? "row-selected" : ""}>
                  <td>{r.generated_at ? new Date(r.generated_at).toLocaleString() : "—"}</td>
                  <td>{r.title}</td>
                  <td className="sub"><code>{r.template_key}</code> v{r.template_version}</td>
                  <td className="sub">{(r.filter?.include_states ?? []).join(", ") || "—"}</td>
                  <td className="row-actions">
                    {r.artifacts.map((a) => (
                      a.unavailable_reason
                        ? <span key={a.format} className="sub" title={a.unavailable_reason}>
                            {a.format} unavailable
                          </span>
                        : <button key={a.format} type="button" className="link"
                                  onClick={() => download(r.id, a.format)}>
                            {a.format} ({Math.round(a.bytes / 1024)} kB)
                          </button>
                    ))}
                  </td>
                  <td className="row-actions">
                    <button type="button" onClick={() => setOpen(open === r.id ? null : r.id)}>
                      {open === r.id ? "Hide" : "Inspect"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {dlError ? <ErrorBox error={dlError} /> : null}
      </Card>

      {open && detail.data && (
        <Card title={detail.data.title}>
          <div className="stats">
            <Stat label="State" value={detail.data.state} />
            <Stat label="Assessments" value={(detail.data.job_ids ?? []).length} />
            <Stat label="Evidence pinned" value={detail.data.evidence_pinned} />
            <Stat label="Pins blob" value={detail.data.pins_blob ? "yes" : "no"} />
          </div>
          {detail.data.artifacts.map((a) => (
            <p key={a.format} className="note">
              <code>{a.format}</code>{" "}
              {a.unavailable_reason
                ? <span className="warn">unavailable — {a.unavailable_reason}</span>
                : <>{a.bytes} bytes, sha256 <code className="mono-sm">{a.sha256?.slice(0, 32)}…</code></>}
            </p>
          ))}
          {detail.data.sections.map((s) => (
            <section key={s.seq} className="report-section">
              <h3>{s.heading}</h3>
              {s.body_md && <pre className="body-md">{s.body_md}</pre>}
              <SectionBody data={s.data} />
            </section>
          ))}
        </Card>
      )}
    </>
  );
}
