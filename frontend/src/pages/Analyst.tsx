import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AgentProposal, type AgentRun } from "../api/client";
import { Card, Empty, ErrorBox, Pill, Stat } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

function Proposal({ p, onReview }: { p: AgentProposal; onReview: (d: "accepted" | "rejected") => void }) {
  const text = Object.entries(p.arguments).filter(([k]) => k !== "finding_id");
  return (
    <div className="proposal">
      <div className="proposal-head">
        <code>{p.tool}</code>
        <Pill kind="state" value={p.state} />
        {p.citations.length > 0 && (
          <span className="sub">
            cites {p.citations.length} finding{p.citations.length > 1 ? "s" : ""}
          </span>
        )}
      </div>
      <dl className="proposal-body">
        {text.map(([k, v]) => (
          <div key={k}>
            <dt>{k.replace(/_/g, " ")}</dt>
            <dd>{String(v)}</dd>
          </div>
        ))}
      </dl>
      {p.state === "proposed" ? (
        <div className="row-actions">
          <button type="button" onClick={() => onReview("accepted")}>Agree</button>
          <button type="button" onClick={() => onReview("rejected")}>Dismiss</button>
          <span className="sub">
            Agreeing records your decision. It changes no finding, state or score.
          </span>
        </div>
      ) : (
        <p className="sub">
          {p.state} by {p.reviewed_by ?? "an analyst"}
          {p.review_note ? ` — ${p.review_note}` : ""}
        </p>
      )}
    </div>
  );
}

function Run({ run, onReview }: { run: AgentRun; onReview: (id: string, d: "accepted" | "rejected") => void }) {
  return (
    <Card title={`Run ${run.id.slice(0, 8)} — ${run.state}`}>
      <div className="stats">
        <Stat label="Model" value={run.model ?? "—"} />
        <Stat label="Provider" value={run.provider_host ?? "not contacted"} />
        <Stat label="Proposals" value={run.proposals.length} />
        <Stat label="Refused" value={run.rejected.length} tone={run.rejected.length ? "warn" : undefined} />
        <Stat label="Boundary" value={run.boundary_report ? `${run.boundary_report.checked_fields} fields` : "not reached"} />
      </div>
      {run.error && <p className="warnbox">{run.error}</p>}
      {run.rejected.length > 0 && (
        <>
          <h3>Refused model output</h3>
          <table>
            <thead><tr><th>Tool</th><th>Reason</th><th>Why</th></tr></thead>
            <tbody>
              {run.rejected.map((r, i) => (
                <tr key={i}>
                  <td><code>{r.tool ?? "—"}</code></td>
                  <td className="off">{r.reason}</td>
                  <td className="sub">{r.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {run.proposals.length > 0 && (
        <>
          <h3>Proposals</h3>
          {run.proposals.map((p) => (
            <Proposal key={p.id} p={p} onReview={(d) => onReview(p.id, d)} />
          ))}
        </>
      )}
    </Card>
  );
}

export default function Analyst() {
  const { asset } = usePrimaryAsset();
  const qc = useQueryClient();
  const caps = useQuery({ queryKey: ["agentCaps"], queryFn: api.agentCapabilities });
  const runs = useQuery({
    queryKey: ["agentRuns", asset?.id], queryFn: () => api.agentRuns(asset!.id), enabled: !!asset,
  });
  const start = useMutation({
    mutationFn: () => api.startAgentRun(asset!.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agentRuns"] }),
  });
  const review = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "accepted" | "rejected" }) =>
      api.reviewProposal(id, decision),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agentRuns"] }),
  });

  if (!asset) return <Empty>Register an asset first.</Empty>;
  const c = caps.data;

  return (
    <>
      <header className="page">
        <h1>AI analyst</h1>
        <p className="sub">
          Advisory only. The agent proposes from a fixed catalogue, cites the findings it
          describes, and cannot set a validation state, a severity, a CVSS score, scope,
          or start anything.
        </p>
      </header>

      {c && (
        <Card title="What it is allowed to do">
          <div className="stats">
            <Stat label="Agent" value={c.llm_enabled ? "enabled" : "disabled"}
                  tone={c.llm_enabled ? undefined : "ok"} />
            <Stat label="Model" value={c.model ?? "—"} />
            <Stat label="Provider" value={c.provider_host ?? "—"} />
            <Stat label="Catalogue" value={`v${c.tool_catalogue_version}`} />
            <Stat label="Boundary" value={`v${c.boundary_version}`} />
          </div>
          <table>
            <thead><tr><th>Tool</th><th>What it proposes</th><th>Citations</th></tr></thead>
            <tbody>
              {c.tools.map((t) => (
                <tr key={t.tool}>
                  <td><code>{t.tool}</code></td>
                  <td className="sub">{t.summary}</td>
                  <td>{t.requires_citations ? "required" : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Structurally unable to</h3>
          <ul className="plain">
            {c.cannot.map(([k, why]) => (
              <li key={k}><code>{k}</code> <span className="sub">— {why}</span></li>
            ))}
          </ul>
          <p className="note">{c.egress}</p>
        </Card>
      )}

      <Card title="Run" actions={
        <button type="button" onClick={() => start.mutate()} disabled={start.isPending}>
          {start.isPending ? "Running…" : "Ask the analyst"}
        </button>
      }>
        <p className="note">
          One bounded pass over the stored findings and coverage. Evidence is re-redacted on the
          way out and the request is refused rather than sent if anything would leak.
        </p>
        {start.isError && <ErrorBox error={start.error} />}
        {review.isError && <ErrorBox error={review.error} />}
      </Card>

      {(runs.data ?? []).length === 0
        ? <Empty>No agent runs yet.</Empty>
        : (runs.data ?? []).map((r) => (
            <Run key={r.id} run={r}
                 onReview={(id, decision) => review.mutate({ id, decision })} />
          ))}
    </>
  );
}
