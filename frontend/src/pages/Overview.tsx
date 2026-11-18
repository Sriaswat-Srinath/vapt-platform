import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Card, Empty, ErrorBox, Pill, Stat } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

export default function Overview() {
  const { asset, isLoading } = usePrimaryAsset();
  const caps = useQuery({ queryKey: ["caps"], queryFn: api.capabilities });
  const iso = useQuery({ queryKey: ["iso"], queryFn: api.isolation });
  const summary = useQuery({
    queryKey: ["summary", asset?.id],
    queryFn: () => api.findingsSummary(asset!.id),
    enabled: !!asset,
  });
  const jobs = useQuery({
    queryKey: ["jobs", asset?.id], queryFn: () => api.jobs(asset!.id), enabled: !!asset,
  });
  const surface = useQuery({
    queryKey: ["surface", asset?.id], queryFn: () => api.attackSurface(asset!.id), enabled: !!asset,
  });

  if (isLoading) return <p className="empty">Loading…</p>;
  if (!asset) return <Empty>No asset is registered yet. Register one on the Assets screen.</Empty>;

  const s = summary.data;
  const recent = (jobs.data ?? []).slice(0, 6);
  const isolation = iso.data as { isolation_passed?: boolean; stale?: boolean; host_hygiene_passed?: boolean } | undefined;

  return (
    <>
      <header className="page">
        <h1>Overview</h1>
        <p className="sub">
          {asset.asset_identifier} — {asset.hostname}:{asset.port} ·{" "}
          <Pill kind="plain" value={asset.environment} />
        </p>
      </header>

      <div className="banner">
        <strong>Synthetic lab assessment.</strong> This platform assesses a deliberately vulnerable
        training application on an isolated network. Findings say nothing about any real system.
      </div>

      <div className="stats">
        <Stat label="Findings" value={s?.total ?? "—"} />
        <Stat label="Confirmed" value={s?.by_validation_state.confirmed ?? 0} tone="bad" />
        <Stat label="False positive" value={s?.by_validation_state.false_positive ?? 0} />
        <Stat label="Inconclusive" value={s?.by_validation_state.inconclusive ?? 0} tone="warn" />
        <Stat label="Endpoints" value={surface.data?.counts.endpoints ?? "—"} />
        <Stat label="Assessments" value={jobs.data?.length ?? "—"} />
      </div>

      <div className="grid-2">
        <Card title="Findings by severity">
          {!s || s.total === 0 ? (
            <Empty>No findings yet. Run an assessment.</Empty>
          ) : (
            <table>
              <tbody>
                {["critical", "high", "medium", "low", "informational"]
                  .filter((k) => s.by_severity[k])
                  .map((k) => (
                    <tr key={k}>
                      <td><Pill kind="sev" value={k} /></td>
                      <td className="num">{s.by_severity[k]}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
          {s && <p className="note">{s.note}</p>}
        </Card>

        <Card title="Containment">
          {iso.isError ? <ErrorBox error={iso.error} /> : (
            <dl className="kv">
              <dt>Lab isolation</dt>
              <dd className={isolation?.isolation_passed ? "on" : "off"}>
                {isolation?.isolation_passed === undefined
                  ? "not reported"
                  : isolation.isolation_passed ? "contained" : "FAILED"}
                {isolation?.stale ? " (stale)" : ""}
              </dd>
              <dt>Host hygiene</dt>
              <dd className={isolation?.host_hygiene_passed ? "on" : "warn"}>
                {isolation?.host_hygiene_passed === undefined
                  ? "not reported"
                  : isolation.host_hygiene_passed ? "clean" : "foreign listeners present"}
              </dd>
              <dt>Scanner execution</dt>
              <dd className={caps.data?.scanner_execution_enabled ? "on" : "off"}>
                {caps.data?.scanner_execution_enabled ? "enabled" : "disabled"}
              </dd>
              <dt>Policy version</dt>
              <dd>{caps.data?.policy_version}</dd>
              <dt>Evidence at rest</dt>
              <dd>{caps.data?.evidence_encryption}</dd>
            </dl>
          )}
          {caps.data && !caps.data.dual_control.effective && (
            <p className="warnbox">{caps.data.dual_control.note}</p>
          )}
        </Card>
      </div>

      <Card title="Recent assessments" actions={<Link to="/assessments">All assessments</Link>}>
        {recent.length === 0 ? <Empty>Nothing has been run yet.</Empty> : (
          <table>
            <thead>
              <tr><th>Started</th><th>Mode</th><th>Profile</th><th>State</th><th>Coverage</th></tr>
            </thead>
            <tbody>
              {recent.map((j) => (
                <tr key={j.id}>
                  <td>{new Date(j.created_at).toLocaleString()}</td>
                  <td><Pill kind="mode" value={j.mode} /></td>
                  <td><code>{j.profile_key}</code></td>
                  <td>{j.state}{j.stop_reason ? ` (${j.stop_reason})` : ""}</td>
                  <td className={j.coverage_complete ? "" : "warn"}>
                    {j.coverage_complete ? "complete" : "partial"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
