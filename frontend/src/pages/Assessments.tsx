import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Card, Empty, ErrorBox, Pill } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

export default function Assessments() {
  const { asset } = usePrimaryAsset();
  const qc = useQueryClient();
  const [mode, setMode] = useState<"fixture" | "live">("fixture");
  const [profileKey, setProfileKey] = useState("mock-passive");
  const [selected, setSelected] = useState<string | null>(null);

  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles });
  const jobs = useQuery({
    queryKey: ["jobs", asset?.id], queryFn: () => api.jobs(asset!.id), enabled: !!asset,
    refetchInterval: (q) =>
      (q.state.data ?? []).some((j) => ["queued", "preflight", "running", "cancelling"].includes(j.state))
        ? 2000 : false,
  });
  const surface = useQuery({
    queryKey: ["surface", asset?.id], queryFn: () => api.attackSurface(asset!.id), enabled: !!asset,
  });
  const candidates = useQuery({
    queryKey: ["candidates", asset?.id], queryFn: () => api.candidateTests(asset!.id), enabled: !!asset,
  });
  const events = useQuery({
    queryKey: ["events", selected], queryFn: () => api.jobEvents(selected!), enabled: !!selected,
  });

  const start = useMutation({
    mutationFn: () => api.startAssessment(asset!.id, profileKey, mode),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const discover = useMutation({
    mutationFn: () => api.startDiscovery(asset!.id, mode),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["surface"] }); qc.invalidateQueries({ queryKey: ["candidates"] }); },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api.cancelAssessment(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
  });

  if (!asset) return <Empty>Register an asset first.</Empty>;

  return (
    <>
      <header className="page">
        <h1>Assessments</h1>
        <p className="sub">Discover the attack surface, then run a permitted assessment against it.</p>
      </header>

      <Card title="Run">
        <form className="form inline" onSubmit={(e) => e.preventDefault()}>
          <label>Mode
            <select value={mode} onChange={(e) => setMode(e.target.value as "fixture" | "live")}>
              <option value="fixture">fixture — replays recorded data, contacts nothing</option>
              <option value="live">live — contacts the target, full gate chain</option>
            </select>
          </label>
          <label>Profile
            <select value={profileKey} onChange={(e) => setProfileKey(e.target.value)}>
              {(profiles.data ?? []).map((p) => (
                <option key={p.key} value={p.key}>
                  {p.key}{p.is_intrusive ? " (intrusive)" : ""}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={() => discover.mutate()} disabled={discover.isPending}>
            {discover.isPending ? "Discovering…" : "Discover surface"}
          </button>
          <button type="button" onClick={() => start.mutate()} disabled={start.isPending}>
            {start.isPending ? "Starting…" : "Start assessment"}
          </button>
        </form>
        {discover.isError && <ErrorBox error={discover.error} />}
        {start.isError && <ErrorBox error={start.error} />}
        {start.isSuccess && <p className="ok">Queued assessment {start.data.id.slice(0, 8)}.</p>}
      </Card>

      <div className="grid-2">
        <Card title="Attack surface">
          {!surface.data ? <Empty>Run discovery.</Empty> : (
            <>
              <table>
                <tbody>
                  {Object.entries(surface.data.counts).map(([k, v]) => (
                    <tr key={k}><td>{k.replace(/_/g, " ")}</td><td className="num">{v}</td></tr>
                  ))}
                  {Object.entries(surface.data.by_assessment).map(([k, v]) => (
                    <tr key={k}><td>endpoints — {k}</td><td className="num">{v}</td></tr>
                  ))}
                </tbody>
              </table>
              {surface.data.auth_entry_points.length > 0 && (
                <>
                  <h3>Authentication entry points</h3>
                  <ul className="plain">
                    {surface.data.auth_entry_points.map((e) => (
                      <li key={e.path}><code>{e.path}</code> — {e.kind.replace(/_/g, " ")}</li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </Card>

        <Card title="Candidate tests">
          {!candidates.data?.candidates.length ? <Empty>Run discovery.</Empty> : (
            <>
              <p className="note">{candidates.data.note}</p>
              <table>
                <thead><tr><th>Concern</th><th>Surface</th><th>Needs</th></tr></thead>
                <tbody>
                  {Array.from(
                    new Map(candidates.data.candidates.map((c) => [`${c.concern}|${c.surface_kind}`, c])).values(),
                  ).map((c) => (
                    <tr key={c.id}>
                      <td>{c.concern.replace(/_/g, " ")}</td>
                      <td className="sub">{c.surface_kind.replace(/_/g, " ")}</td>
                      <td className={c.requires_intrusive ? "warn" : ""}>
                        {c.requires_intrusive ? "intrusive + dual control" : c.suggested_profile_key || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </Card>
      </div>

      <Card title="History">
        {(jobs.data ?? []).length === 0 ? <Empty>Nothing has been run.</Empty> : (
          <table>
            <thead>
              <tr><th>Started</th><th>Mode</th><th>Profile</th><th>State</th><th>Coverage</th><th /></tr>
            </thead>
            <tbody>
              {(jobs.data ?? []).map((j) => (
                <tr key={j.id} className={selected === j.id ? "row-selected" : ""}>
                  <td>{new Date(j.created_at).toLocaleString()}</td>
                  <td><Pill kind="mode" value={j.mode} /></td>
                  <td><code>{j.profile_key}</code></td>
                  <td>
                    {j.state}
                    {j.stop_reason ? <span className="sub"> ({j.stop_reason})</span> : null}
                  </td>
                  <td className={j.coverage_complete ? "" : "warn"}>
                    {j.coverage_complete ? "complete" : "partial"}
                  </td>
                  <td className="row-actions">
                    <button type="button" onClick={() => setSelected(selected === j.id ? null : j.id)}>
                      {selected === j.id ? "Hide" : "Timeline"}
                    </button>
                    {["queued", "preflight", "running"].includes(j.state) && (
                      <button type="button" onClick={() => cancel.mutate(j.id)}>Cancel</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {cancel.isError && <ErrorBox error={cancel.error} />}
        {selected && events.data && (
          <div className="timeline">
            <h3>Timeline</h3>
            <ol>
              {events.data.map((e, i) => (
                <li key={i}>
                  <span className="sub">{new Date(e.at).toLocaleTimeString()}</span>{" "}
                  <strong>{e.to_state}</strong>{" "}
                  <span className="sub">{e.phase}</span> — {e.message}
                </li>
              ))}
            </ol>
          </div>
        )}
      </Card>
    </>
  );
}
