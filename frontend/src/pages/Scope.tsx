import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Card, Empty, ErrorBox, Pill } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

export default function Scope() {
  const { asset } = usePrimaryAsset();
  const rules = useQuery({ queryKey: ["rules", asset?.id], queryFn: () => api.scopeRules(asset!.id), enabled: !!asset });
  const grants = useQuery({ queryKey: ["grants", asset?.id], queryFn: () => api.grants(asset!.id), enabled: !!asset });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles });
  const [profileKey, setProfileKey] = useState("zap-passive");
  const [path, setPath] = useState("/");

  const validate = useMutation({
    mutationFn: () => api.validateScope(asset!.id, { profile_key: profileKey, path, method: "GET" }),
  });

  if (!asset) return <Empty>Register an asset first.</Empty>;

  return (
    <>
      <header className="page">
        <h1>Scope</h1>
        <p className="sub">What may be assessed, and the authorisation that permits it.</p>
      </header>

      <Card title="Authorisation">
        {grants.isLoading ? <Empty>Loading…</Empty> : (grants.data ?? []).length === 0 ? (
          <>
            <Empty>No scope grant exists for this asset.</Empty>
            <p className="warnbox">
              Without an active grant whose authorisation document is signed and verified, every
              assessment is denied. This is the designed blocker, not a defect.
            </p>
          </>
        ) : (
          <table>
            <thead>
              <tr><th>Document</th><th>Document state</th><th>Grant state</th><th>Profiles</th><th>Intrusive</th></tr>
            </thead>
            <tbody>
              {(grants.data ?? []).map((g) => (
                <tr key={g.id}>
                  <td><code>{g.document_ref}</code></td>
                  <td className={g.document_state === "signed_verified" ? "on" : "off"}>
                    {g.document_state.replace(/_/g, " ")}
                  </td>
                  <td className={g.state === "active" ? "on" : "off"}>{g.state}</td>
                  <td>{g.allowed_profiles.join(", ") || "—"}</td>
                  <td className={g.intrusive_allowed ? "warn" : ""}>{g.intrusive_allowed ? "allowed" : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Scope rules">
        {rules.isLoading ? <Empty>Loading…</Empty> : (
          <table>
            <thead>
              <tr><th>Rule</th><th>Host</th><th>Port</th><th>Path prefix</th><th>Methods</th><th>Reason</th></tr>
            </thead>
            <tbody>
              {(rules.data ?? []).map((r) => (
                <tr key={r.id}>
                  <td><Pill kind="state" value={r.kind} /></td>
                  <td><code>{r.host_pattern}</code></td>
                  <td className="num">{r.port ?? "—"}</td>
                  <td><code>{r.path_prefix}</code></td>
                  <td>{(r.method_allowlist ?? []).join(", ") || "—"}</td>
                  <td className="sub">{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="note">An exclude rule always wins over an include rule.</p>
      </Card>

      <Card title="Check the gate chain">
        <p className="note">
          A dry run of all 13 gates. Nothing is executed and nothing is contacted; the decision is
          recorded and audited exactly like a real request.
        </p>
        <form className="form inline" onSubmit={(e) => { e.preventDefault(); validate.mutate(); }}>
          <label>Profile
            <select value={profileKey} onChange={(e) => setProfileKey(e.target.value)}>
              {(profiles.data ?? []).map((p) => (
                <option key={p.key} value={p.key}>
                  {p.key}{p.is_intrusive ? " (intrusive)" : ""}
                </option>
              ))}
            </select>
          </label>
          <label>Path
            <input value={path} onChange={(e) => setPath(e.target.value)} />
          </label>
          <button type="submit" disabled={validate.isPending}>
            {validate.isPending ? "Checking…" : "Check"}
          </button>
        </form>
        {validate.isError && <ErrorBox error={validate.error} />}
        {validate.data && (
          <>
            <p>
              Decision:{" "}
              <strong className={validate.data.decision === "allow" ? "on" : "off"}>
                {validate.data.decision}
              </strong>{" "}
              <span className="sub">policy {validate.data.policy_version}</span>
            </p>
            <table className="gates">
              <thead><tr><th>#</th><th>Gate</th><th>Result</th><th>Reason</th></tr></thead>
              <tbody>
                {validate.data.gate_results.map((g, i) => (
                  <tr key={g.gate} className={g.pass ? "" : "row-fail"}>
                    <td className="num">{i + 1}</td>
                    <td><code>{g.gate}</code></td>
                    <td className={g.pass ? "on" : "off"}>{g.pass ? "pass" : "deny"}</td>
                    <td className="sub">{g.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Card>
    </>
  );
}
