import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Card, Empty, ErrorBox, Pill } from "../lib/ui";
import { useAssets } from "../lib/useAsset";

export default function Assets() {
  const assets = useAssets();
  const qc = useQueryClient();
  const [form, setForm] = useState({ asset_identifier: "", display_name: "", hostname: "", port: 3000 });

  const register = useMutation({
    mutationFn: () => api.registerAsset({ ...form, protocol: "http", environment: "mock_lab" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setForm({ asset_identifier: "", display_name: "", hostname: "", port: 3000 }); },
  });

  return (
    <>
      <header className="page">
        <h1>Assets</h1>
        <p className="sub">Only registered synthetic lab assets can be assessed.</p>
      </header>

      <Card title="Registered assets">
        {assets.isLoading ? <Empty>Loading…</Empty> : (assets.data ?? []).length === 0 ? (
          <Empty>Nothing registered.</Empty>
        ) : (
          <table>
            <thead>
              <tr><th>Identifier</th><th>Target</th><th>Environment</th><th>State</th><th>Criticality</th></tr>
            </thead>
            <tbody>
              {(assets.data ?? []).map((a) => (
                <tr key={a.id}>
                  <td><strong>{a.asset_identifier}</strong><br /><span className="sub">{a.display_name}</span></td>
                  <td><code>{a.protocol}://{a.hostname}:{a.port}</code></td>
                  <td><Pill kind="plain" value={a.environment} /></td>
                  <td>{a.state}</td>
                  <td className="num">{a.criticality}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Register an asset">
        <p className="note">
          The platform accepts synthetic lab targets only. A public hostname, a public IP or an
          address outside the lab subnet is rejected with its reasons — try it.
        </p>
        <form
          className="form"
          onSubmit={(e) => { e.preventDefault(); register.mutate(); }}
        >
          <label>Identifier
            <input value={form.asset_identifier} required minLength={3}
              onChange={(e) => setForm({ ...form, asset_identifier: e.target.value })} />
          </label>
          <label>Display name
            <input value={form.display_name} required
              onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
          </label>
          <label>Hostname
            <input value={form.hostname} required placeholder="shop.brakes-vapt.test"
              onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
          </label>
          <label>Port
            <input type="number" value={form.port} min={1} max={65535}
              onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
          </label>
          <button type="submit" disabled={register.isPending}>
            {register.isPending ? "Registering…" : "Register"}
          </button>
        </form>
        {register.isError && <ErrorBox error={register.error} />}
        {register.isSuccess && <p className="ok">Registered {register.data.asset_identifier}.</p>}
      </Card>
    </>
  );
}
