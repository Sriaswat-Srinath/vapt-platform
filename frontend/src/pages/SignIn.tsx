import { useState } from "react";
import { api, setToken } from "../api/client";

export default function SignIn() {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setToken(value.trim());
    try {
      await api.capabilities();
      window.location.reload();
    } catch {
      setToken(null);
      setError("That token was rejected. Check it and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <form onSubmit={submit}>
        <h1>VAPT platform</h1>
        <p className="sub">
          Authorised assessment of registered synthetic lab assets only. Paste the API token
          issued to your analyst account.
        </p>
        <label htmlFor="token">API token</label>
        <input
          id="token"
          type="password"
          autoComplete="off"
          value={value}
          placeholder="vapt_…"
          onChange={(e) => setValue(e.target.value)}
        />
        <button type="submit" disabled={busy || !value.trim()}>
          {busy ? "Checking…" : "Sign in"}
        </button>
        {error && <p className="error">{error}</p>}
        <p className="note">
          The token is kept for this browser tab only and is never written to persistent storage.
        </p>
      </form>
    </div>
  );
}
