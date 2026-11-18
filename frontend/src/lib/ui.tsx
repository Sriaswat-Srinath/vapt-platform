import { Component } from "react";
import type { ReactNode } from "react";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

export function Pill({ kind, value }: { kind: "sev" | "state" | "mode" | "plain"; value: string }) {
  return <span className={`pill ${kind}-${value}`}>{value.replace(/_/g, " ")}</span>;
}

export function Card({ title, actions, children }: { title?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const anyErr = error as { status?: number; problem?: { title?: string; detail?: string; scope_decision?: { gate_results: { gate: string; pass: boolean; reason?: string }[] }; reasons?: string[] }; message?: string };
  const problem = anyErr?.problem;
  const gates = problem?.scope_decision?.gate_results?.filter((g) => !g.pass) ?? [];
  return (
    <div className="errorbox">
      <strong>{problem?.title || "Request failed"}</strong>
      <p>{problem?.detail || anyErr?.message}</p>
      {problem?.reasons && (
        <ul>{problem.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
      )}
      {gates.length > 0 && (
        <table className="gates">
          <tbody>
            {gates.map((g) => (
              <tr key={g.gate}>
                <td><code>{g.gate}</code></td>
                <td>{g.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** Scanner-controlled text is rendered as escaped text in a <pre>, never as markup. */
export function EvidenceBlock({ text }: { text: string }) {
  return <pre className="evidence">{text}</pre>;
}

/** A render failure in one screen must not blank the whole dashboard. */
export class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="errorbox">
        <strong>This screen failed to render</strong>
        <p>{this.state.error.message}</p>
        <p className="note">
          The failure is in the dashboard, not in the assessment data. Reload, or
          report the message above.
        </p>
      </div>
    );
  }
}
