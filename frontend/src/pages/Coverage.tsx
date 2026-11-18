import { useQuery } from "@tanstack/react-query";
import { api, type CategoryCoverage } from "../api/client";
import { Card, Empty, Stat } from "../lib/ui";
import { usePrimaryAsset } from "../lib/useAsset";

const DETECTION_LABEL: Record<string, string> = {
  detects: "Detects",
  partial: "Partial",
  surface_only: "Surface only",
  catalogued: "Catalogued only",
  none: "No capability",
};

function Bar({ row }: { row: CategoryCoverage }) {
  return <span className={`cov cov-${row.detection}`}>{DETECTION_LABEL[row.detection] ?? row.detection}</span>;
}

function Group({ title, note, rows }: { title: string; note: string; rows: CategoryCoverage[] }) {
  return (
    <Card title={title}>
      <p className="note">{note}</p>
      <table>
        <thead>
          <tr>
            <th>Category</th><th>Priority</th><th>Needs</th>
            <th className="num">Catalogue</th><th className="num">Surfaces</th>
            <th className="num">Findings</th><th>This build</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key}>
              <td>
                {r.display_name}
                {r.owasp_2021 ? <span className="sub"> · OWASP {r.owasp_2021}</span> : null}
                <span className="why">{r.note}</span>
                {r.blocked_by.length > 0 && (
                  <span className="why warn">Blocked by: {r.blocked_by.join("; ")}</span>
                )}
              </td>
              <td><span className={`pill prio-${r.priority}`}>{r.priority}</span></td>
              <td className="sub">{r.assertability}</td>
              <td className="num">{r.catalogue_entries}</td>
              <td className="num">{r.candidates}</td>
              <td className={`num${r.findings_total === 0 ? " zero" : ""}`}>{r.findings_total}</td>
              <td><Bar row={r} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export default function Coverage() {
  const { asset } = usePrimaryAsset();
  const q = useQuery({ queryKey: ["coverage", asset?.id], queryFn: () => api.coverage(asset!.id), enabled: !!asset });

  if (!asset) return <Empty>Register an asset first.</Empty>;
  if (q.isLoading || !q.data) return <Empty>Loading coverage…</Empty>;

  const s = q.data.summary;
  const tier1 = q.data.categories.filter((c) => c.tier === 1);
  const tier2 = q.data.categories.filter((c) => c.tier === 2);
  const silent = tier1.filter((c) => c.detection === "none" || c.detection === "catalogued");

  return (
    <>
      <header className="page">
        <h1>Coverage</h1>
        <p className="sub">
          What this build could have found, per category — not just what it did find.
          Every number is counted from the catalogue, the rule packs, the discovery matrix
          and the stored findings.
        </p>
      </header>

      <Card title="Tier 1 at a glance">
        <div className="stats">
          <Stat label="Categories" value={s.tier1_total} />
          <Stat label="Detects" value={s.tier1_detecting} tone="ok" />
          <Stat label="Partial" value={s.tier1_partial} />
          <Stat label="Surface only" value={s.tier1_surface_only} tone="warn" />
          <Stat label="No capability" value={s.tier1_catalogued_only + s.tier1_no_capability} tone="bad" />
          <Stat label="With findings" value={s.tier1_with_findings} />
        </div>
        {silent.length > 0 && (
          <p className="warnbox">
            <strong>{silent.length} of {s.tier1_total} Tier-1 categories cannot be reported by this
            build at all:</strong> {silent.map((c) => c.display_name).join(", ")}. Their absence from
            a report is not evidence of their absence in the target.
          </p>
        )}
        <p className="note">
          taxonomy {s.taxonomy_version} · matrix {s.matrix_version} · rules {s.rules_version}
          {s.uncategorised_findings > 0
            ? ` · ${s.uncategorised_findings} finding(s) carry no taxonomy category (unmapped detections)`
            : ""}
        </p>
      </Card>

      <Group
        title="Tier 1 — the MVP set"
        note={s.note}
        rows={tier1}
      />
      <Group
        title="Tier 2 — after the first demonstration"
        note="Catalogued so they can be reported as out of scope rather than silently omitted. Denial of service is excluded from execution by project constraint and will never be run."
        rows={tier2}
      />
    </>
  );
}
