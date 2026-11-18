import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, getToken } from "./api/client";
import { Boundary } from "./lib/ui";
import SignIn from "./pages/SignIn";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import Scope from "./pages/Scope";
import Assessments from "./pages/Assessments";
import Findings from "./pages/Findings";
import Coverage from "./pages/Coverage";
import Analyst from "./pages/Analyst";
import Reports from "./pages/Reports";

const NAV = [
  { to: "/overview", label: "Overview" },
  { to: "/assets", label: "Assets" },
  { to: "/scope", label: "Scope" },
  { to: "/assessments", label: "Assessments" },
  { to: "/findings", label: "Findings" },
  { to: "/coverage", label: "Coverage" },
  { to: "/analyst", label: "AI analyst" },
  { to: "/reports", label: "Reports" },
];

export default function App() {
  const token = getToken();
  const caps = useQuery({ queryKey: ["caps"], queryFn: api.capabilities, enabled: !!token });

  if (!token) return <SignIn />;

  const c = caps.data;
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <strong>VAPT</strong>
          <span>platform</span>
        </div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? "active" : "")}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        {c && (
          <div className="posture">
            <h3>Safety posture</h3>
            <dl>
              <dt>Scanner execution</dt>
              <dd className={c.scanner_execution_enabled ? "on" : "off"}>
                {c.scanner_execution_enabled ? "enabled" : "disabled"}
              </dd>
              <dt>Active scanning</dt>
              <dd className={c.active_scan_enabled ? "on" : "off"}>
                {c.active_scan_enabled ? "enabled" : "disabled"}
              </dd>
              <dt>Dual control</dt>
              <dd className={c.dual_control.effective ? "on" : "off"}>
                {c.dual_control.effective ? "available" : "unavailable"}
              </dd>
              <dt>Adapter</dt>
              <dd>{c.default_scanner_adapter}</dd>
              <dt>Environment</dt>
              <dd>{c.environment_policy}</dd>
            </dl>
          </div>
        )}
      </aside>
      <main>
        <Boundary>
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/scope" element={<Scope />} />
          <Route path="/assessments" element={<Assessments />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:findingId" element={<Findings />} />
          <Route path="/coverage" element={<Coverage />} />
          <Route path="/analyst" element={<Analyst />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
        </Boundary>
      </main>
    </div>
  );
}
