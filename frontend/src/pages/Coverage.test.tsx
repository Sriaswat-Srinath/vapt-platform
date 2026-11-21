import { describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { renderScreen } from "../test/render";
import { api } from "../api/client";
import Coverage from "./Coverage";

const ASSET = {
  id: "a1", asset_identifier: "MOCK-WEB-001", display_name: "Juice Shop",
  hostname: "h", protocol: "http", port: 3000, base_path: "/", environment: "mock_lab",
  criticality: 1, state: "active", notes: null, created_at: "",
};

function category(over: Record<string, unknown> = {}) {
  return {
    key: "business_logic", display_name: "Business Logic", tier: 1, priority: "high",
    assertability: "manual", owasp_2021: null, description: "Flaws in what is permitted.",
    catalogue_entries: 0, decidable_entries: 0, candidates: 2, findings_total: 0,
    findings_by_state: {}, detection: "none",
    blocked_by: ["no automated rule can confirm this category"],
    note: "No catalogue entry exists for this category.", ...over,
  };
}

describe("Coverage", () => {
  it("names the categories this build cannot report at all", async () => {
    vi.spyOn(api, "assets").mockResolvedValue([ASSET]);
    vi.spyOn(api, "coverage").mockResolvedValue({
      asset_id: "a1", asset_identifier: "MOCK-WEB-001",
      summary: {
        taxonomy_version: "1.0.0", matrix_version: "2.0.0", rules_version: "1.2.0",
        tier1_total: 12, tier1_detecting: 5, tier1_partial: 1, tier1_surface_only: 5,
        tier1_catalogued_only: 0, tier1_no_capability: 1, tier1_with_findings: 7,
        categories_this_build_cannot_report: ["business_logic"],
        uncategorised_findings: 1, note: "absence is not evidence of absence",
      },
      categories: [category()],
    });
    renderScreen(<Coverage />);
    expect(await screen.findByText(/cannot be reported by this build at all/))
      .toBeInTheDocument();
    // Named twice on purpose: in the warning and in the table row.
    expect(screen.getAllByText(/Business Logic/).length).toBeGreaterThanOrEqual(2);
    // The zero is the point of the screen: it must be shown, not omitted. It
    // appears as a headline count and as the row's own state.
    expect(screen.getAllByText("No capability").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/no automated rule can confirm/)).toBeInTheDocument();
  });

  it("shows what blocks a category rather than only that it is blocked", async () => {
    vi.spyOn(api, "assets").mockResolvedValue([ASSET]);
    vi.spyOn(api, "coverage").mockResolvedValue({
      asset_id: "a1", asset_identifier: "MOCK-WEB-001",
      summary: {
        taxonomy_version: "1.0.0", matrix_version: "2.0.0", rules_version: "1.2.0",
        tier1_total: 12, tier1_detecting: 5, tier1_partial: 1, tier1_surface_only: 5,
        tier1_catalogued_only: 0, tier1_no_capability: 0, tier1_with_findings: 7,
        categories_this_build_cannot_report: [], uncategorised_findings: 0, note: "n",
      },
      categories: [category({
        key: "ssrf", display_name: "Server-Side Request Forgery", detection: "surface_only",
        catalogue_entries: 1, blocked_by: ["active scanning is disabled",
                                           "intrusive testing needs two independent approvals"],
      })],
    });
    renderScreen(<Coverage />);
    expect(await screen.findByText(/active scanning is disabled/)).toBeInTheDocument();
    expect(screen.getByText(/two independent approvals/)).toBeInTheDocument();
  });
});
