import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderScreen } from "../test/render";
import { api } from "../api/client";

import { resetAssetSelection, useSelectedAsset } from "./useAsset";

// The selection lives in a MODULE-LEVEL store — one value every screen shares,
// which is the point. It therefore survives between tests, so each test starts
// by re-reading storage through the same function sign-out uses.
beforeEach(() => resetAssetSelection(true));

const ASSETS = [
  { id: "a1", asset_identifier: "MOCK-WEB-001", display_name: "Juice Shop",
    hostname: "shop.brakes-vapt.test", protocol: "http", port: 3000, base_path: "/",
    environment: "mock_lab", criticality: 1, state: "active", notes: null, created_at: "" },
  { id: "a2", asset_identifier: "MOCK-WEB-002", display_name: "Supplier Portal",
    hostname: "portal.brakes-vapt.test", protocol: "http", port: 8080, base_path: "/",
    environment: "mock_lab", criticality: 1, state: "active", notes: null, created_at: "" },
];

/** Two independent consumers of the hook, as the real app has: the sidebar
 *  switcher and a screen. They must agree. */
function Switcher() {
  const { asset, assets, select } = useSelectedAsset();
  return (
    <div>
      <select aria-label="switcher" value={asset?.id ?? ""}
              onChange={(e) => select(e.target.value)}>
        {assets.map((a) => <option key={a.id} value={a.id}>{a.asset_identifier}</option>)}
      </select>
    </div>
  );
}
function Screen() {
  const { asset } = useSelectedAsset();
  return <p data-testid="screen">{asset?.asset_identifier ?? "none"}</p>;
}

describe("asset selection", () => {
  it("defaults to the first asset", async () => {
    vi.spyOn(api, "assets").mockResolvedValue(ASSETS);
    renderScreen(<><Switcher /><Screen /></>);
    expect(await screen.findByTestId("screen")).toHaveTextContent("MOCK-WEB-001");
  });

  it("changes EVERY consumer, not just the switcher", async () => {
    // The first implementation kept selection in each component's own state,
    // so the sidebar changed and the screen did not. This is that regression.
    vi.spyOn(api, "assets").mockResolvedValue(ASSETS);
    renderScreen(<><Switcher /><Screen /></>);
    await screen.findByTestId("screen");
    await userEvent.selectOptions(screen.getByLabelText("switcher"), "a2");
    await waitFor(() =>
      expect(screen.getByTestId("screen")).toHaveTextContent("MOCK-WEB-002"));
  });

  it("remembers the selection for the tab", async () => {
    vi.spyOn(api, "assets").mockResolvedValue(ASSETS);
    renderScreen(<><Switcher /><Screen /></>);
    await screen.findByTestId("screen");
    await userEvent.selectOptions(screen.getByLabelText("switcher"), "a2");
    await waitFor(() => expect(sessionStorage.getItem("vapt.asset")).toBe("a2"));
  });

  it("recovers when a remembered asset no longer exists", async () => {
    sessionStorage.setItem("vapt.asset", "deleted-asset");
    vi.spyOn(api, "assets").mockResolvedValue(ASSETS);
    renderScreen(<Screen />);
    await waitFor(() =>
      expect(screen.getByTestId("screen")).toHaveTextContent("MOCK-WEB-001"));
  });
});
