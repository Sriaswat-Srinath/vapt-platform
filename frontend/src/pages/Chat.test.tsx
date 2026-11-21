import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderScreen } from "../test/render";
import { api } from "../api/client";
import Chat from "./Chat";

const ASSET = {
  id: "a1", asset_identifier: "MOCK-WEB-001", display_name: "Juice Shop",
  hostname: "shop.brakes-vapt.test", protocol: "http", port: 3000, base_path: "/",
  environment: "mock_lab", criticality: 1, state: "active", notes: null,
  created_at: "2026-01-01T00:00:00Z",
};
const CAPS = {
  enabled: true, model: "claude-haiku-4-5", chat_version: "1.0.0",
  retrieval_version: "1.0.0", max_tool_rounds: 4, conversation_token_budget: 120000,
  tools: [{ name: "list_findings", description: "List findings." }],
  note: "Every tool READS. The assistant cannot act on the platform.",
};

function stub(over: Partial<Record<keyof typeof api, unknown>> = {}) {
  vi.spyOn(api, "assets").mockResolvedValue([ASSET]);
  vi.spyOn(api, "chatCapabilities").mockResolvedValue(CAPS);
  vi.spyOn(api, "conversations").mockResolvedValue([]);
  vi.spyOn(api, "conversation").mockResolvedValue({
    id: "c1", asset_id: "a1", title: "t", state: "open",
    input_tokens: 0, output_tokens: 0, created_at: "", updated_at: "", turns: [],
  });
  vi.spyOn(api, "startConversation").mockResolvedValue({
    id: "c1", asset_id: "a1", title: "t", state: "open",
    input_tokens: 0, output_tokens: 0, created_at: "", updated_at: "", turns: [],
  });
  Object.assign(api, over);
}

describe("Ask the analyst", () => {
  it("shows the suggestions before any question is asked", async () => {
    stub();
    renderScreen(<Chat />);
    expect(await screen.findByText(/What vulnerabilities were discovered\?/)).toBeInTheDocument();
  });

  it("sends a typed question and renders the answer with its citations", async () => {
    stub();
    const ask = vi.spyOn(api, "askQuestion").mockResolvedValue({
      id: "t1", role: "assistant",
      content: "Four findings were recorded: f1, f2.",
      citations: ["f1", "f2"],
      tool_calls: [{ tool: "list_findings", arguments: {}, rows: 4 }],
      refusals: [], rounds: 1, model: "claude-haiku-4-5",
      input_tokens: 800, output_tokens: 90, error: null, created_at: "",
    });
    vi.spyOn(api, "conversation").mockResolvedValue({
      id: "c1", asset_id: "a1", title: "t", state: "open",
      input_tokens: 800, output_tokens: 90, created_at: "", updated_at: "",
      turns: [
        { id: "u1", role: "user", content: "What was found?", citations: [], tool_calls: [],
          refusals: [], rounds: null, model: null, input_tokens: null, output_tokens: null,
          error: null, created_at: "" },
        { id: "t1", role: "assistant", content: "Four findings were recorded: f1, f2.",
          citations: ["f1", "f2"],
          tool_calls: [{ tool: "list_findings", arguments: {}, rows: 4 }],
          refusals: [], rounds: 1, model: "claude-haiku-4-5",
          input_tokens: 800, output_tokens: 90, error: null, created_at: "" },
      ],
    });

    const { container } = renderScreen(<Chat />);
    const box = await screen.findByPlaceholderText(/Ask about this assessment/);
    await userEvent.type(box, "What was found?");
    await userEvent.click(screen.getByRole("button", { name: "Ask" }));

    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(await screen.findByText(/Four findings were recorded/)).toBeInTheDocument();
    expect(await screen.findByText("cites f1")).toBeInTheDocument();
    // The chips carry the provenance of the answer: which tool was read, and
    // what was cited. Queried by class because `list_findings` legitimately
    // appears twice on the screen — once here, once in "What it can read".
    const tools = [...container.querySelectorAll(".toolchip")].map((e) => e.textContent);
    expect(tools.join(" ")).toMatch(/read\s*list_findings/);
    expect(tools.join(" ")).toMatch(/4 rows/);
  });

  it("reopens a past conversation and shows what the assistant was REFUSED", async () => {
    stub();
    vi.spyOn(api, "conversations").mockResolvedValue([
      { id: "c1", asset_id: "a1", title: "Earlier questions", state: "open",
        input_tokens: 10, output_tokens: 5, created_at: "", updated_at: "" },
    ]);
    vi.spyOn(api, "conversation").mockResolvedValue({
      id: "c1", asset_id: "a1", title: "Earlier questions", state: "open",
      input_tokens: 10, output_tokens: 5, created_at: "", updated_at: "",
      turns: [{ id: "t2", role: "assistant", content: "An answer.", citations: [],
                tool_calls: [], refusals: [{ tool: "-", reason: "invented citation",
                                            detail: "the answer cited f99" }],
                rounds: 1, model: "m", input_tokens: 1, output_tokens: 1,
                error: null, created_at: "" }],
    });

    const { container } = renderScreen(<Chat />);
    await userEvent.click(await screen.findByRole("button", { name: "Earlier questions" }));
    await screen.findByText("An answer.");
    const refusals = [...container.querySelectorAll(".refusechip")].map((e) => e.textContent);
    expect(refusals.join(" ")).toMatch(/refused: invented citation/);
  });

  it("says plainly when the assistant is disabled", async () => {
    stub();
    vi.spyOn(api, "chatCapabilities").mockResolvedValue({ ...CAPS, enabled: false, model: null });
    renderScreen(<Chat />);
    expect(await screen.findByText(/disabled/)).toBeInTheDocument();
    expect(screen.getByText(/grants no new authority/)).toBeInTheDocument();
  });

  it("tells the analyst the assistant cannot act on the platform", async () => {
    stub();
    renderScreen(<Chat />);
    expect(await screen.findByText(/cannot act on the platform/)).toBeInTheDocument();
  });
});
