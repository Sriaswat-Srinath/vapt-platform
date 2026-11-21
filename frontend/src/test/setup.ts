import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  try {
    sessionStorage.clear();
  } catch {
    /* jsdom always has it; a browser in private mode may not */
  }
});

// jsdom implements no layout, so `scrollIntoView` does not exist. The chat log
// scrolls to the newest turn; without this the whole render throws, which would
// look like a product bug and is not one.
Element.prototype.scrollIntoView = vi.fn();

// Nothing in these tests may reach the network. A test that tries has a bug:
// the API is stubbed per test, so an unstubbed call should fail loudly.
globalThis.fetch = vi.fn(() => {
  throw new Error("unstubbed fetch: stub the api module for this test");
}) as unknown as typeof fetch;
