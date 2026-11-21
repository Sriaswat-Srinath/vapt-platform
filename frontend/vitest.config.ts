import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Tests run against jsdom with no network: every API call is stubbed. The point
// is the screens' behaviour — what an analyst sees and can do — not a second
// copy of the backend's assertions.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
