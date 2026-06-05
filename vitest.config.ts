import { defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
    env: {
      // 32+ char test secret so badge-hmac's getSecret() is satisfied in unit tests
      AISEAL_BADGE_SECRET: "test-secret-0123456789abcdef0123456789abcdef",
    },
  },
});
