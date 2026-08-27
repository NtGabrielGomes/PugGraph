/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

const libsodiumCjs = fileURLToPath(
  new URL("./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url),
);

const srcRoot = fileURLToPath(new URL("./src", import.meta.url));

const loroBrowser = fileURLToPath(new URL("./node_modules/loro-crdt/browser/index.js", import.meta.url));
const loroNode = fileURLToPath(new URL("./node_modules/loro-crdt/nodejs/index.js", import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": srcRoot,
      "libsodium-wrappers": libsodiumCjs,
      ...(process.env.VITEST
        ? { "loro-crdt": loroNode }
        : { "loro-crdt": loroBrowser }),
    },
  },

  optimizeDeps: {
    exclude: ["loro-crdt"],
  },

  test: {
    environment: "node",
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
});
