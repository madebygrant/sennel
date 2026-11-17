import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { resolve } from "node:path";

// SENNEL_FAKE_APP=1 builds the test extension, which talks to src/fake-app.js instead of Sennel.
const fake = process.env.SENNEL_FAKE_APP === "1";

export default defineConfig({
  plugins: [svelte()],
  define: { __FAKE_APP__: JSON.stringify(fake) },
  root: "src",
  publicDir: resolve(import.meta.dirname, "public"),
  build: {
    outDir: resolve(import.meta.dirname, fake ? "dist/test-common" : "dist/common"),
    emptyOutDir: true,
    sourcemap: false,
    // Extension pages may not run inline scripts, and nothing is fetched at run time.
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: resolve(import.meta.dirname, "src/popup.html"),
        background: resolve(import.meta.dirname, "src/background.js"),
      },
      // The manifest names the worker by a fixed path.
      output: { entryFileNames: (chunk) => (chunk.name === "background" ? "background.js" : "assets/[name]-[hash].js") },
    },
  },
});
