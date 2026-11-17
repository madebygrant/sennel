// One build, two folders. Chrome-family browsers read the `key` that fixes the extension's id and run
// the background as a service worker; Firefox wants its own id, no `key`, and background scripts.
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const base = JSON.parse(readFileSync("manifest.json", "utf8"));
// `node build.js test` packs the test build for Chrome, with the content script's shadow root open
// so the browser tests can look inside it.
const testing = process.argv[2] === "test";

for (const target of testing ? ["test-chrome"] : ["chrome", "firefox"]) {
  const out = `dist/${target}`;
  rmSync(out, { recursive: true, force: true });
  cpSync(testing ? "dist/test-common" : "dist/common", out, { recursive: true });
  if (testing) {
    const content = `${out}/content.js`;
    writeFileSync(content, readFileSync(content, "utf8").replace("const TESTING = false;", "const TESTING = true;"));
  }
  const manifest = structuredClone(base);
  if (target !== "firefox") {
    delete manifest.browser_specific_settings;
    manifest.background = { service_worker: "background.js" };
  } else {
    delete manifest.key;
    manifest.background = { scripts: ["background.js"] };
  }
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2));
}
