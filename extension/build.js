// One build, two folders. Chrome-family browsers read the `key` that fixes the extension's id and run
// the background as a service worker; Firefox wants its own id, no `key`, and background scripts.
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const base = JSON.parse(readFileSync("manifest.json", "utf8"));

for (const target of ["chrome", "firefox"]) {
  const out = `dist/${target}`;
  rmSync(out, { recursive: true, force: true });
  cpSync("dist/common", out, { recursive: true });
  const manifest = structuredClone(base);
  if (target === "chrome") {
    delete manifest.browser_specific_settings;
    manifest.background = { service_worker: "background.js" };
  } else {
    delete manifest.key;
    manifest.background = { scripts: ["background.js"] };
  }
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2));
}
