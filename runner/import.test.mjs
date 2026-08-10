import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { importInstalledPackage } from "./import.mjs";

async function fixture(t, name, packageJSON, source, extension = "js") {
  const root = await mkdtemp(path.join(os.tmpdir(), "behaviorlock-import-"));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })); });
  await writeFile(path.join(root, "package.json"), JSON.stringify({ private: true }));
  const packageRoot = path.join(root, "node_modules", name);
  await mkdir(packageRoot, { recursive: true });
  await writeFile(path.join(packageRoot, "package.json"), JSON.stringify(packageJSON));
  await writeFile(path.join(packageRoot, `index.${extension}`), source);
  return path.join(root, "package.json");
}

test("loads CommonJS and ESM entry points", async (t) => {
  const commonBase = await fixture(t, "common-example", { main: "index.cjs" }, "module.exports = 42;", "cjs");
  assert.equal((await importInstalledPackage("common-example", commonBase)).kind, "commonjs");
  const esmBase = await fixture(t, "esm-example", { type: "module", main: "index.js" }, "export default 42;");
  assert.equal((await importInstalledPackage("esm-example", esmBase)).kind, "esm");
});

test("reports thrown and unsupported entry points explicitly", async (t) => {
  const thrownBase = await fixture(t, "throw-example", { main: "index.cjs" }, "throw new Error('fixture-threw');", "cjs");
  await assert.rejects(() => importInstalledPackage("throw-example", thrownBase), /fixture-threw/);
  const unsupportedBase = await fixture(t, "native-example", { main: "index.node" }, "not a native addon", "node");
  await assert.rejects(() => importInstalledPackage("native-example", unsupportedBase), /behaviorlock_import_entrypoint_unsupported/);
  await assert.rejects(() => importInstalledPackage("missing-example", unsupportedBase), /behaviorlock_import_entrypoint_unresolved/);
});
