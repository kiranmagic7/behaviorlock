import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { nearestPackageType, resolvedModuleKind } from "./module-kind.mjs";

test("uses the nearest package scope for JavaScript module kind", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "behaviorlock-module-kind-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "package.json"), JSON.stringify({ type: "commonjs" }));
  const nested = path.join(root, "dist");
  await mkdir(nested);
  await writeFile(path.join(nested, "package.json"), JSON.stringify({ type: "module" }));
  const entrypoint = path.join(nested, "index.js");
  await writeFile(entrypoint, "export default 42;\n");

  assert.equal(nearestPackageType(entrypoint, root), "module");
  assert.equal(resolvedModuleKind(entrypoint, root), "esm");
  assert.equal(resolvedModuleKind(path.join(root, "index.cjs"), root), "commonjs");
  assert.equal(resolvedModuleKind(path.join(root, "addon.node"), root), "unsupported");
});
