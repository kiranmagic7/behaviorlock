import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { resolvedModuleKind } from "./module-kind.mjs";

export async function importInstalledPackage(name, base = "/work/package.json") {
  const packageRoot = path.resolve(path.dirname(base), "node_modules", name);
  const requireFromWork = createRequire(base);
  let resolved;
  try {
    resolved = requireFromWork.resolve(name);
  } catch {
    throw new Error("behaviorlock_import_entrypoint_unresolved");
  }
  const relative = path.relative(packageRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("behaviorlock_import_entrypoint_outside_package");
  }
  const kind = resolvedModuleKind(resolved, packageRoot);
  if (kind === "esm") {
    await import(pathToFileURL(resolved).href);
    return { resolved, kind };
  }
  if (kind === "commonjs") {
    requireFromWork(resolved);
    return { resolved, kind };
  }
  throw new Error("behaviorlock_import_entrypoint_unsupported");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  importInstalledPackage(process.argv[2] ?? "").catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "behaviorlock_import_failed"}\n`);
    process.exit(65);
  });
}
