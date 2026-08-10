import { readFileSync } from "node:fs";
import path from "node:path";

export function nearestPackageType(resolved, packageRoot) {
  let directory = path.dirname(resolved);
  for (;;) {
    const relative = path.relative(packageRoot, directory);
    if (relative.startsWith("..") || path.isAbsolute(relative)) return "commonjs";
    try {
      const packageJSON = JSON.parse(readFileSync(path.join(directory, "package.json"), "utf8"));
      return packageJSON?.type === "module" ? "module" : "commonjs";
    } catch (error) {
      if (error?.code !== "ENOENT") return "commonjs";
    }
    if (directory === packageRoot) break;
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return "commonjs";
}

export function resolvedModuleKind(resolved, packageRoot, packageType) {
  const extension = path.extname(resolved).toLowerCase();
  if (extension === ".mjs") return "esm";
  if (extension === ".cjs") return "commonjs";
  if (extension !== ".js") return "unsupported";
  const effectiveType = packageType ?? nearestPackageType(resolved, packageRoot);
  return effectiveType === "module" ? "esm" : "commonjs";
}
