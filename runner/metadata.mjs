import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export function buildMetadata(spec, lockBytes) {
  const separator = spec.lastIndexOf("@");
  const name = spec.slice(0, separator);
  const lock = JSON.parse(lockBytes.toString("utf8"));
  if (!lock.packages || typeof lock.packages !== "object") {
    throw new Error("dependency lock package inventory is missing");
  }
  for (const [packagePath, packageEntry] of Object.entries(lock.packages)) {
    if (!packagePath.startsWith("node_modules/") || !packageEntry || typeof packageEntry !== "object") {
      continue;
    }
    if (packageEntry.link === true) {
      throw new Error("local or linked dependency sources are not allowed");
    }
    if (packageEntry.resolved === undefined && packageEntry.inBundle === true) {
      continue;
    }
    if (typeof packageEntry.resolved !== "string" || typeof packageEntry.integrity !== "string") {
      throw new Error("registry dependency provenance is incomplete");
    }
    let resolved;
    try {
      resolved = new URL(packageEntry.resolved);
    } catch {
      throw new Error("dependency source URL is invalid");
    }
    if (
      resolved.protocol !== "https:" ||
      resolved.hostname !== "registry.npmjs.org" ||
      (resolved.port !== "" && resolved.port !== "443") ||
      resolved.username !== "" ||
      resolved.password !== ""
    ) {
      throw new Error("dependency source is outside the public npm registry allowlist");
    }
  }
  const entry = lock.packages[`node_modules/${name}`];
  if (!entry || typeof entry.integrity !== "string") {
    throw new Error("installed package integrity metadata is missing");
  }
  return {
    integrity: entry.integrity,
    dependencyLockSha256: `sha256:${createHash("sha256").update(lockBytes).digest("hex")}`,
    acquisitionPolicyVersion: "npm-registry-connect-v1",
    allowedAuthority: "registry.npmjs.org:443",
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const spec = process.argv[2] ?? "";
    const lockBytes = readFileSync("/seed/package-lock.json");
    process.stdout.write(JSON.stringify(buildMetadata(spec, lockBytes)));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "metadata validation failed"}\n`);
    process.exit(65);
  }
}
