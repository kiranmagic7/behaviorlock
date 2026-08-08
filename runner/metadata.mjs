import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const spec = process.argv[2] ?? "";
const separator = spec.lastIndexOf("@");
const name = spec.slice(0, separator);
const lockBytes = readFileSync("/seed/package-lock.json");
const lock = JSON.parse(lockBytes.toString("utf8"));
const entry = lock.packages?.[`node_modules/${name}`];

if (!entry || typeof entry.integrity !== "string") {
  process.stderr.write("installed package integrity metadata is missing\n");
  process.exit(65);
}

process.stdout.write(JSON.stringify({
  integrity: entry.integrity,
  dependencyLockSha256: `sha256:${createHash("sha256").update(lockBytes).digest("hex")}`,
}));
