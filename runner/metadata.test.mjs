import assert from "node:assert/strict";
import test from "node:test";

import { buildMetadata } from "./metadata.mjs";

const integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

function lockWith(entry) {
  return Buffer.from(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { example: "1.0.0" } },
      "node_modules/example": { version: "1.0.0", integrity, ...entry },
    },
  }));
}

test("accepts exact HTTPS npm registry provenance", () => {
  const metadata = buildMetadata("example@1.0.0", lockWith({
    resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
  }));
  assert.equal(metadata.integrity, integrity);
  assert.equal(metadata.acquisitionPolicyVersion, "npm-registry-connect-v1");
  assert.equal(metadata.allowedAuthority, "registry.npmjs.org:443");
  assert.match(metadata.dependencyLockSha256, /^sha256:[0-9a-f]{64}$/);
});

test("rejects nonregistry, credentialed, linked, and incomplete sources", () => {
  for (const entry of [
    { resolved: "https://registry.npmjs.org.attacker.invalid/example.tgz", integrity },
    { resolved: "https://user:password@registry.npmjs.org/example.tgz", integrity },
    { resolved: "http://registry.npmjs.org/example.tgz", integrity },
    { resolved: "https://registry.npmjs.org:444/example.tgz", integrity },
    { resolved: "git+https://github.com/example/repository.git", integrity },
    { resolved: "file:../example", integrity },
    { link: true, resolved: "https://registry.npmjs.org/example.tgz", integrity },
    { resolved: "https://registry.npmjs.org/example.tgz", integrity: undefined },
  ]) {
    assert.throws(() => buildMetadata("example@1.0.0", lockWith(entry)));
  }
});

test("allows a bundled dependency without a separate acquisition URL", () => {
  const lock = JSON.parse(lockWith({
    resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
  }).toString("utf8"));
  lock.packages["node_modules/example/node_modules/bundled"] = {
    version: "1.0.0",
    inBundle: true,
  };
  assert.equal(buildMetadata("example@1.0.0", Buffer.from(JSON.stringify(lock))).integrity, integrity);
});
