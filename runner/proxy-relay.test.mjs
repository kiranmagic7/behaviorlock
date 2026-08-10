import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createProxyRelay } from "./proxy-relay.mjs";

function listen(server, ...listenArgs) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(...listenArgs, resolve);
  });
}

test("relays loopback TCP bytes only to the private Unix socket", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "behaviorlock-relay-"));
  const socketPath = path.join(directory, "proxy.sock");
  const upstream = net.createServer((socket) => socket.pipe(socket));
  const relay = createProxyRelay(socketPath);
  try {
    await listen(upstream, socketPath);
    await listen(relay, 0, "127.0.0.1");
    const address = relay.address();
    assert.equal(typeof address, "object");
    const response = await new Promise((resolve, reject) => {
      const client = net.connect({ host: "127.0.0.1", port: address.port }, () => client.write("registry-only"));
      client.once("data", (data) => {
        resolve(data.toString("utf8"));
        client.end();
      });
      client.once("error", reject);
    });
    assert.equal(response, "registry-only");
  } finally {
    relay.close();
    upstream.close();
    await rm(directory, { recursive: true, force: true });
  }
});
