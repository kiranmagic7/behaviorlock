import { writeFileSync } from "node:fs";
import net from "node:net";
import { pathToFileURL } from "node:url";

export function createProxyRelay(socketPath = "/proxy/proxy.sock") {
  return net.createServer((client) => {
    client.on("error", () => {});
    const upstream = net.connect(socketPath);
    upstream.on("error", () => client.destroy());
    client.pipe(upstream);
    upstream.pipe(client);
  });
}

export function startProxyRelay() {
  const server = createProxyRelay(process.env.BEHAVIORLOCK_PROXY_SOCKET || "/proxy/proxy.sock");
  server.listen(8080, "127.0.0.1", () => {
    writeFileSync("/tmp/behaviorlock-relay-ready", "ready\n", { mode: 0o600 });
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startProxyRelay();
}
