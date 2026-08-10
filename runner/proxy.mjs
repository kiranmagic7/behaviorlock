import dns from "node:dns/promises";
import { chmodSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { pathToFileURL } from "node:url";

export const POLICY_VERSION = "npm-registry-connect-v1";
export const ALLOWED_AUTHORITY = "registry.npmjs.org:443";
const MAX_ACTIVE_TUNNELS = 64;

const blockedIPv4 = new net.BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]) {
  blockedIPv4.addSubnet(address, prefix, "ipv4");
}

const allowedIPv6 = new net.BlockList();
allowedIPv6.addSubnet("2000::", 3, "ipv6");
const blockedIPv6 = new net.BlockList();
for (const [address, prefix] of [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
]) {
  blockedIPv6.addSubnet(address, prefix, "ipv6");
}

export function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    return !blockedIPv4.check(address, "ipv4");
  }
  if (family === 6) {
    return allowedIPv6.check(address, "ipv6") && !blockedIPv6.check(address, "ipv6");
  }
  return false;
}

export function validateAuthority(authority) {
  if (authority !== ALLOWED_AUTHORITY) {
    throw new Error("authority_not_allowed");
  }
  return { host: "registry.npmjs.org", port: 443 };
}

export function validateConnectRequest(request) {
  if (request.method !== "CONNECT") {
    throw new Error("method_not_allowed");
  }
  if (request.httpVersion !== "1.1") {
    throw new Error("http_version_not_allowed");
  }
  validateAuthority(request.url);
  if (request.headers.host !== ALLOWED_AUTHORITY) {
    throw new Error("host_header_not_allowed");
  }
  if (request.rawHeaders.length > 64) {
    throw new Error("too_many_headers");
  }
  let hostHeaders = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (String(request.rawHeaders[index]).toLowerCase() === "host") {
      hostHeaders += 1;
    }
  }
  if (hostHeaders !== 1) {
    throw new Error("host_header_count");
  }
  for (const name of ["transfer-encoding", "content-length", "proxy-authorization", "upgrade"]) {
    if (request.headers[name] !== undefined) {
      throw new Error("unsafe_connect_header");
    }
  }
}

export async function resolveAllowedHost(lookup = dns.lookup) {
  const records = await lookup("registry.npmjs.org", { all: true, verbatim: true });
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error("dns_empty");
  }
  for (const record of records) {
    if ((record.family !== 4 && record.family !== 6) || !isPublicAddress(record.address)) {
      throw new Error("dns_nonpublic");
    }
  }
  return [...records].sort((left, right) => {
    if (left.family !== right.family) {
      return left.family - right.family;
    }
    return left.address.localeCompare(right.address);
  })[0];
}

function proxyResponse(socket, status, message) {
  if (!socket.destroyed) {
    socket.end(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  }
}

function audit(logger, decision, reason, authority = "") {
  logger(`BEHAVIORLOCK_PROXY_V1 ${JSON.stringify({ decision, reason, authority })}`);
}

export function createRegistryProxy({
  lookup = dns.lookup,
  connect = net.connect,
  logger = (line) => process.stdout.write(`${line}\n`),
} = {}) {
  let activeTunnels = 0;
  const server = http.createServer((_request, response) => {
    response.writeHead(405, { Connection: "close", "Content-Length": "0" });
    response.end();
  });
  server.maxHeadersCount = 32;
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 1_000;

  server.on("connect", async (request, client, head) => {
    client.on("error", () => {});
    if (activeTunnels >= MAX_ACTIVE_TUNNELS) {
      audit(logger, "deny", "tunnel_limit", request.url);
      proxyResponse(client, 503, "Service Unavailable");
      return;
    }
    activeTunnels += 1;
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        activeTunnels -= 1;
      }
    };
    client.once("close", release);

    try {
      validateConnectRequest(request);
      const record = await resolveAllowedHost(lookup);
      const upstream = connect({ host: record.address, port: 443, family: record.family });
      let connected = false;
      upstream.setTimeout(120_000, () => upstream.destroy(new Error("upstream_timeout")));
      client.setTimeout(120_000, () => client.destroy(new Error("client_timeout")));
      upstream.once("connect", () => {
        connected = true;
        audit(logger, "allow", POLICY_VERSION, request.url);
        client.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: BehaviorLock\r\n\r\n");
        if (head.length > 0) {
          upstream.write(head);
        }
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.once("error", () => {
        audit(logger, "deny", "upstream_error", request.url);
        if (!connected) {
          proxyResponse(client, 502, "Bad Gateway");
        } else {
          client.destroy();
        }
      });
      upstream.once("close", () => {
        if (!client.destroyed) {
          client.end();
        }
      });
    } catch (error) {
      audit(logger, "deny", error instanceof Error ? error.message : "request_rejected", request.url);
      proxyResponse(client, 403, "Forbidden");
    }
  });

  server.on("clientError", (_error, socket) => {
    audit(logger, "deny", "malformed_http");
    proxyResponse(socket, 400, "Bad Request");
  });
  return server;
}

export function startRegistryProxy(socketPath = "/proxy/proxy.sock") {
  if (typeof process.getuid !== "function" || process.getuid() !== 65532) {
    throw new Error("proxy_process_must_run_as_uid_65532");
  }
  const server = createRegistryProxy();
  server.listen(socketPath, () => {
    chmodSync(socketPath, 0o600);
    process.stdout.write(`BEHAVIORLOCK_PROXY_READY_V1 ${POLICY_VERSION} ${ALLOWED_AUTHORITY}\n`);
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startRegistryProxy(process.env.BEHAVIORLOCK_PROXY_SOCKET || "/proxy/proxy.sock");
}
