import dgram from "node:dgram";
import http from "node:http";
import net from "node:net";
import { pathToFileURL } from "node:url";

const policyVersion = "inert-sinkhole-v1";
const maxPayloadBytes = 8 * 1024;
const maxEvents = 4_096;

export function decodeCanaries(encoded = "") {
  if (encoded.length > 16 * 1024) throw new Error("sinkhole_canary_metadata_too_large");
  let entries;
  try {
    entries = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("sinkhole_canary_metadata_invalid");
  }
  if (!Array.isArray(entries) || entries.length > 32) throw new Error("sinkhole_canary_metadata_invalid");
  const identifiers = new Set();
  const values = new Set();
  return entries.map((entry) => {
    if (!entry || typeof entry.id !== "string" || typeof entry.value !== "string" ||
        !/^canary:[a-z0-9][a-z0-9-]{0,88}$/.test(entry.id) ||
        !entry.value.startsWith("behaviorlock-canary.invalid/") || entry.value.length > 256) {
      throw new Error("sinkhole_canary_metadata_invalid");
    }
    if (identifiers.has(entry.id) || values.has(entry.value)) throw new Error("sinkhole_canary_metadata_invalid");
    identifiers.add(entry.id);
    values.add(entry.value);
    return { id: entry.id, value: Buffer.from(entry.value) };
  });
}

export function visibleCanaryIDs(payload, canaries) {
  const bounded = Buffer.from(payload).subarray(0, maxPayloadBytes);
  return canaries.filter((canary) => bounded.includes(canary.value)).map((canary) => canary.id).sort();
}

function questionEnd(packet) {
  if (packet.length < 17) return -1;
  let offset = 12;
  let labels = 0;
  while (offset < packet.length && labels < 128) {
    const length = packet[offset];
    offset += 1;
    if (length === 0) return offset + 4 <= packet.length ? offset + 4 : -1;
    if ((length & 0xc0) !== 0 || length > 63 || offset + length > packet.length) return -1;
    offset += length;
    labels += 1;
  }
  return -1;
}

export function buildDNSResponse(packet) {
  if (!Buffer.isBuffer(packet) || packet.length > 512 || packet.length < 17 || packet.readUInt16BE(4) !== 1) return null;
  const end = questionEnd(packet);
  if (end < 0) return null;
  const type = packet.readUInt16BE(end - 4);
  const address = type === 1 ? Buffer.from([127, 0, 0, 1]) :
    type === 28 ? Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) : null;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(address ? 0x8180 : 0x8183, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(address ? 1 : 0, 6);
  if (!address) return Buffer.concat([header, packet.subarray(12, end)]);
  const answer = Buffer.alloc(12 + address.length);
  answer.writeUInt16BE(0xc00c, 0);
  answer.writeUInt16BE(type, 2);
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(0, 6);
  answer.writeUInt16BE(address.length, 10);
  address.copy(answer, 12);
  return Buffer.concat([header, packet.subarray(12, end), answer]);
}

export function startSinkhole({ canaries, dnsPort = 53, httpPort = 80, tcpPort = 443 } = {}) {
  let events = 0;
  const audit = (kind, canaryIDs = []) => {
    if (events >= maxEvents) return;
    events += 1;
    process.stdout.write(`BEHAVIORLOCK_SINKHOLE_V1 ${JSON.stringify({ kind, canaryIds: canaryIDs })}\n`);
  };

  const dns = dgram.createSocket("udp4");
  dns.on("message", (packet, remote) => {
    audit("dns", visibleCanaryIDs(packet, canaries));
    const response = buildDNSResponse(packet);
    if (response) dns.send(response, remote.port, remote.address);
  });
  dns.bind(dnsPort, "127.0.0.1");

  const web = http.createServer((request, response) => {
    let observed = Buffer.concat([Buffer.from(request.method ?? ""), Buffer.from(request.url ?? "")]).subarray(0, maxPayloadBytes);
    for (const [name, value] of Object.entries(request.headers)) {
      if (observed.length >= maxPayloadBytes) break;
      observed = Buffer.concat([
        observed,
        Buffer.from(name),
        Buffer.from(Array.isArray(value) ? value.join(",") : value ?? ""),
      ]).subarray(0, maxPayloadBytes);
    }
    request.on("data", (chunk) => {
      if (observed.length < maxPayloadBytes) observed = Buffer.concat([observed, chunk]).subarray(0, maxPayloadBytes);
    });
    request.on("end", () => {
      audit("http", visibleCanaryIDs(observed, canaries));
      const body = Buffer.from('{"stage":"behaviorlock-inert-synthetic-v1"}\n');
      response.writeHead(200, { "content-type": "application/json", "content-length": String(body.length), "connection": "close" });
      response.end(body);
    });
  });
  web.maxHeadersCount = 64;
  web.headersTimeout = 2_000;
  web.requestTimeout = 2_000;
  web.listen(httpPort, "127.0.0.1");

  const tcp = net.createServer((socket) => {
    let observed = Buffer.alloc(0);
    socket.setTimeout(2_000, () => socket.destroy());
    socket.on("data", (chunk) => {
      if (observed.length < maxPayloadBytes) observed = Buffer.concat([observed, chunk]).subarray(0, maxPayloadBytes);
    });
    socket.on("close", () => audit("tcp", visibleCanaryIDs(observed, canaries)));
    socket.end("BEHAVIORLOCK_SINKHOLE_STAGE_V1\n");
  });
  tcp.listen(tcpPort, "127.0.0.1");

  return Promise.all([
    new Promise((resolve) => dns.once("listening", resolve)),
    new Promise((resolve) => web.once("listening", resolve)),
    new Promise((resolve) => tcp.once("listening", resolve)),
  ]).then(() => {
    process.stdout.write(`BEHAVIORLOCK_SINKHOLE_READY_V1 ${policyVersion}\n`);
    return { dns, web, tcp };
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let canaries;
  try {
    canaries = decodeCanaries(process.env.BEHAVIORLOCK_SINKHOLE_CANARIES ?? "");
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "sinkhole_start_failed"}\n`);
    process.exit(65);
  }
  startSinkhole({ canaries }).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "sinkhole_start_failed"}\n`);
    process.exit(70);
  });
}
