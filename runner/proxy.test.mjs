import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import {
  ALLOWED_AUTHORITY,
  createRegistryProxy,
  isPublicAddress,
  resolveAllowedHost,
  validateAuthority,
  validateConnectRequest,
} from "./proxy.mjs";

function listen(server, ...listenArgs) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(...listenArgs, resolve);
  });
}

function rawRequest(port, payload) {
  return new Promise((resolve, reject) => {
    let response = "";
    const socket = net.connect({ host: "127.0.0.1", port }, () => socket.write(payload));
    socket.on("data", (data) => {
      response += data.toString("utf8");
      if (response.includes("\r\n\r\n")) socket.end();
    });
    socket.once("error", reject);
    socket.setTimeout(2_000, () => reject(new Error("proxy_test_timeout")));
    socket.once("close", () => resolve(response));
  });
}

function request(overrides = {}) {
  return {
    method: "CONNECT",
    httpVersion: "1.1",
    url: ALLOWED_AUTHORITY,
    headers: { host: ALLOWED_AUTHORITY },
    rawHeaders: ["Host", ALLOWED_AUTHORITY],
    ...overrides,
  };
}

test("accepts only the exact npm registry authority", () => {
  assert.deepEqual(validateAuthority(ALLOWED_AUTHORITY), { host: "registry.npmjs.org", port: 443 });
  for (const authority of [
    "registry.npmjs.org:80",
    "REGISTRY.NPMJS.ORG:443",
    "registry.npmjs.org.:443",
    "registry.npmjs.org.attacker.invalid:443",
    "registry.npmjs.org@attacker.invalid:443",
    "127.0.0.1:443",
    "[::1]:443",
    "registry.npmjs.org:443 ",
    "registry．npmjs.org:443",
    "registry.npmjs.org:443 HTTP/1.1\r\nHost: attacker.invalid",
  ]) {
    assert.throws(() => validateAuthority(authority), /authority_not_allowed/);
  }
});

test("rejects malformed or smuggling-prone CONNECT metadata", () => {
  validateConnectRequest(request());
  assert.throws(() => validateConnectRequest(request({ method: "GET" })), /method_not_allowed/);
  assert.throws(() => validateConnectRequest(request({ httpVersion: "1.0" })), /http_version_not_allowed/);
  assert.throws(
    () => validateConnectRequest(request({ rawHeaders: ["Host", ALLOWED_AUTHORITY, "Host", ALLOWED_AUTHORITY] })),
    /host_header_count/,
  );
  for (const name of ["transfer-encoding", "content-length", "proxy-authorization", "upgrade"]) {
    assert.throws(
      () => validateConnectRequest(request({ headers: { host: ALLOWED_AUTHORITY, [name]: "1" } })),
      /unsafe_connect_header/,
    );
  }
});

test("accepts public addresses and rejects special-use ranges", () => {
  for (const address of ["104.16.1.1", "8.8.8.8", "2606:4700:4700::1111"]) {
    assert.equal(isPublicAddress(address), true, address);
  }
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.0.2.1",
    "192.168.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:10.0.0.1",
    "2001:db8::1",
    "3fff::1",
    "fc00::1",
    "fe80::1",
    "ff00::1",
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test("rejects a mixed public and nonpublic DNS answer", async () => {
  await assert.rejects(
    resolveAllowedHost(async () => [
      { address: "104.16.1.1", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ]),
    /dns_nonpublic/,
  );
});

test("dials a validated resolved address instead of the hostname", async () => {
  const result = await resolveAllowedHost(async (hostname, options) => {
    assert.equal(hostname, "registry.npmjs.org");
    assert.deepEqual(options, { all: true, verbatim: true });
    return [
      { address: "2606:4700:4700::1111", family: 6 },
      { address: "104.16.1.1", family: 4 },
    ];
  });
  assert.deepEqual(result, { address: "104.16.1.1", family: 4 });
});

test("the HTTP parser fails closed on methods, duplicate hosts, and framing headers", async () => {
  const server = createRegistryProxy({ logger: () => {} });
  try {
    await listen(server, 0, "127.0.0.1");
    const address = server.address();
    assert.equal(typeof address, "object");
    const cases = [
      [
        "GET https://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n",
        "HTTP/1.1 405",
      ],
      [
        `CONNECT ${ALLOWED_AUTHORITY} HTTP/1.1\r\nHost: ${ALLOWED_AUTHORITY}\r\nHost: ${ALLOWED_AUTHORITY}\r\n\r\n`,
        "HTTP/1.1 403",
      ],
      [
        `CONNECT ${ALLOWED_AUTHORITY} HTTP/1.1\r\nHost: ${ALLOWED_AUTHORITY}\r\nTransfer-Encoding: chunked\r\n\r\n`,
        "HTTP/1.1 403",
      ],
      [
        `CONNECT ${ALLOWED_AUTHORITY} HTTP/1.1\r\nHost: ${ALLOWED_AUTHORITY}\r\nContent-Length: 0\r\n\r\n`,
        "HTTP/1.1 403",
      ],
    ];
    for (const [payload, expected] of cases) {
      assert.match(await rawRequest(address.port, payload), new RegExp(`^${expected}`));
    }
  } finally {
    server.close();
  }
});
