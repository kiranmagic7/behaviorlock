import assert from "node:assert/strict";
import test from "node:test";

import { buildDNSResponse, decodeCanaries, visibleCanaryIDs } from "./sinkhole.mjs";

function dnsQuery(type = 1) {
  return Buffer.from([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, ...Buffer.from("example"), 0x07, ...Buffer.from("invalid"), 0x00,
    0x00, type, 0x00, 0x01,
  ]);
}

test("returns only loopback synthetic DNS answers", () => {
  const ipv4 = buildDNSResponse(dnsQuery(1));
  assert.deepEqual([...ipv4.subarray(-4)], [127, 0, 0, 1]);
  const ipv6 = buildDNSResponse(dnsQuery(28));
  assert.deepEqual([...ipv6.subarray(-16)], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.equal(buildDNSResponse(Buffer.alloc(513)), null);
});

test("reports canary identifiers without returning values", () => {
  const encoded = Buffer.from(JSON.stringify([
    { id: "canary:test-value", value: "behaviorlock-canary.invalid/test-value/0123456789abcdef" },
  ])).toString("base64url");
  const canaries = decodeCanaries(encoded);
  assert.deepEqual(visibleCanaryIDs(Buffer.from(`prefix ${canaries[0].value.toString()} suffix`), canaries), ["canary:test-value"]);
  assert.throws(() => decodeCanaries(Buffer.from('{"not":"an array"}').toString("base64url")));
  assert.throws(() => decodeCanaries(Buffer.from(JSON.stringify([
    { id: "canary:duplicate", value: "behaviorlock-canary.invalid/duplicate/0123456789abcdef" },
    { id: "canary:duplicate", value: "behaviorlock-canary.invalid/other/0123456789abcdef" },
  ])).toString("base64url")));
});
