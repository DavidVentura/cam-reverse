import assert from "assert";
import { buildLogger } from "../logger.js";

import { decode, encode } from "../encode.js";

const hstrToU8 = (hs) => new Uint8Array(hs.match(/../g).map((h) => parseInt(h, 16)));
describe("encode/decode", () => {
  it("decodes example", () => {
    buildLogger("trace");
    const pkt = "2ccb6293bf2321ed0ad7ea318106e0d5a28d800233207369";
    const expected = "f141001444474f4100000000000e3f854e44424e44000000";
    const pktbuf = hstrToU8(pkt);
    const expbuf = hstrToU8(expected);

    assert.deepEqual(decode(new DataView(pktbuf.buffer)), new DataView(expbuf.buffer));
  });
  it("encodes example", () => {
    buildLogger("trace");
    const pkt = "f141001444474f4100000000000e3f854e44424e44000000";
    const expected = "2ccb6293bf2321ed0ad7ea318106e0d5a28d800233207369";
    const pktbuf = hstrToU8(pkt);
    const expbuf = hstrToU8(expected);

    assert.deepEqual(encode(new DataView(pktbuf.buffer)), new DataView(expbuf.buffer));
  });
  it("roundtrips encode/decode", () => {
    buildLogger("trace");
    const pkt = "f141001444474f4100000000000e3f854e44424e44000000";
    const pktbuf = hstrToU8(pkt);
    const encoded = encode(new DataView(pktbuf.buffer));
    assert.deepEqual(decode(encoded), new DataView(pktbuf.buffer));
  });
});
