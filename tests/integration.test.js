import { mockServer } from "../mock_server.js";
import { discoverDevices } from "../discovery.js";
import { buildLogger } from "../logger.js";
import { Commands } from "../datatypes.js";

import assert from "assert";

const hstrToU8 = (hs) => new Uint8Array(hs.match(/../g).map((h) => parseInt(h, 16)));
describe("integration", () => {
  it("discovers a device", () => {
    // LanSearch (server) -> PunchPkt (camera) -> discovered serial
    buildLogger("trace");
    const EXPECTED_SERIAL = "BATD156362WONJM";
    const punchPkt = "f14100144241544400000000000262ca574f4e4a4d000000";
    const mockSock = mockServer((msg) => {
      const cmd = msg.readU16();
      if (cmd == Commands.LanSearch) {
        const buf = hstrToU8(punchPkt);
        return [buf];
      }
      return [];
    });
    const ev = discoverDevices("127.0.0.1");
    ev.on("discover", (rinfo, dev) => {
      assert.deepEqual(dev.devId, EXPECTED_SERIAL);
      ev.emit("close");
      mockSock.close();
    });
  });
  // TODO
  it("emits login event upon logging in", () => {
    // LanSearch (server) -> PunchPkt (camera)
    // vvv need to call makeSession vvv
    // P2pRdy (server) -> P2pRdy (camera)
    // Drw<Login> (server) -> [DrwAck, Drw<LoginAck>]
  });
});
