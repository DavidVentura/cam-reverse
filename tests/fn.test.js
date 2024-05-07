// vim: nowrap
import "../shim.ts";

import assert from "assert";

import { XqBytesDec, XqBytesEnc } from "../func_replacements.js";
import { makeP2pRdy, parseListWifi } from "../handlers.js";
import { parse_PunchPkt, SendDevStatus, SendStartVideo, SendUsrChk, SendWifiDetails } from "../impl.ts";
import { buildLogger } from "../logger.js";
import { placeholderTypes, sprintf } from "../utils.js";

describe("debug_tools", () => {
  it("parses printed data", () => {
    const fmt = "string: %s, int: %d, float: %f, hexint: %02x, newline: \n\n last int: %d";
    const expected_placeholders = ["s", "d", "f", "x", "d"];
    const actual_placeholders = placeholderTypes(fmt);
    assert.deepEqual(actual_placeholders, expected_placeholders);
  });
  it("prints data back", () => {
    const fmt = "string: %s, int: %d, float: %f, hexint: %02x, newline: \n\n last int: %d";
    const in_values = ["potato", 5, 3.5, 0x20, 999];
    const expected_string = "string: potato, int: 5, float: 3.5, hexint: 0x20, newline: \n\n last int: 999";
    assert.deepEqual(sprintf(fmt, in_values), expected_string);
  });
  it("prints leftover after last formatter", () => {
    const fmt = "string: %s and this bit is also printed";
    const in_values = ["potato"];
    const expected_string = "string: potato and this bit is also printed";
    assert.deepEqual(sprintf(fmt, in_values), expected_string);
  });
});

describe("module", () => {
  const simple_enc_bytes = new Uint8Array([
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
  ]);
  const simple_dec_bytes = new Uint8Array([
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]);
  const long_enc_bytes = new Uint8Array([
    0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x43, 0x40, 0x55, 0x42, 0x37, 0x31, 0x38, 0x34, 0x32, 0x30, 0x44, 0x59, 0x4d, 0x57, 0x52, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x33, 0x32, 0x35, 0x34,
    0x37, 0x36, 0x39, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x31, 0x2f, 0x33, 0x34, 0x34, 0x2f, 0x33, 0x34, 0x34, 0x2f,
    0x33, 0x34, 0x34, 0x01, 0x01, 0x01, 0x31, 0x2f, 0x31, 0x2f, 0x31, 0x2f, 0x31, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x31, 0x2f, 0x31, 0x2f, 0x31, 0x2f, 0x31, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x31, 0x2f, 0x31, 0x2f, 0x31, 0x2f, 0x31, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x31, 0x2f, 0x31,
    0x2f, 0x31, 0x2f, 0x31, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  ]);
  const long_dec_bytes = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x41, 0x54, 0x43, 0x36, 0x30, 0x39, 0x35, 0x33, 0x31, 0x45, 0x58, 0x4c, 0x56,
    0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x2e, 0x32, 0x35, 0x35, 0x2e,
    0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x00, 0x00, 0x00, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]);
  it("encrypts without rotation", () => {
    const in_buf = new DataView(new Uint8Array([1, 2, 3, 4]).buffer);
    XqBytesEnc(in_buf, in_buf.byteLength, 0); // this mutates in_buf
    assert.equal(in_buf.add(0).readU8(), 0);
    assert.equal(in_buf.add(1).readU8(), 3);
    assert.equal(in_buf.add(2).readU8(), 2);
    assert.equal(in_buf.add(3).readU8(), 5);
  });
  it("decrypts without rotation", () => {
    const in_buf = new DataView(new Uint8Array([1, 2, 3, 4]).buffer);
    XqBytesDec(in_buf, in_buf.byteLength, 0); // this mutates in_buf
    assert.equal(in_buf.add(0).readU8(), 0);
    assert.equal(in_buf.add(1).readU8(), 3);
    assert.equal(in_buf.add(2).readU8(), 2);
    assert.equal(in_buf.add(3).readU8(), 5);
  });
  it("decrypts simple input", () => {
    const in_buf = new DataView(simple_enc_bytes.buffer.slice(0));
    XqBytesDec(in_buf, simple_enc_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), simple_dec_bytes);
  });
  it("decrypts more complex input", () => {
    const in_buf = new DataView(long_enc_bytes.buffer.slice(0));
    XqBytesDec(in_buf, long_enc_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), long_dec_bytes);
  });
  it("encrypts simple input", () => {
    const in_buf = new DataView(simple_dec_bytes.buffer.slice(0));
    XqBytesEnc(in_buf, simple_dec_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), simple_enc_bytes);
  });
  it("encrypts more complex input", () => {
    const in_buf = new DataView(long_dec_bytes.buffer.slice(0));
    XqBytesEnc(in_buf, long_dec_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), long_enc_bytes);
  });
  /* TODO
  it("decrypts offset dataviews", () => {
    const in_buf = new DataView(simple_enc_bytes.buffer.slice(0));
    XqBytesDec(in_buf, simple_enc_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), simple_dec_bytes);
  });
  */
  it("reverts Enc with Dec", () => {
    const in_buf = new DataView(long_dec_bytes.buffer.slice(0));
    XqBytesEnc(in_buf, long_dec_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), long_enc_bytes); // ENC
    XqBytesDec(in_buf, long_dec_bytes.byteLength, 4); // this mutates in_buf
    assert.deepEqual(new Uint8Array(in_buf.buffer), long_dec_bytes); // DEC
  });
});

const hstrToBA = (hs) => new Uint8Array(hs.match(/../g).map((h) => parseInt(h, 16))).buffer;
const BATohstr = (ba) => [...new Uint8Array(ba.buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
describe("parse packet", () => {
  it("parses PunchPkt", () => {
    const in_pkt_str = "f14100144241544400000000000262ca574f4e4a4d000000";
    const pkt = new DataView(hstrToBA(in_pkt_str));
    const expected = {
      prefix: "BATD",
      serial: "156362",
      suffix: "WONJM",
      serialU64: BigInt(156362),
      devId: "BATD156362WONJM",
    };

    assert.deepEqual(parse_PunchPkt(pkt), expected);
  });
  {
    const in_pkt_str = "f14100145848410000000000000003e24b4d4d4542000000";
    const pkt = new DataView(hstrToBA(in_pkt_str));
    it("parses PunchPkt when prefix is 3 letters long", () => {
      const expected = {
        prefix: "XHA",
        serial: "994",
        suffix: "KMMEB",
        serialU64: BigInt(994),
        devId: "XHA994KMMEB",
      };
      assert.deepEqual(parse_PunchPkt(pkt), expected);
    });
    // https://github.com/DavidVentura/cam-reverse/issues/17#issuecomment-2094819873
    it("replies properly to PunchPkt with 3-letters-long prefix", () => {
      const dev = parse_PunchPkt(pkt);
      const p2prdy = makeP2pRdy(dev);
      let p2pstr = BATohstr(p2prdy);

      assert.deepEqual(in_pkt_str.slice(8), p2pstr.slice(8));
    });
  }
  it("parses wifiscan chan0", () => {
    buildLogger("warning");
    const in_pkt_str =
      "f1d00238d1000009110a03612c020100060000002f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101a741a15822a1010101010101b2fefefe650101010101010101010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ab41a158605c010101010101b6fefefe650101010101010101010101" +
      "404253422f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101a741a158605c010101010101c3fefefe650101010101010101010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101af41a15822a1010101010101c8fefefe650101010101010101010101" +
      "404253422f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101933aac0b5330010101010101b4fefefe650101010101010101010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101973aac0b5330010101010101b4fefefe650101010101010101010101" +
      "40425342"; // incomplete entry
    let pkt = new DataView(hstrToBA(in_pkt_str));
    let payload_len = pkt.add(0xc).readU16LE();
    XqBytesDec(pkt.add(20), payload_len - 4, 4); // this mutates pkt
    const expected = [
      { channel: 0, dbm0: 4294967219, dbm1: 100, mac: "a6:40:a0:59:23:a0", mode: 0, security: 0, ssid: "ACRC.NET" },
      { channel: 0, dbm0: 4294967223, dbm1: 100, mac: "aa:40:a0:59:61:5d", mode: 0, security: 0, ssid: "ACRC.Guest" },
      { channel: 0, dbm0: 4294967234, dbm1: 100, mac: "a6:40:a0:59:61:5d", mode: 0, security: 0, ssid: "ACRC.NET" },
      { channel: 0, dbm0: 4294967241, dbm1: 100, mac: "ae:40:a0:59:23:a0", mode: 0, security: 0, ssid: "ACRC.Guest" },
      { channel: 0, dbm0: 4294967221, dbm1: 100, mac: "92:3b:ad:0a:52:31", mode: 0, security: 0, ssid: "ACRC.NET" },
      { channel: 0, dbm0: 4294967221, dbm1: 100, mac: "96:3b:ad:0a:52:31", mode: 0, security: 0, ssid: "ACRC.Guest" },
    ];

    assert.deepEqual(parseListWifi(pkt), expected);
  });
  it("parses wifiscan chan2", () => {
    buildLogger("warning");
    const in_pkt_str =
      "f1d00404d100000d110a0361f80300000b0000002f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101603735316031340101010101c701010165010101010101010301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101606035316031340101010101c7010101650101010101010103010101" + // frame
      "404253422f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101603735316031340101010101c2010101650101010101010103010101" +
      "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101676460373736320101010101b1010101650101010101010103010101" +
      "404253422f4f44550101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101383332636065310101010101af010101650101010101010103010101" +
      "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101393764606465350101010101af010101650101010101010103010101" +
      "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101326460603964670101010101ac010101650101010101010103010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101606435316031340101010101c7010101650101010101010103010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101606035316031340101010101c2010101650101010101010103010101" +
      "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101643562323360620101010101b3010101650101010101010103010101" +
      "404253422f4674647275010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101383732636065310101010101af010101650101010101010103010101" +
      "40425342"; // incomplete
    let pkt = new DataView(hstrToBA(in_pkt_str));
    let payload_len = pkt.add(0xc).readU16LE();
    XqBytesDec(pkt.add(20), payload_len - 4, 4); // this mutates pkt
    const expected = [
      { ssid: "ACRC.NET", mac: "61:36:34:30:61:30", security: 0, dbm0: 198, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "", mac: "61:61:34:30:61:30", security: 0, dbm0: 198, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "ACRC.NET", mac: "61:36:34:30:61:30", security: 0, dbm0: 195, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "", mac: "66:65:61:36:36:37", security: 0, dbm0: 176, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "ACRC.NET", mac: "39:32:33:62:61:64", security: 0, dbm0: 174, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "", mac: "38:36:65:61:65:64", security: 0, dbm0: 174, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "", mac: "33:65:61:61:38:65", security: 0, dbm0: 173, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "ACRC.Guest", mac: "61:65:34:30:61:30", security: 0, dbm0: 198, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "ACRC.Guest", mac: "61:61:34:30:61:30", security: 0, dbm0: 195, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "", mac: "65:34:63:33:32:61", security: 0, dbm0: 178, dbm1: 100, mode: 0, channel: 2 },
      { ssid: "ACRC.Guest", mac: "39:36:33:62:61:64", security: 0, dbm0: 174, dbm1: 100, mode: 0, channel: 2 },
    ];

    assert.deepEqual(parseListWifi(pkt), expected);
  });
});
describe("make packet", () => {
  it("builds a good SendUsrChk", () => {
    const expected_str =
      "f1d000b0d1000000110a2010a400ff00000000006f01010101010101010101010101010101010101010101010101010160656c686f01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010160656c68";
    const expected = hstrToBA(expected_str);
    const sess = { outgoingCommandId: 0, ticket: [0, 0, 0, 0] };
    assert.deepEqual(SendUsrChk(sess, "admin", "admin").buffer, expected);
  });
  it("builds a good SendStartVideo", () => {
    const _expected_str = "f1d00010d1000000110a10300400000001020304";
    const expected = hstrToBA(_expected_str);

    const sess = { outgoingCommandId: 0, ticket: [1, 2, 3, 4] };
    const got = SendStartVideo(sess);
    assert.deepEqual(got.buffer, expected);
  });
  it("builds a good SendDevStatus", () => {
    const sess = { outgoingCommandId: 0, ticket: [1, 2, 3, 4] };
    const _expected_str = "f1d00010d1000000110a08100400000001020304";
    const expected = hstrToBA(_expected_str);

    const got = SendDevStatus(sess);
    assert.deepEqual(got.buffer, expected);
  });
  it("builds a good WifiSettingsSet", () => {
    const sess = { outgoingCommandId: 2, ticket: [1, 2, 3, 4] };
    const _expected_str =
      "f1d00118d1000002110a01600c01000001020304" + // drw header + ticket
      "0101010101010101010101010101010100010101" + // all zeroes, but DHCP u32
      // set to 1
      "726a786f64750101010101010101010101010101010101010101010101010101" + // ssid
      "7274716473627360710101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101" + // pass
      "312f312f312f31010101010101010101" + // 0.0.0.0
      "312f3334342f3334342f333434010101" + // 0.255.255.255
      "312f312f312f31010101010101010101" + // 0.0.0.0
      "312f312f312f31010101010101010101" + // 0.0.0.0
      "312f312f312f31010101010101010101" + // 0.0.0.0
      "01010101"; // 0000
    const expected = hstrToBA(_expected_str);

    const got = SendWifiDetails(sess, "skynet", "supercrap", true);
    assert.deepEqual(got.buffer, expected);
  });
});
