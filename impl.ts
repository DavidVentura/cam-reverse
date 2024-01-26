import "./shim.ts";

import { Commands, XqBytesEnc } from "./func_replacements.js";
import { u16_swap } from "./utils.js";

const str2byte = (s: string): number[] => {
  return Array.from(s).map((_, i) => s.charCodeAt(i));
};

const CmdSndProcHdr = (start: number, cmd: number, len: number, dest: number): DataView => {
  len = len + 4; // hdr size?
  let cmdHeader = new DataView(new Uint8Array(8).buffer);
  cmdHeader.writeU16(u16_swap(start));
  cmdHeader.add(2).writeU16(u16_swap(cmd));
  cmdHeader.add(4).writeU16(u16_swap(len));
  cmdHeader.add(6).writeU16(u16_swap(dest));
  return cmdHeader;
};

const DrwHdr = (cmd: number, len: number, d1_or_d2: 0xd1 | 0xd2, m_chan: number): DataView => {
  let retret = new DataView(new Uint8Array(len + 4).buffer);
  retret.writeU16(cmd);
  retret.add(2).writeU16(len); // buflen -4?
  retret.add(4).writeU16(u16_swap(d1_or_d2));
  retret.add(6).writeU16(m_chan); // chan? hardcoded
  return retret;
};

export const SendUsrAck = (challenge: number[]): DataView => {
  // TODO: extract SendUsrChk
  let buf = new DataView(new Uint8Array(0x18).buffer);
  const seq = 0x1;
  let bytes = [
    0xf1,
    0xd0,
    0x01,
    0x14,
    0xd1,
    0x00,
    0x00,
    seq,
    0x11,
    0x0a,
    0x10,
    0x30,
    0x08,
    0x01,
    0x00,
    0x00,
    challenge[0] % 2 == 0 ? challenge[0] + 1 : challenge[0] - 1,
    challenge[1] % 2 == 0 ? challenge[1] + 1 : challenge[1] - 1,
    challenge[2] % 2 == 0 ? challenge[2] + 1 : challenge[2] - 1,
    challenge[3] % 2 == 0 ? challenge[3] + 1 : challenge[3] - 1,
    0x01,
    0x01,
    0x01,
    0x01,
  ];
  buf.writeByteArray(bytes);
  return buf;
};
export const SendUsrChk = (username: string, password: string): DataView => {
  // type is char account[0x20]; char password[0x80];
  let buf = new Uint8Array(0x20 + 0x80);
  buf.fill(0);
  let cmd_payload = new DataView(buf.buffer);
  cmd_payload.writeByteArray(str2byte(username));
  cmd_payload.add(0x20).writeByteArray(str2byte(password));

  const start = 0xa11;
  const dest = 0xff;
  const cmd = 0x1020;
  const len = buf.byteLength;
  let cmdHeader = CmdSndProcHdr(start, cmd, len, dest);
  let ret = new DataView(new Uint8Array(12 + len).buffer);
  ret.writeByteArray(new Uint8Array(cmdHeader.buffer));
  XqBytesEnc(cmd_payload, 0x20 + 0x80, 4);
  ret.add(12).writeByteArray(new Uint8Array(cmd_payload.buffer));

  // need to encapsulate this into create_Drw(outbuf, 0xd1, param4?, svar1?,
  // copy_len, inbuf); seems like param4/svar1 are overflowing == maybe '0xa'
  // and '0x2010'??
  let retret = DrwHdr(0xf1d0, 8 + 12 + len - 4, 0xd1, 0);
  retret.add(8).writeByteArray(new Uint8Array(ret.buffer));
  return retret;
};

export const create_P2pRdy = (inbuf: DataView): DataView => {
  const P2PRDY_SIZE = 0x14;
  const outbuf = new DataView(new Uint8Array(P2PRDY_SIZE + 4).buffer);
  outbuf.writeU16(Commands.P2pRdy);
  outbuf.add(2).writeU16(P2PRDY_SIZE);
  outbuf.add(4).writeByteArray(new Uint8Array(inbuf.readByteArray(P2PRDY_SIZE).buffer));
  return outbuf;
};
