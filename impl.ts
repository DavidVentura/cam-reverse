import "./shim.ts";

import { Commands } from "./datatypes.js";
import { Session } from "./server.js";
import { XqBytesEnc } from "./func_replacements.js";
import { hexdump } from "./hexdump.js";
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

const DrwHdr = (cmd: number, len: number, d1_or_d2: 0xd1 | 0xd2, m_chan: number, pkt_id: number): DataView => {
  let retret = new DataView(new Uint8Array(len + 4).buffer);
  retret.writeU16(cmd);
  retret.add(2).writeU16(len); // buflen -4?
  retret.add(4).writeU8(d1_or_d2);
  retret.add(5).writeU8(m_chan); // chan? hardcoded
  retret.add(6).writeU16(pkt_id);
  return retret;
};
export const SendDevStatus = (session: Session): DataView => {
  let buf = new DataView(new Uint8Array(0x14).buffer);

  /*
00000000  f1 d0 00 10 d1 00 00 c3 11 0a 08 10 04 00 00 00  ................
00000010  68 66 6b 67                                      hfkg
*/
  let bytes = [
    0xf1,
    0xd0,
    0x00, // len? lower values= no response, larger values = 1 frame then kicked
    0x10, // len
    0xd1, // ?
    0x00, // chan
    session.outgoingCommandId >> 8,
    session.outgoingCommandId,
    0x11,
    0x0a,
    0x08,
    0x10,
    0x04, // len
    0x00, // len
    0x00, // dst
    0x00, // dst
    session.ticket[0],
    session.ticket[1],
    session.ticket[2],
    session.ticket[3],
  ];
  buf.writeByteArray(bytes);
  return buf;
};

export const SendStartVideo = (session: Session): DataView => {
  // TODO: extract SendUsrChk
  let buf = new DataView(new Uint8Array(0x18).buffer);
  // console.log(hexdump(DrwHdr(0xf1d0, 0x0114, 0xd1, 0, pkt_id).buffer));

  let bytes = [
    0xf1,
    0xd0,
    0x01, // len? lower values= no response, larger values = 1 frame then kicked
    0x14, // len
    0xd1, // ?
    0x00, // chan
    session.outgoingCommandId >> 8,
    session.outgoingCommandId,
    0x11,
    0x0a,
    0x10,
    0x30,
    0x08,
    0x01,
    0x00,
    0x00,
    session.ticket[0],
    session.ticket[1],
    session.ticket[2],
    session.ticket[3],
    0x01,
    0x01,
    0x01,
    0x01,
  ];
  buf.writeByteArray(bytes);
  return buf;
};
export const SendUsrChk = (username: string, password: string, pkt_id: number): DataView => {
  // type is char account[0x20]; char password[0x80];
  let buf = new Uint8Array(0x20 + 0x80);
  buf.fill(0);
  let cmd_payload = new DataView(buf.buffer);
  cmd_payload.writeByteArray(str2byte(username));
  cmd_payload.add(0x20).writeByteArray(str2byte(password));

  const start = 0xa11;
  const dest = 0xff;
  const cmd = 0x1020; // FIXME ControlCommands.ConnectUser
  const len = buf.byteLength;
  let cmdHeader = CmdSndProcHdr(start, cmd, len, dest);
  let ret = new DataView(new Uint8Array(12 + len).buffer);
  ret.writeByteArray(new Uint8Array(cmdHeader.buffer));
  XqBytesEnc(cmd_payload, 0x20 + 0x80, 4);
  ret.add(12).writeByteArray(new Uint8Array(cmd_payload.buffer));

  // need to encapsulate this into create_Drw(outbuf, 0xd1, param4?, svar1?,
  // copy_len, inbuf); seems like param4/svar1 are overflowing == maybe '0xa'
  // and '0x2010'??
  let retret = DrwHdr(0xf1d0, 8 + 12 + len - 4, 0xd1, 0, pkt_id);
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
