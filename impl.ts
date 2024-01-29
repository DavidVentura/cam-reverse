import "./shim.ts";

import { ControlCommands, Commands, ccDest } from "./datatypes.js";
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

const makeDataReadWrite = (session: Session, command: number, data: DataView | null): DataView => {
  const DRW_HEADER_LEN = 0x10;
  const TOKEN_LEN = 0x4;
  const CHANNEL = 0;
  const START_CMD = 0x110a;

  let pkt_len = DRW_HEADER_LEN + TOKEN_LEN;
  let payload_len = TOKEN_LEN;
  let bufCopy: Uint8Array | null = null;
  if (data) {
    bufCopy = new Uint8Array(data.buffer);
    const bufDV = new DataView(bufCopy.buffer);
    // this mutates the buffer, don't want to mutate the caller
    XqBytesEnc(bufDV, bufDV.byteLength, 4);
    pkt_len += bufDV.byteLength;
    payload_len += bufDV.byteLength;
  }

  const ret = new DataView(new Uint8Array(pkt_len).buffer);
  ret.add(0).writeU16(Commands.Drw);
  ret.add(2).writeU16(pkt_len - 4); // -4 as we ignore the [0xf1, 0xd0, len, len]
  ret.add(4).writeU8(0xd1); // ?
  ret.add(5).writeU8(CHANNEL);
  ret.add(6).writeU16(session.outgoingCommandId);
  ret.add(8).writeU16(START_CMD);
  ret.add(10).writeU16(command);
  ret.add(12).writeU16(u16_swap(payload_len));
  ret.add(14).writeU16(ccDest[command]);
  ret.add(16).writeByteArray(session.ticket);
  if (data) {
    ret.add(20).writeByteArray(bufCopy);
  }

  return ret;
};

export const SendDevStatus = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.DevStatus, null);
};

export const SendWifiSettings = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.WifiSettings, null);
};

export const SendListWifi = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.ListWifi, null);
};

export const SendStartVideo = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.StartVideo, null);
};

export const SendUsrChk = (session: Session, username: string, password: string): DataView => {
  let buf = new Uint8Array(0x20 + 0x80);
  buf.fill(0);
  let cmd_payload = new DataView(buf.buffer);
  // type is char account[0x20]; char password[0x80];
  cmd_payload.writeByteArray(str2byte(username));
  cmd_payload.add(0x20).writeByteArray(str2byte(password));
  return makeDataReadWrite(session, ControlCommands.ConnectUser, cmd_payload);
};

export const create_LanSearch = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.LanSearch);
  outbuf.add(2).writeU16(0x0);
  return outbuf;
};

export const create_P2pRdy = (inbuf: DataView): DataView => {
  const P2PRDY_SIZE = 0x14;
  const outbuf = new DataView(new Uint8Array(P2PRDY_SIZE + 4).buffer);
  outbuf.writeU16(Commands.P2pRdy);
  outbuf.add(2).writeU16(P2PRDY_SIZE);
  outbuf.add(4).writeByteArray(new Uint8Array(inbuf.readByteArray(P2PRDY_SIZE).buffer));
  return outbuf;
};

export const create_P2pAlive = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.P2PAlive);
  outbuf.add(2).writeU16(0);
  return outbuf;
};
