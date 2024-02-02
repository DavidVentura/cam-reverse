import "./shim.js";

import { ccDest, Commands, ControlCommands } from "./datatypes.js";
import { XqBytesEnc } from "./func_replacements.js";
import { hexdump } from "./hexdump.js";
import { Session } from "./session.js";
import { u16_swap } from "./utils.js";

const str2byte = (s: string): number[] => {
  return Array.from(s).map((_, i) => s.charCodeAt(i));
};

const makeDataReadWrite = (session: Session, command: number, data: DataView | null): DataView => {
  const DRW_HEADER_LEN = 0x10;
  const TOKEN_LEN = 0x4;
  const CHANNEL = 0;
  const START_CMD = 0x110a;

  let pkt_len = DRW_HEADER_LEN + TOKEN_LEN;
  let payload_len = TOKEN_LEN;
  let bufCopy: Uint8Array | null = null;
  if (data && data.byteLength > 4) {
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
  if (data && data.byteLength > 4) {
    ret.add(20).writeByteArray(bufCopy);
  }

  session.outgoingCommandId++;
  return ret;
};

export const SendIRToggle = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.IRToggle, null);
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

export const SendStopVideo = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.StopVideo, null);
};

export const SendStartVideo = (session: Session): DataView => {
  return makeDataReadWrite(session, ControlCommands.StartVideo, null);
};

export const getVideoKey = (session: Session): void => {
  // this is not useful at all
  for (let i = 0; i < 12; i++) {
    // payload len??
    const payload = [0x0, i]; //, 0x0, 0x0, 0x0, 0x0];
    const dv = new DataView(new Uint8Array(payload).buffer);
    session.send(makeDataReadWrite(session, ControlCommands.VideoParamGet, dv));
  }
};

export const SendVideoResolution = (session: Session, resol: 1 | 2 | 3 | 4): DataView[] => {
  // seems like 0x1 = resolution, and is specified by ID not by size
  // unclear what 0x2-0xf achieve - they report back as '0' always -- ignored?
  const pairs = {
    1: [
      // 320 x 240
      [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
      //[0x7, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0],
    ],
    2: [
      // 640x480
      [0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0],
      //[0x7, 0x0, 0x0, 0x0, 0x50, 0x0, 0x0, 0x0],
    ],
    3: [
      // also 640x480 on the X5 -- hwat now?
      [0x1, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0],
      //[0x7, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0],
    ],
    4: [
      // also 640x480 on the X5 -- hwat now?
      [0x1, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0],
      //[0x7, 0x0, 0x0, 0x0, 0xa0, 0x0, 0x0, 0x0],
    ],
    // maybe the 0x7 = bitrate??
  };

  return pairs[resol].map((payload: number[]) => {
    const dv = new DataView(new Uint8Array(payload).buffer);
    return makeDataReadWrite(session, ControlCommands.VideoParamSet, dv);
  });
};

export const SendReboot = (session: Session): DataView => {
  let dv = null;
  return makeDataReadWrite(session, ControlCommands.Reboot, dv);
};

export const SendWifiDetails = (session: Session, ssid: string, password: string, dhcp: boolean): DataView => {
  if (!dhcp) {
    throw new Error("only DHCP is supported");
  }
  let buf = new Uint8Array(0x108).fill(0);
  let cmd_payload = new DataView(buf.buffer);
  let mask_reversed = "0.255.255.255";
  // unclear which is which ))
  let m_ip = "0.0.0.0";
  let m_gw = "0.0.0.0";
  let m_dns1 = "0.0.0.0";
  let m_dns2 = "0.0.0.0";

  cmd_payload.add(0x14).writeU8(1); // DHCP ?
  cmd_payload.add(0x18).writeByteArray(str2byte(ssid));
  cmd_payload.add(0x38).writeByteArray(str2byte(password));
  cmd_payload.add(0xb8).writeByteArray(str2byte(mask_reversed));
  cmd_payload.add(0xc8).writeByteArray(str2byte(m_ip));
  cmd_payload.add(0xd8).writeByteArray(str2byte(m_gw));
  cmd_payload.add(0xe8).writeByteArray(str2byte(m_dns1));
  cmd_payload.add(0xf8).writeByteArray(str2byte(m_dns2));

  const ret = makeDataReadWrite(session, ControlCommands.WifiSettingsSet, cmd_payload);
  return ret;
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

export const create_P2pClose = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.Close);
  outbuf.add(2).writeU16(0);
  return outbuf;
};

export type DevSerial = { prefix: string; serial: string; suffix: string; serialU64: bigint; devId: string };
export const parse_PunchPkt = (dv: DataView): DevSerial => {
  const punchCmd = dv.readU16();
  const len = dv.add(2).readU16();
  const prefix = dv.add(4).readString(4);
  const serialU64 = dv.add(8).readU64();
  const serial = serialU64.toString();
  const suffix = dv.add(16).readString(len - 16 + 4); // 16 = offset, +4 header
  const devId = prefix + serial + suffix;

  return { prefix, serial, suffix, serialU64, devId };
};
