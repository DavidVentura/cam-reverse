import "./shim.ts";

import dgram from "node:dgram";

import { Commands, CommandsByValue, create_LanSearch, XqBytesEnc } from "./func_replacements.js";
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

const DrwHdr = (cmd: number, len: number, d1_or_d2: 0xd1 | 0xd2, m_chan: number): DataView => {
  let retret = new DataView(new Uint8Array(len + 4).buffer);
  retret.writeU16(cmd);
  retret.add(2).writeU16(len); // buflen -4?
  retret.add(4).writeU16(u16_swap(d1_or_d2));
  retret.add(6).writeU16(m_chan); // chan? hardcoded
  return retret;
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

// console.log(hexdump(SendUsrChk("admin", "admin").buffer, { ansi: true }));
//
const EstablishSession = () => {
  const ls = create_LanSearch(); // Broadcast
};

const MakeSock = (
  cb: (msg: Buffer, rinfo: any) => void,
): { send: (msg: DataView) => void; broadcast: (msg: DataView) => void } => {
  const server = dgram.createSocket("udp4");

  server.on("error", (err) => {
    console.error(`server error:\n${err.stack}`);
    server.close();
  });

  server.on("message", cb);

  server.on("listening", () => {
    const address = server.address();
    console.log(`server listening ${address.address}:${address.port}`);
    server.setBroadcast(true);
  });

  const RECV_PORT = 49512; // important?
  const DST_IP = "192.168.1.1";
  const BCAST_IP = "192.168.1.255";
  const SEND_PORT = 32108;
  server.bind(RECV_PORT);

  return {
    send: (msg: DataView) => server.send(new Uint8Array(msg.buffer), SEND_PORT, DST_IP),
    broadcast: (msg: DataView) => server.send(new Uint8Array(msg.buffer), SEND_PORT, BCAST_IP),
  };
};

const notImpl = (sock, dv: DataView) => {
  const raw = dv.readU16();
  const cmd = CommandsByValue[raw];
  console.log(`Got ${cmd} (${raw.toString(16)}) and it's not implemented yet`);
};

const handle_PunchPkt = (sock, dv: DataView) => {
  console.log(`Got a nice punchpkt`);
  const punchCmd = dv.readU16();
  const len = dv.add(2).readU16();
  const prefix = dv.add(4).readString(4);
  const serial = dv.add(8).readU64().toString();
  const suffix = dv.add(16).readString(4);
  // f141 20 BATC 609531 EXLV
  console.log(punchCmd.toString(16), len, prefix, serial, suffix);
};

export const Handlers: Record<keyof typeof Commands, (sock: any, dv: DataView) => void> = {
  // FIXME: keys are 'any' bc import?
  PunchPkt: handle_PunchPkt,

  Close: notImpl,
  LanSearchExt: notImpl,
  LanSearch: notImpl,
  P2PAlive: notImpl,
  P2PAliveAck: notImpl,
  Hello: notImpl,
  P2pRdy: notImpl,
  P2pReq: notImpl,
  LstReq: notImpl,
  DrwAck: notImpl,
  Drw: notImpl,

  // From CSession_CtrlPkt_Proc, incomplete
  PunchTo: notImpl,
  HelloAck: notImpl,
  RlyTo: notImpl,
  DevLgnAck: notImpl,
  P2PReqAck: notImpl,
  ListenReqAck: notImpl,
  RlyHelloAck: notImpl, // always
  RlyHelloAck2: notImpl, // if len >1??
};

const sock = MakeSock((msg, rinfo) => {
  const ab = new Uint8Array(msg).buffer;
  const dv = new DataView(ab);
  const cmd = CommandsByValue[dv.readU16()];
  console.log(`from ${rinfo.address}:${rinfo.port}, server got ${cmd}`);
  console.log(hexdump(ab));
  Handlers[cmd](sock, dv);
});

const int = setInterval(() => {
  let buf = new DataView(new Uint8Array(4).buffer);
  create_LanSearch(buf);
  sock.broadcast(buf);
  // sock.send(buf);
}, 1000);
