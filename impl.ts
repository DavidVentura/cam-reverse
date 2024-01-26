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
    send: (msg: DataView) => {
      const raw = msg.readU16();
      const cmd = CommandsByValue[raw];
      console.log(`>> ${cmd}`);
      console.log(hexdump(msg.buffer, { ansi: true, ansiColor: 0 }));
      server.send(new Uint8Array(msg.buffer), SEND_PORT, DST_IP);
    },
    broadcast: (msg: DataView) => server.send(new Uint8Array(msg.buffer), SEND_PORT, BCAST_IP),
  };
};

const notImpl = (sock, dv: DataView) => {
  const raw = dv.readU16();
  const cmd = CommandsByValue[raw];
  console.log(`^^ ${cmd} (${raw.toString(16)}) and it's not implemented yet`);
};

const noop = (sock, dv: DataView) => {};
const create_P2pAliveAck = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.P2PAliveAck);
  outbuf.add(2).writeU16(0);
  return outbuf;
};

const create_P2pRdy = (inbuf: DataView): DataView => {
  const P2PRDY_SIZE = 0x14;
  const outbuf = new DataView(new Uint8Array(P2PRDY_SIZE + 4).buffer);
  outbuf.writeU16(Commands.P2pRdy);
  outbuf.add(2).writeU16(P2PRDY_SIZE);
  outbuf.add(4).writeByteArray(new Uint8Array(inbuf.readByteArray(P2PRDY_SIZE).buffer));
  return outbuf;
};

const handle_Drw = (sock, dv: DataView) => {
  // TODO
  // INPUT
  // byte 4 = d1 or d2, just add 1
  // byte 5 = stream??
  // byte 6-7 = pkt id
  // OUTPUT
  // f1d1
  // 2b len
  // d1/d2 +1 (always d2?)
  // 2b ack'd packets (1 for now, no coalescing)
  // N times 2b with packet id
  /*
   *
	00000000  f1 d0 00 18 d1 00 00 00 11 0a 20 11 0c 00 ff 00  .......... .....
	00000010  00 00 00 00 34 54 63 4d fe 01 01 01              ....4TcM....
	                      ^^^^^^^^^^^^^^
						  some kind of challenge
						  need to send the 0x3010 command with this
						  but add 1 to every byte
	*/
  const should_be_d1 = dv.add(4).readU8();
  const m_stream = dv.add(5).readU8();
  const pkt_id = dv.add(6).readU16();
  const start_type = dv.add(8).readU16(); // 0xa11
  const cmd_id = dv.add(10).readU16(); // 0x1120
  console.log("DRW", should_be_d1, m_stream, pkt_id, start_type.toString(16), cmd_id.toString(16));

  if (cmd_id == 0x2011) {
    challenge[0] = dv.add(0x14).readU8();
    challenge[1] = dv.add(0x15).readU8();
    challenge[2] = dv.add(0x16).readU8();
    challenge[3] = dv.add(0x17).readU8();
  }

  const item_count = 1; // TODO
  const reply_len = item_count * 2 + 4; // 4 hdr, 2b per item
  const outbuf = new DataView(new Uint8Array(32).buffer);
  outbuf.writeU16(Commands.DrwAck);
  outbuf.add(2).writeU16(reply_len);
  outbuf.add(4).writeU8(0xd2);
  outbuf.add(5).writeU8(m_stream);
  outbuf.add(6).writeU16(item_count);
  for (let i = 0; i < item_count; i++) {
    outbuf.add(8 + i * 2).writeU16(pkt_id);
  }
  sock.send(outbuf);
  // CSession_Drw_Deal
  //   set some stuff?
  //   return a counter with pkt # ??
  //   stream: 0 control
  //           1 data?? video+aud
  // Send_Pkt_DrwAck(10,0xd2,channel,1,&cmd_,sock_fd,ipaddr_);
};
const handle_P2PRdy = (sock, dv: DataView) => {
  const b = SendUsrChk("admin", "admin");
  sock.send(b);
  setTimeout(() => {
    /*
	00000000  f1 d0 01 14 d1 00 00 90 11 0a 10 30 08 01 00 00  ...........0....
	00000010  77 78 35 69 01 01 01 01                          wx5i....

	00000000  f1 d0 01 14 d1 00 00 04 11 0a 10 30 08 01 00 00  ...........0....
	00000010  55 58 36 59 01 01 01 01                          UX6Y....
	*/
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
    sock.send(buf);
  }, 100);
};
const handle_P2PAlive = (sock, dv: DataView) => {
  const b = create_P2pAliveAck();
  sock.send(b);
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
  sock.send(create_P2pRdy(dv.add(4).readByteArray(len)));
};

export const Handlers: Record<keyof typeof Commands, (sock: any, dv: DataView) => void> = {
  // FIXME: keys are 'any' bc import?
  PunchPkt: handle_PunchPkt,

  Close: notImpl,
  LanSearchExt: notImpl,
  LanSearch: notImpl,
  P2PAlive: handle_P2PAlive,
  P2PAliveAck: notImpl,
  Hello: notImpl,
  P2pRdy: handle_P2PRdy,
  P2pReq: notImpl,
  LstReq: notImpl,
  DrwAck: noop,
  Drw: handle_Drw,

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
  // ${rinfo.address}:${rinfo.port}
  console.log(`<< ${cmd}`);
  console.log(hexdump(ab, { useAnsi: true, ansiColor: 1 }));
  Handlers[cmd](sock, dv);
});

const int = setInterval(() => {
  let buf = new DataView(new Uint8Array(4).buffer);
  create_LanSearch(buf);
  sock.broadcast(buf);
  // sock.send(buf);
}, 1000);
