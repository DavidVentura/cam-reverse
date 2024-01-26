import dgram from "node:dgram";
import { create_LanSearch, Commands, CommandsByValue } from "./func_replacements.js";
import { handle_P2PAlive, handle_PunchPkt, handle_P2PRdy, handle_Drw, notImpl, noop } from "./handlers.js";
import { hexdump } from "./hexdump.js";

export type sock = {
  send: (msg: DataView) => void;
  broadcast: (msg: DataView) => void;
};

type opt = {
  debug: boolean;
  ansi: boolean;
};

type msgCb = (msg: Buffer, rinfo: any, options: opt) => void;
type connCb = () => void;

const MakeSock = (cb: msgCb, connCb: connCb, options?: opt): sock => {
  const server = dgram.createSocket("udp4");

  server.on("error", (err) => {
    console.error(`server error:\n${err.stack}`);
    server.close();
  });

  server.on("message", (msg, rinfo) => cb(msg, rinfo, options));

  server.on("listening", () => {
    const address = server.address();
    console.log(`server listening ${address.address}:${address.port}`);
    server.setBroadcast(true);
    connCb();
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
      if (options.debug) {
        console.log(`>> ${cmd}`);
        console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 0 }));
      }
      server.send(new Uint8Array(msg.buffer), SEND_PORT, DST_IP);
    },
    broadcast: (msg: DataView) => server.send(new Uint8Array(msg.buffer), SEND_PORT, BCAST_IP),
  };
};

const Handlers: Record<keyof typeof Commands, (sock: sock, dv: DataView) => void> = {
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

const sock = MakeSock(
  (msg, rinfo, options) => {
    const ab = new Uint8Array(msg).buffer;
    const dv = new DataView(ab);
    const cmd = CommandsByValue[dv.readU16()];
    if (options.debug) {
      console.log(`<< ${cmd}`);
      console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 1 }));
    }
    Handlers[cmd](sock, dv);
  },
  () => {
    const int = setInterval(() => {
      let buf = new DataView(new Uint8Array(4).buffer);
      create_LanSearch(buf);
      sock.broadcast(buf);
    }, 1000);
  },
  { debug: false, ansi: false },
);
