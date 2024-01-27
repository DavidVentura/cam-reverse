import dgram from "node:dgram";
import { createWriteStream } from "node:fs";
import { create_LanSearch } from "./func_replacements.js";
import { Commands, CommandsByValue } from "./datatypes.js";
import { handle_P2PAlive, handle_PunchPkt, handle_P2PRdy, handle_Drw, notImpl, noop } from "./handlers.js";
import { hexdump } from "./hexdump.js";
import EventEmitter from "node:events";

export type Session = {
  send: (msg: DataView) => void;
  broadcast: (msg: DataView) => void;
  outgoingCommandId: number;
  ticket: number[];
  frameEmitter: EventEmitter;
};

export type PacketHandler = (session: Session, dv: DataView) => void;

type opt = {
  debug: boolean;
  ansi: boolean;
};

type msgCb = (session: Session, msg: Buffer, rinfo: any, options: opt) => void;
type connCb = (session: Session) => void;

const makeSession = (cb: msgCb, connCb: connCb, options?: opt): Session => {
  const sock = dgram.createSocket("udp4");

  sock.on("error", (err) => {
    console.error(`sock error:\n${err.stack}`);
    sock.close();
  });

  sock.on("message", (msg, rinfo) => cb(session, msg, rinfo, options));

  sock.on("listening", () => {
    const address = sock.address();
    console.log(`sock listening ${address.address}:${address.port}`);
    sock.setBroadcast(true);
    connCb(session);
  });

  const RECV_PORT = 49512; // important?
  const DST_IP = "192.168.1.1";
  const BCAST_IP = "192.168.1.255";
  const SEND_PORT = 32108;
  sock.bind(RECV_PORT);

  const session: Session = {
    outgoingCommandId: 0,
    ticket: [0, 0, 0, 0],
    frameEmitter: new EventEmitter(),
    send: (msg: DataView) => {
      const raw = msg.readU16();
      const cmd = CommandsByValue[raw];
      if (options.debug) {
        console.log(`>> ${cmd}`);
        console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 0 }));
      }
      if (raw == Commands.Drw) {
        // not sure why cmd == Commands.Drw does not work
        session.outgoingCommandId++;
      }
      sock.send(new Uint8Array(msg.buffer), SEND_PORT, DST_IP);
    },
    broadcast: (msg: DataView) => sock.send(new Uint8Array(msg.buffer), SEND_PORT, BCAST_IP),
  };
  return session;
};

const Handlers: Record<keyof typeof Commands, PacketHandler> = {
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

const s = makeSession(
  (session, msg, _, options) => {
    const ab = new Uint8Array(msg).buffer;
    const dv = new DataView(ab);
    const cmd = CommandsByValue[dv.readU16()];
    if (options.debug) {
      console.log(`<< ${cmd}`);
      console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 1 }));
    }
    Handlers[cmd](session, dv);
  },
  (session) => {
    const int = setInterval(() => {
      let buf = new DataView(new Uint8Array(4).buffer);
      create_LanSearch(buf);
      session.broadcast(buf);
    }, 1000);
  },
  { debug: false, ansi: false },
);

let cur_image_index = 0;
s.frameEmitter.on("frame", (frame: Buffer) => {
  const fname = `captures/${cur_image_index.toString().padStart(4, "0")}.jpg`;
  let cur_image = createWriteStream(fname);
  cur_image_index++;
  cur_image.write(frame);
  cur_image.close();
  console.log("got an entire frame", frame.length);
});
