import { createSocket, RemoteInfo } from "node:dgram";
import { Commands, CommandsByValue } from "./datatypes.js";
import { handle_P2PAlive, handle_PunchPkt, handle_P2PRdy, handle_Drw, notImpl, noop } from "./handlers.js";
import { hexdump } from "./hexdump.js";
import { SendDevStatus } from "./impl.js";
import EventEmitter from "node:events";

export type Session = {
  send: (msg: DataView) => void;
  broadcast: (msg: DataView) => void;
  outgoingCommandId: number;
  ticket: number[];
  eventEmitter: EventEmitter;
  dst_ip: string;
  lastReceivedPacket: number;
};

export type PacketHandler = (session: Session, dv: DataView, rinfo: RemoteInfo) => void;

type opt = {
  debug: boolean;
  ansi: boolean;
};

type msgCb = (session: Session, msg: Buffer, rinfo: RemoteInfo, options: opt) => void;
type connCb = (session: Session) => void;

export const makeSession = (cb: msgCb, connCb: connCb, options: opt): Session => {
  const sock = createSocket("udp4");

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
  const BCAST_IP = "192.168.1.255";
  const SEND_PORT = 32108;
  sock.bind(RECV_PORT);

  const session: Session = {
    outgoingCommandId: 0,
    ticket: [0, 0, 0, 0],
    lastReceivedPacket: 0,
    eventEmitter: new EventEmitter(),
    send: (msg: DataView) => {
      const raw = msg.readU16();
      const cmd = CommandsByValue[raw];
      if (options.debug) {
        console.log(`>> ${cmd}`);
        if (raw != Commands.P2PAlive) {
          console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 0 }));
        }
      }
      if (raw == Commands.Drw) {
        session.outgoingCommandId++;
      }
      sock.send(new Uint8Array(msg.buffer), SEND_PORT, session.dst_ip);
    },
    broadcast: (msg: DataView) => {
      sock.send(new Uint8Array(msg.buffer), SEND_PORT, BCAST_IP);
    },
    dst_ip: BCAST_IP,
  };
  return session;
};

export const Handlers: Record<keyof typeof Commands, PacketHandler> = {
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
