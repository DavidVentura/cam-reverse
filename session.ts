import { createSocket, RemoteInfo } from "node:dgram";
import EventEmitter from "node:events";

import { Commands, CommandsByValue } from "./datatypes.js";
import { handle_Drw, handle_P2PAlive, handle_P2PRdy, makePunchPkt, noop, notImpl } from "./handlers.js";
import { hexdump } from "./hexdump.js";
import { create_P2pAlive, DevSerial, SendStartVideo, SendVideoResolution, SendWifiDetails } from "./impl.js";
import { opt } from "./options.js";

export type Session = {
  send: (msg: DataView) => void;
  outgoingCommandId: number;
  ticket: number[];
  eventEmitter: EventEmitter;
  dst_ip: string;
  lastReceivedPacket: number;
  connected: boolean;
  devName: string;
  timers: ReturnType<typeof setInterval>[];
  curImage: Buffer | null;
  rcvSeqId: number;
  frame_is_bad: boolean;
};

export type PacketHandler = (session: Session, dv: DataView, rinfo: RemoteInfo) => void;

type msgCb = (
  session: Session,
  handlers: Record<keyof typeof Commands, PacketHandler>,
  msg: Buffer,
  rinfo: RemoteInfo,
  options: opt,
) => void;

const handleIncoming: msgCb = (session, handlers, msg, rinfo, options) => {
  const ab = new Uint8Array(msg).buffer;
  const dv = new DataView(ab);
  const cmd = CommandsByValue[dv.readU16()];
  if (options.debug) {
    console.log(`<< ${cmd}`);
    console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 1 }));
  }
  handlers[cmd](session, dv, rinfo);
  session.lastReceivedPacket = Date.now();
};

export const makeSession = (
  handlers: Record<keyof typeof Commands, PacketHandler>,
  dev: DevSerial,
  ra: RemoteInfo,
  onLogin: (s: Session) => void,
  options: opt,
): Session => {
  const sock = createSocket("udp4");

  sock.on("error", (err) => {
    console.error(`sock error:\n${err.stack}`);
    sock.close();
  });

  sock.on("message", (msg, rinfo) => handleIncoming(session, handlers, msg, rinfo, options));

  sock.on("listening", () => {
    const buf = makePunchPkt(dev);
    session.send(buf);
  });

  const SEND_PORT = 32108;
  sock.bind();
  const sessTimer = setInterval(() => {
    const delta = Date.now() - session.lastReceivedPacket;
    if (delta > 600) {
      let buf = create_P2pAlive();
      session.send(buf);
    }
    if (delta > 8000) {
      session.eventEmitter.emit("disconnect");
    }
  }, 400);

  const session: Session = {
    outgoingCommandId: 0,
    ticket: [0, 0, 0, 0],
    lastReceivedPacket: 0,
    eventEmitter: new EventEmitter(),
    connected: true,
    timers: [sessTimer],
    devName: dev.devId,
    send: (msg: DataView) => {
      const raw = msg.readU16();
      const cmd = CommandsByValue[raw];
      if (options.debug) {
        console.log(`>> ${cmd}`);
        if (raw != Commands.P2PAlive) {
          console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 0 }));
        }
      }
      sock.send(new Uint8Array(msg.buffer), SEND_PORT, session.dst_ip);
    },
    dst_ip: ra.address,
    curImage: null,
    rcvSeqId: 0,
    frame_is_bad: false,
  };

  session.eventEmitter.on("disconnect", () => {
    console.log(`Disconnected from ${session.devName} - ${session.dst_ip}`);
    session.dst_ip = "0.0.0.0";
    session.connected = false;
    session.timers.forEach((x) => clearInterval(x));
    session.timers = [];
  });

  session.eventEmitter.on("login", () => {
    console.log(`Logged in - ${session.devName}`);
    onLogin(session);
  });
  return session;
};

export const configureWifi = (ssid: string, password: string) => {
  return (s: Session) => {
    [SendWifiDetails(s, ssid, password, true)].forEach(s.send);
  };
};

export const startVideoStream = (s: Session) => {
  [
    ...SendVideoResolution(s, 2), // 640x480
    SendStartVideo(s),
  ].forEach(s.send);
};

export const Handlers: Record<keyof typeof Commands, PacketHandler> = {
  PunchPkt: notImpl,
  P2PAlive: handle_P2PAlive,
  P2pRdy: handle_P2PRdy,
  DrwAck: noop,
  Drw: handle_Drw,

  Close: notImpl,
  LanSearchExt: notImpl,
  LanSearch: notImpl,
  P2PAliveAck: notImpl,
  Hello: notImpl,
  P2pReq: notImpl,
  LstReq: notImpl,
  PunchTo: notImpl,
  HelloAck: notImpl,
  RlyTo: notImpl,
  DevLgnAck: notImpl,
  P2PReqAck: notImpl,
  ListenReqAck: notImpl,
  RlyHelloAck: notImpl, // always
  RlyHelloAck2: notImpl, // if len >1??
};
