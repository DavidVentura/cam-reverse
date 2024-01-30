import { RemoteInfo } from "node:dgram";
import { createWriteStream } from "node:fs";
import http from "node:http";

import { CommandsByValue } from "./datatypes.js";
import { hexdump } from "./hexdump.js";
import { create_LanSearch, create_P2pAlive } from "./impl.js";
import { Handlers, makeSession } from "./server.js";

const s = makeSession(
  (session, msg, rinfo, options) => {
    const ab = new Uint8Array(msg).buffer;
    const dv = new DataView(ab);
    const cmd = CommandsByValue[dv.readU16()];
    if (options.debug) {
      console.log(`<< ${cmd}`);
      console.log(hexdump(msg.buffer, { ansi: options.ansi, ansiColor: 1 }));
    }
    Handlers[cmd](session, dv, rinfo);
    session.lastReceivedPacket = Date.now();
  },
  (session) => {
    // ther should be a better way of executing periodic status update
    // requests per device
    let buf = create_LanSearch();
    const int = setInterval(() => {
      session.broadcast(buf);
    }, 2000);
    session.broadcast(buf);
  },
  { debug: false, ansi: false },
);

let BOUNDARY = "a very good boundary line";
let responses = [];

s.eventEmitter.on("frame", (frame: Buffer) => {
  let s = `--${BOUNDARY}\r\n`;
  s += "Content-Type: image/jpeg\r\n\r\n";
  responses.forEach((res) => {
    res.write(Buffer.from(s));
    res.write(frame);
  });
});

const audioFd = createWriteStream(`audio.pcm`);
s.eventEmitter.on("audio", (frame: Buffer) => {
  audioFd.write(frame);
});

s.eventEmitter.on("connect", (name: string, rinfo: RemoteInfo) => {
  console.log(`Connected to ${name} - ${rinfo.address}`);
  s.outgoingCommandId = 0;
  s.dst_ip = rinfo.address;

  if (s.ticket.every((x) => x == 0)) {
    const int = setInterval(() => {
      let buf = create_P2pAlive();
      if (Date.now() - s.lastReceivedPacket > 600) {
        s.send(buf);
      }
    }, 400);
  }
});

const server = http.createServer((req, res) => {
  if (s.ticket.every((x) => x == 0)) {
    res.writeHead(400);
    res.end("Nothing online");
    return;
  }
  res.setHeader("Content-Type", `multipart/x-mixed-replace; boundary="${BOUNDARY}"`);
  responses.push(res);
});

server.listen(1234);
