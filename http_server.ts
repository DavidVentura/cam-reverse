import { createWriteStream } from "node:fs";
import http from "node:http";

import { Handlers, makeSession, Session } from "./session.js";
import { discoverDevices } from "./discovery.js";
import { DevSerial } from "./impl.js";

const opts = { debug: false, ansi: false };

let BOUNDARY = "a very good boundary line";
let responses = [];
let sessions: Record<string, Session> = {};

const server = http.createServer((req, res) => {
  let devId = req.url.slice(1);
  console.log("requested for", devId);
  let s = sessions[devId];

  if (s === undefined) {
    res.writeHead(400);
    res.end("invalid ID");
    return;
  }
  if (!s.connected) {
    res.writeHead(400);
    res.end("Nothing online");
    return;
  }
  res.setHeader("Content-Type", `multipart/x-mixed-replace; boundary="${BOUNDARY}"`);
  responses.push(res);
});

let devEv = discoverDevices(opts);
devEv.on("discover", (rinfo, dev: DevSerial) => {
  if (dev.devId in sessions) {
    console.log(`ignoring ${dev.devId} - ${rinfo.address}`);
    return;
  }
  console.log(`discovered ${dev.devId} - ${rinfo.address}`);
  const s = makeSession(Handlers, dev, rinfo, opts);
  const withAudio = false;
  s.eventEmitter.on("frame", (frame: Buffer) => {
    let s = `--${BOUNDARY}\r\n`;
    s += "Content-Type: image/jpeg\r\n\r\n";
    responses.forEach((res) => {
      res.write(Buffer.from(s));
      res.write(frame);
    });
  });

  s.eventEmitter.on("disconnect", () => {
    console.log("deleting from sessions");
    sessions[dev.devId] = undefined;
  });
  if (withAudio) {
    const audioFd = createWriteStream(`audio.pcm`);
    s.eventEmitter.on("audio", (frame: Buffer) => {
      audioFd.write(frame);
    });
  }
  sessions[dev.devId] = s;
});

server.listen(1234);
