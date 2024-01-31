import { createWriteStream } from "node:fs";
import http from "node:http";

import { Handlers, makeSession } from "./server.js";

const s = makeSession(Handlers, { debug: false, ansi: false });

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
