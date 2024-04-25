import { RemoteInfo } from "dgram";
import { readFileSync } from "node:fs";
import http from "node:http";

import { opt } from "./options.js";
import { discoverDevices } from "./discovery.js";
import { DevSerial } from "./impl.js";
import { Handlers, makeSession, Session, startVideoStream } from "./session.js";

let BOUNDARY = "a very good boundary line";
let responses: Record<string, http.ServerResponse[]> = {};
let audioResponses: Record<string, http.ServerResponse[]> = {};
let sessions: Record<string, Session> = {};

export const serveHttp = (opts: opt, port: number, with_audio: boolean) => {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/ui/")) {
      let devId = req.url.split("/")[2];
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
      const ui = readFileSync("asd.html").toString();
      res.end(ui.replace(/\${id}/g, devId));
      return;
    }
    if (req.url.startsWith("/audio/")) {
      let devId = req.url.split("/")[2];
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
      res.setHeader("Content-Type", `text/event-stream`);
      audioResponses[devId].push(res);
      return;
    }

    if (req.url.startsWith("/camera/")) {
      let devId = req.url.split("/")[2];
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
      responses[devId].push(res);
      res.on("close", () => {
        responses[devId] = responses[devId].filter((r) => r !== res);
        console.log("Conn closed, kicked");
      });
    } else {
      res.write(`<html>`);
      Object.keys(sessions).forEach((id) =>
        res.write(`<h2>${id}</h2><a href="/ui/${id}"><img src="/camera/${id}"/></a><hr/>`),
      );
      res.write(`</html>`);
      res.end();
    }
  });

  let devEv = discoverDevices(opts.debug, opts.discovery_ip);
  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      console.log(`ignoring ${dev.devId} - ${rinfo.address}`);
      return;
    }

    console.log(`discovered ${dev.devId} - ${rinfo.address}`);
    responses[dev.devId] = [];
    audioResponses[dev.devId] = [];
    const s = makeSession(Handlers, dev, rinfo, startVideoStream, opts);

    const header = Buffer.from(`--${BOUNDARY}\r\nContent-Type: image/jpeg\r\n\r\n`);

    s.eventEmitter.on("frame", () => {
      const assembled = Buffer.concat(s.curImage);

      responses[dev.devId].forEach((res) => {
        res.write(header);
        res.write(assembled);
      });
    });

    s.eventEmitter.on("disconnect", () => {
      console.log("deleting from sessions");
      delete sessions[dev.devId];
    });
    if (with_audio) {
      s.eventEmitter.on("audio", ({ gap, data }) => {
        // ew, maybe WS?
        var b64encoded = Buffer.from(data).toString("base64");
        audioResponses[dev.devId].forEach((res) => {
          res.write("data: ");
          res.write(b64encoded);
          res.write("\n\n");
        });
      });
    }
    sessions[dev.devId] = s;
  });

  console.log(`Starting HTTP server on port ${port}`);
  server.listen(port);
};
