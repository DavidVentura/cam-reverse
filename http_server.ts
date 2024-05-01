import { RemoteInfo } from "dgram";
import { readFileSync, existsSync } from "node:fs";
import http from "node:http";

import { logger } from "./logger.js";
import { opt } from "./options.js";
import { discoverDevices } from "./discovery.js";
import { DevSerial, SendDevStatus } from "./impl.js";
import { Handlers, makeSession, Session, startVideoStream } from "./session.js";

// @ts-expect-error TS2307
import favicon from "./cam.ico.gz";
// @ts-expect-error TS2307
import html_template from "./asd.html";

const BOUNDARY = "a very good boundary line";
const responses: Record<string, http.ServerResponse[]> = {};
const audioResponses: Record<string, http.ServerResponse[]> = {};
const sessions: Record<string, Session> = {};

// Text file containing the mapping of camera names.
const nameFile = "cameras.txt";

// Reads the simple mapping of camera names from the text file.
const cameraNames = Object.assign(
  {},
  ...(existsSync(nameFile) ? readFileSync(nameFile, "utf8") : "")
    .toString()
    .replace(/\r\n/g, "\n")
    .split("\n")
    .filter((l) => !l.startsWith("#"))
    .filter((l) => l.trim() != "")
    .map((l) => {
      let kv = l.split("=");
      return { [kv[0]]: kv[1] };
    }),
);

// Returns the camera name (custom name, if it exists, otherwise its ID).
const cameraName = (id: string): string => cameraNames[id] || id;

// The HTTP server.
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
      const ui = html_template
        .toString()
        .replace(/\${id}/g, devId)
        .replace(/\${name}/g, cameraName(devId))
        .replace(/\${audio}/g, with_audio.toString());
      res.end(ui);
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
      logger.info(`Audio stream requested for camera ${devId}`);
      return;
    }

    if (req.url.startsWith("/favicon.ico")) {
      res.setHeader("Content-Type", "image/x-icon");
      res.setHeader("Content-Encoding", "gzip");
      res.end(favicon);
      return;
    }

    if (req.url.startsWith("/camera/")) {
      let devId = req.url.split("/")[2];
      logger.info(`Video stream requested for camera ${devId}`);
      let s = sessions[devId];

      if (s === undefined) {
        res.writeHead(400);
        res.end(`Camera ${devId} not discovered`);
        return;
      }
      if (!s.connected) {
        res.writeHead(400);
        res.end(`Camera ${devId} offline`);
        return;
      }

      res.setHeader("Content-Type", `multipart/x-mixed-replace; boundary="${BOUNDARY}"`);
      responses[devId].push(res);
      res.on("close", () => {
        responses[devId] = responses[devId].filter((r) => r !== res);
        logger.info(`Video stream closed for camera ${devId}`);
      });
    } else {
      res.write("<html>");
      res.write("<head>");
      res.write(`<link rel="shortcut icon" href="/favicon.ico">`);
      res.write("<title>All cameras</title>");
      res.write("</head>");
      res.write("<body>");
      res.write("<h1>All cameras</h1><hr/>");
      Object.keys(sessions).forEach((id) =>
        res.write(`<h2>${cameraName(id)}</h2><a href="/ui/${id}"><img src="/camera/${id}"/></a><hr/>`),
      );
      res.write("</body>");
      res.write("</html>");
      res.end();
    }
  });

  let devEv = discoverDevices(opts.discovery_ip);

  const startSession = (s: Session) => {
    s.send(SendDevStatus(s));
    startVideoStream(s);
    logger.info(`Camera ${s.devName} is now ready to stream`);
  };

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      logger.info(`Camera ${dev.devId} at ${rinfo.address} already discovered, ignoring`);
      return;
    }

    logger.info(`Discovered camera ${dev.devId} at ${rinfo.address}`);
    responses[dev.devId] = [];
    audioResponses[dev.devId] = [];
    const s = makeSession(Handlers, dev, rinfo, startSession, opts);

    const header = Buffer.from(`--${BOUNDARY}\r\nContent-Type: image/jpeg\r\n\r\n`);

    s.eventEmitter.on("frame", () => {
      const assembled = Buffer.concat(s.curImage);

      responses[dev.devId].forEach((res) => {
        res.write(header);
        res.write(assembled);
      });
    });

    s.eventEmitter.on("disconnect", () => {
      logger.info(`Camera ${dev.devId} disconnected`);
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

  logger.info(`Starting HTTP server on port ${port}`);
  server.listen(port);
};
