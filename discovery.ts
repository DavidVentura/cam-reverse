import { createSocket, RemoteInfo } from "node:dgram";
import EventEmitter from "node:events";

import { Commands } from "./datatypes.js";
import { create_LanSearch, parse_PunchPkt } from "./impl.js";
import { logger } from "./logger.js";
import { config } from "./settings.js";

const handleIncomingPunch = (msg: Buffer, ee: EventEmitter, rinfo: RemoteInfo) => {
  const ab = new Uint8Array(msg).buffer;
  const dv = new DataView(ab);
  const cmd_id = dv.readU16();
  if (cmd_id != Commands.PunchPkt) {
    return;
  }
  if (config.blacklisted_ips.indexOf(rinfo.address) !== -1) {
    logger.debug(`Dropping packet of blacklisted IP: ${rinfo.address}`);
    return;
  }
  logger.debug("Received a PunchPkt message");
  ee.emit("discover", rinfo, parse_PunchPkt(dv));
};

export const discoverDevices = (discovery_ips: string[]): EventEmitter => {
  const sock = createSocket("udp4");
  const SEND_PORT = 32108;
  const ee = new EventEmitter();

  sock.on("error", (err) => {
    console.error(`sock error:\n${err.stack}`);
    sock.close();
  });

  sock.on("message", (msg, rinfo) => handleIncomingPunch(msg, ee, rinfo));

  let timers = [];
  sock.on("listening", () => {
    let ls_buf = create_LanSearch();
    sock.setBroadcast(true);
    discovery_ips.forEach((discovery_ip) => {
      logger.info(`Searching for devices on ${discovery_ip}`);

      let int = setInterval(() => {
        logger.log("trace", `>> LanSearch [${discovery_ip}]`);
        sock.send(new Uint8Array(ls_buf.buffer), SEND_PORT, discovery_ip);
      }, 3000);
      timers.push(int);
      logger.log("trace", `>> LanSearch [${discovery_ip}]`);
      sock.send(new Uint8Array(ls_buf.buffer), SEND_PORT, discovery_ip);
    });
  });

  sock.bind();

  sock.on("close", () => timers.forEach((timer) => clearInterval(timer)));
  ee.on("close", () => sock.close());
  return ee;
};
