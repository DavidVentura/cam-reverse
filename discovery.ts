import EventEmitter from "node:events";
import { create_LanSearch, parse_PunchPkt } from "./impl.js";
import { createSocket, RemoteInfo } from "node:dgram";
import { Commands } from "./datatypes.js";
import { logger } from "./logger.js";

const handleIncomingPunch = (msg: Buffer, ee: EventEmitter, rinfo: RemoteInfo) => {
  const ab = new Uint8Array(msg).buffer;
  const dv = new DataView(ab);
  const cmd_id = dv.readU16();
  if (cmd_id != Commands.PunchPkt) {
    return;
  }
  logger.debug("Received a PunchPkt message");
  ee.emit("discover", rinfo, parse_PunchPkt(dv));
};

export const discoverDevices = (discovery_ip: string): EventEmitter => {
  const sock = createSocket("udp4");
  const SEND_PORT = 32108;
  const ee = new EventEmitter();

  sock.on("error", (err) => {
    console.error(`sock error:\n${err.stack}`);
    sock.close();
  });

  sock.on("message", (msg, rinfo) => handleIncomingPunch(msg, ee, rinfo));

  sock.on("listening", () => {
    sock.setBroadcast(true);
    logger.info(`Searching for devices on ${discovery_ip}`);

    let buf = create_LanSearch();
    setInterval(() => {
      sock.send(new Uint8Array(buf.buffer), SEND_PORT, discovery_ip);
    }, 2000);
    sock.send(new Uint8Array(buf.buffer), SEND_PORT, discovery_ip);
  });

  sock.bind();

  return ee;
};
