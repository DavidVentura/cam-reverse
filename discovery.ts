import EventEmitter from "node:events";
import { create_LanSearch, parse_PunchPkt } from "./impl.js";
import { createSocket, RemoteInfo } from "node:dgram";
import { Commands } from "./datatypes.js";
import { hexdump } from "./hexdump.js";
import { opt } from "./options.js";

const handleIncomingPunch = (msg: Buffer, ee: EventEmitter, rinfo: RemoteInfo, options: opt) => {
  const ab = new Uint8Array(msg).buffer;
  const dv = new DataView(ab);
  const cmd_id = dv.readU16();
  if (cmd_id != Commands.PunchPkt) {
    return;
  }
  if (options.debug) {
    console.log("Discovery got a PunchPkt");
  }
  ee.emit("discover", rinfo, parse_PunchPkt(dv));
};

export const discoverDevices = (options: opt): EventEmitter => {
  const sock = createSocket("udp4");
  //const BCAST_IP = "192.168.1.255";
  const BCAST_IP = "192.168.40.101";
  const SEND_PORT = 32108;
  const ee = new EventEmitter();

  sock.on("error", (err) => {
    console.error(`sock error:\n${err.stack}`);
    sock.close();
  });

  sock.on("message", (msg, rinfo) => handleIncomingPunch(msg, ee, rinfo, options));

  sock.on("listening", () => {
    sock.setBroadcast(true);
    console.log("Searching for devices..");

    let buf = create_LanSearch();
    setInterval(() => {
      console.log(".");
      sock.send(new Uint8Array(buf.buffer), SEND_PORT, BCAST_IP);
    }, 2000);
    sock.send(new Uint8Array(buf.buffer), SEND_PORT, BCAST_IP);
  });

  sock.bind();

  return ee;
};
