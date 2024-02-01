import { RemoteInfo } from "dgram";

import { discoverDevices } from "../discovery.js";
import { DevSerial } from "../impl.js";
import { Handlers, makeSession, Session, configureWifi } from "../session.js";

const opts = {
  debug: true,
  ansi: true,
  discovery_ip: "192.168.1.255",
};

let sessions: Record<string, Session> = {};

let devEv = discoverDevices(opts);
if (process.env.SSID == undefined || process.env.PSK == undefined) {
  throw new Error("Set `SSID` and `PSK` environment variables");
}

const onLogin = configureWifi(process.env.SSID, process.env.PSK);

console.log(process.env.SSID, process.env.PSK);
devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
  if (dev.devId in sessions) {
    console.log(`ignoring ${dev.devId} - ${rinfo.address}`);
    return;
  }
  console.log(`discovered ${dev.devId} - ${rinfo.address}`);
  const s = makeSession(Handlers, dev, rinfo, onLogin, opts);

  s.eventEmitter.on("disconnect", () => {
    console.log("deleting from sessions");
    sessions[dev.devId] = undefined;
  });
  sessions[dev.devId] = s;
});
