import { RemoteInfo } from "dgram";

import { opt } from "./options.js";
import { discoverDevices } from "./discovery.js";
import { DevSerial } from "./impl.js";
import { Handlers, makeSession, Session, configureWifi } from "./session.js";

export const pair = ({ opts, ssid, password }: { opts: opt; ssid: string; password: string }) => {
  console.log(`Will configure any devices found to join ${ssid}`);
  let sessions: Record<string, Session> = {};

  let devEv = discoverDevices(opts.debug, opts.discovery_ip);
  if (password == "") {
    throw new Error("You must set a non-zero-length password");
  }

  const onLogin = (s: Session) => {
    configureWifi(ssid, password);
    console.log(`WiFi config for camera ${s.devName} is done`);
  }

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions && sessions[dev.devId] != undefined) {
      console.log(`Camera ${dev.devId} at ${rinfo.address} already discovered, ignoring`);
      return;
    }
    console.log(`Discovered camera ${dev.devId} at ${rinfo.address}`);
    const s = makeSession(Handlers, dev, rinfo, onLogin, opts);

    s.eventEmitter.on("disconnect", () => {
      console.log(`Camera ${dev.devId} disconnected`);
      console.log("Press CONTROL+C if you're done setting up your cameras");
      delete sessions[dev.devId];
    });
    sessions[dev.devId] = s;
  });
};
