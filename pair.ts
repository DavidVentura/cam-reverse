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

  const onLogin = configureWifi(ssid, password);

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      console.log(`ignoring ${dev.devId} - ${rinfo.address}`);
      return;
    }
    console.log(`discovered ${dev.devId} - ${rinfo.address}`);
    const s = makeSession(Handlers, dev, rinfo, onLogin, opts);

    s.eventEmitter.on("disconnect", () => {
      console.log("deleting from sessions");
      delete sessions[dev.devId];
    });
    sessions[dev.devId] = s;
  });
};
