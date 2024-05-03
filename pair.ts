import { RemoteInfo } from "dgram";

import { opt } from "./options.js";
import { discoverDevices } from "./discovery.js";
import { DevSerial, SendReboot, SendWifiSettings } from "./impl.js";
import { Handlers, makeSession, Session, configureWifi } from "./session.js";
import { logger } from "./logger.js";

export const pair = ({ opts, ssid, password }: { opts: opt; ssid: string; password: string }) => {
  logger.info(`Will configure any devices found to join ${ssid}`);
  let sessions: Record<string, Session> = {};

  let devEv = discoverDevices(opts.discovery_ip);
  if (password == "") {
    throw new Error("You must set a non-zero-length password");
  }

  const onLogin = (s: Session) => {
    logger.info(`Configuring camera ${s.devName}`);
    configureWifi(ssid, password)(s);
    logger.info(`WiFi config for camera ${s.devName} is done`);

    logger.info(`Validating WiFi settings on ${s.devName}`);
    s.send(SendWifiSettings(s));

    logger.info(`Asking ${s.devName} to reboot`);
    s.send(SendReboot(s));
  };

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      logger.info(`Camera ${dev.devId} at ${rinfo.address} already discovered, ignoring`);
      return;
    }
    logger.info(`Discovered camera ${dev.devId} at ${rinfo.address}`);
    const s = makeSession(Handlers, dev, rinfo, onLogin, opts);

    s.eventEmitter.on("disconnect", () => {
      logger.info(`Camera ${dev.devId} disconnected`);
      logger.info("Press CONTROL+C if you're done setting up your cameras");
      delete sessions[dev.devId];
    });
    sessions[dev.devId] = s;
  });
};
