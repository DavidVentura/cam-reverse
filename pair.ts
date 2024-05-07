import { RemoteInfo } from "dgram";

import { config } from "./settings.js";
import { discoverDevices } from "./discovery.js";
import { WifiListItem } from "./handlers.js";
import { DevSerial, SendListWifi } from "./impl.js";
import { Handlers, makeSession, Session, configureWifi } from "./session.js";
import { logger } from "./logger.js";

export const pair = ({ ssid, password }: { ssid: string; password: string }) => {
  logger.info(`Will configure any devices found to join ${ssid}`);
  let sessions: Record<string, Session> = {};

  let devEv = discoverDevices(config.discovery_ips);
  if (password == "") {
    throw new Error("You must set a non-zero-length password");
  }

  const onLogin = (s: Session) => {
    logger.info(`Scanning for Wifi networks on ${s.devName} -- this may time out`);

    // configureWifi(ssid, password, 0)(s);
    s.send(SendListWifi(s));
  };

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      logger.info(`Camera ${dev.devId} at ${rinfo.address} already discovered, ignoring`);
      return;
    }
    logger.info(`Discovered camera ${dev.devId} at ${rinfo.address}`);
    const s = makeSession(Handlers, dev, rinfo, onLogin, 10000);
    let configured = {};

    s.eventEmitter.on("disconnect", () => {
      logger.info(`Camera ${dev.devId} disconnected`);
      if (configured[dev.devId]) {
        logger.info("Press CONTROL+C if you're done setting up your cameras");
      }
      delete sessions[dev.devId];
      delete configured[dev.devId];
    });
    sessions[dev.devId] = s;

    s.eventEmitter.on("ListWifi", (items: WifiListItem[]) => {
      const matches = items.filter((i) => i.ssid == ssid);
      if (matches.length == 0) {
        logger.error(`Camera could not find SSID '${ssid}'`);
        return;
      }
      if (configured[dev.devId]) {
        logger.info(`Got two answers from camera, ignoring second`);
        return;
      }
      const match = matches[0];
      logger.info(`Configuring camera ${s.devName} on ${JSON.stringify(match)}`);
      configureWifi(ssid, password, match.channel)(s);
      configured[dev.devId] = true;
      logger.info(`WiFi config for camera ${s.devName} is done`);
      logger.info(`Camera should reboot now`);
    });
  });
};
