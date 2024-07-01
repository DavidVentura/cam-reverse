import fs from "node:fs";
import { DevSerial } from "./impl.js";
import { RemoteInfo } from "dgram";
import { logger } from "./logger.js";
import { startVideoStream } from "./session.js";
import { discoverDevices } from "./discovery.js";
import { Session } from "./session.js";
import { Handlers, makeSession } from "./session.js";
import { config } from "./settings.js";

const sessions: Record<string, Session> = {};
export const captureSingle = ({ discovery_ip, out_file }: { discovery_ip: string; out_file: string }) => {
  let devEv = discoverDevices([discovery_ip]);

  const startSession = (s: Session) => {
    startVideoStream(s);
    logger.info(`Camera ${s.devName} is now ready to stream`);
  };

  devEv.on("discover", (rinfo: RemoteInfo, dev: DevSerial) => {
    if (dev.devId in sessions) {
      logger.info(`Camera ${dev.devId} at ${rinfo.address} already discovered, ignoring`);
      return;
    }

    logger.info(`Discovered camera ${dev.devId} at ${rinfo.address}`);
    const s = makeSession(Handlers, dev, rinfo, startSession, 5000);
    sessions[dev.devId] = s;
    config.cameras[dev.devId] = { fix_packet_loss: false };

    s.eventEmitter.on("frame", () => {
      const assembled = Buffer.concat(s.curImage);
      fs.writeFileSync(out_file, assembled);
      logger.info(`Got frame. Exiting`);
      devEv.emit("close");
      s.close();
    });
  });
};
