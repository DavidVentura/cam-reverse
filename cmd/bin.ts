import process from "node:process";
import { hideBin } from "yargs/helpers";
import yargs from "yargs/yargs";

import { serveHttp } from "../http_server.js";
import { opt } from "../options.js";
import { pair } from "../pair.js";

import { buildLogger, logger } from "../logger.js";

const majorVersion = process.versions.node.split(".").map(Number)[0];

yargs(hideBin(process.argv))
  .command(
    "http_server",
    "start http server",
    (yargs) => {
      return yargs
        .option("ansi", { default: false })
        .option("audio", { describe: "Also stream audio from camera", default: true })
        .option("color", { describe: "Use color in logs", default: undefined })
        .boolean(["ansi", "audio", "color"])
        .option("log_level", { describe: "Set log level", default: "info" })
        .option("discovery_ip", { describe: "Camera discovery IP address", default: "192.168.1.255" })
        .option("attempt_to_fix_packet_loss", { default: false })
        .option("port", { describe: "HTTP Port to listen on", default: 5000 })
        .number(["port"])
        .strict();
    },
    (argv) => {
      const opts: opt = argv as opt;
      buildLogger(argv.log_level, argv.color);
      if (majorVersion < 16) {
        logger.error(`Node version ${majorVersion} is not supported, may malfunction`);
      }
      serveHttp(opts, argv.port, argv.audio || false);
    },
  )
  .command(
    "pair",
    "configure a camera",
    (yargs) => {
      return yargs
        .option("ansi", { default: false })
        .option("color", { describe: "Use color in logs", default: undefined })
        .boolean(["ansi", "color"])
        .option("log_level", { describe: "Set log level", default: "info" })
        .option("discovery_ip", { describe: "Camera discovery IP address", default: "192.168.1.255" })
        .option("attempt_to_fix_packet_loss", { default: false })
        .option("ssid", { describe: "Wifi network for the camera to connect to" })
        .option("password", { describe: "Wifi network password" })
        .demandOption(["ssid", "password"])
        .string(["ssid", "password"]);
    },
    (argv) => {
      const opts: opt = argv as unknown as opt;
      buildLogger(argv.log_level, argv.color);
      if (majorVersion < 16) {
        logger.error(`Node version ${majorVersion} is not supported, may malfunction`);
      }
      pair({ opts, ssid: argv.ssid, password: argv.password });
    },
  )
  .demandCommand()
  .parseSync();
