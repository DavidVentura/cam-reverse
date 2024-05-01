import { hideBin } from "yargs/helpers";
import yargs from "yargs/yargs";

import { serveHttp } from "../http_server.js";
import { opt } from "../options.js";
import { pair } from "../pair.js";

import { buildLogger } from "../logger.js";

yargs(hideBin(process.argv))
  .command(
    "http_server",
    "start http server",
    (yargs) => {
      return yargs
        .option("ansi", { default: false })
        .option("slow_startup", { default: false })
        .option("audio", { describe: "Also stream audio from camera", default: true })
        .option("color", { describe: "Use color in logs", default: undefined })
        .boolean(["ansi", "audio", "slow_startup", "color"])
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
      serveHttp(opts, argv.port, argv.audio || false);
    },
  )
  .command(
    "pair",
    "configure a camera",
    (yargs) => {
      return yargs
        .option("ansi", { default: false })
        .option("slow_startup", { default: false })
        .option("color", { describe: "Use color in logs", default: undefined })
        .boolean(["ansi", "slow_startup", "color"])
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
      pair({ opts, ssid: argv.ssid, password: argv.password });
    },
  )
  .demandCommand()
  .parseSync();
