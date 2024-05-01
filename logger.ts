import { isatty } from "node:tty";
import { addColors, config, createLogger, format, transports as wtransports } from "winston";

const myFormat = format.printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level}] ${message}`;
});

const transports = {
  console: new wtransports.Console(),
};

export let logger = undefined;

export const buildLogger = (level: string, colorize: boolean | undefined) => {
  let use_color = colorize === undefined ? isatty(1) : colorize;
  const fmt = use_color
    ? format.combine(format.colorize(), format.timestamp(), myFormat)
    : format.combine(format.timestamp(), myFormat);
  logger = createLogger({
    levels: { ...config.syslog.levels, trace: 10 },
    level,
    format: fmt,
    transports: [transports.console],
  });
  addColors({ trace: "white" });
};
