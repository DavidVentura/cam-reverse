import fs from "node:fs";
import { parse } from "yaml";

interface HttpServerConfig {
  port: number;
}

interface LoggingConfig {
  level: string;
  use_color?: boolean;
}

interface CameraConfig {
  alias?: string;
  rotate?: number;
  mirror?: boolean;
  audio?: boolean;
  fix_packet_loss?: boolean;
}

interface AppConfig {
  http_server: HttpServerConfig;
  logging: LoggingConfig;
  cameras: Record<string, CameraConfig>;
  discovery_ips: string[];
  blacklisted_ips: string[];
}

const DefaultConfig: AppConfig = {
  http_server: { port: 5000 },
  logging: { level: "info" },
  cameras: {},
  discovery_ips: ["192.168.1.255"],
  blacklisted_ips: [],
};

let config = DefaultConfig;

export const loadConfig = (path: string) => {
  const data = fs.readFileSync(path, { encoding: "utf-8" });
  config = parse(data) as AppConfig;
  config = { ...DefaultConfig, ...config };
};

export { config };
