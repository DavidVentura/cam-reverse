import { Commands, CommandsByValue, ControlCommands } from "./datatypes.js";
import { XqBytesDec } from "./func_replacements.js";
import { create_P2pRdy, DevSerial, SendListWifi, SendUsrChk } from "./impl.js";
import { logger } from "./logger.js";
import { Session } from "./session.js";
import { config } from "./settings.js";

export const notImpl = (session: Session, dv: DataView) => {
  const raw = dv.readU16();
  const cmd = CommandsByValue[raw];
  logger.debug(`^^ ${cmd} (${raw.toString(16)}) and it's not implemented yet`);
};

export const noop = (_: Session, __: DataView) => {};
const create_P2pAliveAck = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.P2PAliveAck);
  outbuf.add(2).writeU16(0);
  return outbuf;
};

export const handle_P2PAlive = (session: Session, _: DataView) => {
  const b = create_P2pAliveAck();
  session.send(b);
};

export const handle_P2PRdy = (session: Session, _: DataView) => {
  // TODO - config
  const b = SendUsrChk(session, "admin", "admin");
  session.send(b);
};

export const makeP2pRdy = (dev: DevSerial): DataView => {
  const outbuf = new DataView(new Uint8Array(0x14).buffer); // 8 = serial u64
  // The protocol seems to expect 4 bytes -- check the regression test
  // `replies properly to PunchPkt with 3-letters-long prefix` for a case with a
  // real device
  const devPrefixLength = 4;
  outbuf.add(0).writeString(dev.prefix);
  outbuf.add(4).writeU64(dev.serialU64);
  outbuf.add(8 + devPrefixLength).writeString(dev.suffix);
  return create_P2pRdy(outbuf);
};

export const swVerToString = (swver: number): string => {
  return (
    ((swver >> 24) & 255).toString() +
    "." +
    ((swver >> 16) & 255).toString() +
    "." +
    ((swver >> 8) & 255).toString() +
    "." +
    (swver & 255).toString()
  );
};
export type DevStatus = {
  charging: boolean;
  battery_mV: number;
  dbm: number;
  swver: string;
};
export const parseDevStatusAck = (dv: DataView): DevStatus => {
  const charging = dv.add(0x28).readU32LE() & 1; // 0x14000101 v 0x14000100
  const power = dv.add(0x18).readU16LE(); // '3730' or '3765', milliVolts
  const dbm = dv.add(0x24).readU8() - 0x100; // 0xbf - 0x100 = -65dbm .. constant??
  const n_swver = dv.add(0x14).readU32LE();
  const swver = swVerToString(n_swver);
  return {
    charging: charging > 0,
    battery_mV: power,
    dbm,
    swver,
  };
};
export const createResponseForControlCommand = (session: Session, dv: DataView): DataView[] => {
  const start_type = dv.add(8).readU16(); // 0xa11 on control; data starts here on DATA pkt
  const cmd_id = dv.add(10).readU16(); // 0x1120
  let payload_len = dv.add(0xc).readU16LE();
  if (dv.byteLength > 20 && payload_len > dv.byteLength) {
    logger.warning(`Received a cropped payload: ${payload_len} when packet is ${dv.byteLength}`);
    payload_len = dv.byteLength - 20;
  }

  if (start_type != 0x110a) {
    logger.error(`Expected start_type to be 0xa11, got 0x${start_type.toString(16)}`);
    return [];
  }
  const rotate_chr = 4;
  if (payload_len > rotate_chr) {
    // 20 = 16 (header) + 4 (??)
    XqBytesDec(dv.add(20), payload_len - 4, rotate_chr);
  }

  // the first 20 bytes are header

  switch (cmd_id) {
    case ControlCommands.ConnectUserAck:
      let c = new Uint8Array(dv.add(0x18).readByteArray(4).buffer);
      session.ticket = [...c];
      session.eventEmitter.emit("login");
      return [];

    case ControlCommands.DevStatusAck:
      // ParseDevStatus -> offset relevant?
      const status = parseDevStatusAck(dv);
      // > -50 = excellent, -50 to -60 good, -60 to -70 fair, <-70 weak

      logger.info(
        `Camera ${session.devName}: sw: ${status.swver}, ${status.charging ? "" : "not "}charging, battery at ${
          status.battery_mV
        }mV, Wifi ${status.dbm} dBm`,
      );
      return [];

    case ControlCommands.WifiSettingsAck:
      const wifiSettings = {
        enable: dv.add(0x14).readU32(),
        status: dv.add(0x18).readU32(),
        mode: dv.add(0x1c).readU32LE(),
        channel: dv.add(0x20).readU32(),
        authtype: dv.add(0x24).readU32(),
        dhcp: dv.add(0x28).readU32(),
        ssid: dv.add(0x2c).readString(0x20),
        psk: dv.add(0x4c).readString(0x80),
        ip: dv.add(0xcc).readString(0x10),
        mask: dv.add(0xdc).readString(0x10),
        gw: dv.add(0xec).readString(0x10),
        dns1: dv.add(0xfc).readString(0x10),
        dns2: dv.add(0x10c).readString(0x10),
      };
      const buf = SendListWifi(session);
      logger.info(`Current Wifi settings: ${JSON.stringify(wifiSettings, null, 2)}`);
      return [buf];

    case ControlCommands.ListWifiAck:
      if (payload_len == 4) {
        logger.debug("ListWifi returned []");
        return [];
      }
      const items = parseListWifi(dv);
      session.eventEmitter.emit("ListWifi", items);
      return [];
    case ControlCommands.StartVideoAck:
      logger.debug("Start video ack");
      return [];
    case ControlCommands.VideoParamSetAck:
      logger.debug("Video param set ack");
      return [];
    default:
      logger.info(`Unhandled control command: 0x${cmd_id.toString(16)}`);
  }
  return [];
};

export type WifiListItem = {
  ssid: string;
  mac: string;
  security: number;
  dbm0: number;
  dbm1: number;
  mode: number;
  channel: number;
};

export const parseListWifi = (dv: DataView): WifiListItem[] => {
  let startat = 0x10;
  const msg_len = 0x5c; // 0x58 + 0x4 of the last u32
  const msg_count = dv.add(startat).readU32LE();
  startat += 4;
  let items = [];
  for (let i = 0; i < msg_count; i++) {
    if (startat + msg_len > dv.byteLength) {
      logger.warning("Wifi listing got cropped");
      break;
    }
    const macBytes = dv.add(startat + 0x40).readByteArray(6).buffer;
    const mb = new Uint8Array(macBytes);
    const wifiListItem = {
      ssid: dv.add(startat).readString(0x40),
      mac: [...mb].map((b) => b.toString(16).padStart(2, "0")).join(":"),
      security: dv.add(startat + 0x48).readU32LE(),
      dbm0: dv.add(startat + 0x4c).readU32LE(),
      dbm1: dv.add(startat + 0x50).readU32LE(),
      mode: dv.add(startat + 0x54).readU32LE(),
      channel: dv.add(startat + 0x58).readU32LE(),
    };
    startat += msg_len;
    items.push(wifiListItem);
  }
  return items;
};

const deal_with_data = (session: Session, dv: DataView) => {
  const pkt_len = dv.add(2).readU16();

  // 12 equals start of header (0x8) + header length (0x4)
  if (pkt_len < 12) {
    logger.log("trace", "Got a short Drw packet, ignoring");
    return;
  }

  const FRAME_HEADER = [0x55, 0xaa, 0x15, 0xa8];
  const m_hdr = dv.add(8).readByteArray(4);
  const pkt_id = dv.add(6).readU16();
  const STREAM_TYPE_AUDIO = 0x06;
  const STREAM_TYPE_JPEG = 0x03;

  const startNewFrame = (buf: ArrayBuffer) => {
    if (session.curImage.length > 0 && !session.frame_is_bad) {
      session.eventEmitter.emit("frame");
    }

    session.frame_was_fixed = false;
    session.frame_is_bad = false;
    session.curImage = [Buffer.from(buf)];
    session.rcvSeqId = pkt_id;
  };

  let is_framed = m_hdr.startsWith(FRAME_HEADER);

  if (is_framed) {
    const stream_type = dv.add(12).readU8();
    if (stream_type == STREAM_TYPE_AUDIO) {
      const audio_len = dv.add(8 + 16).readU16LE();
      const audio_buf = dv.add(32 + 8).readByteArray(audio_len).buffer; // 8 for pkt header, 32 for `stream_head_t`
      session.eventEmitter.emit("audio", { gap: false, data: Buffer.from(audio_buf) });
    } else if (stream_type == STREAM_TYPE_JPEG) {
      const to_read = pkt_len - 4 - 32;
      if (to_read > 0) {
        // some cameras do not send the data with the frame, but rather as a
        // followup message skip 8 bytes (drw header) + 32 bytes (data frame)
        const data = dv.add(32 + 8).readByteArray(to_read);
        startNewFrame(data.buffer);
      }
    } else {
      logger.debug(`Ignoring data frame with stream type ${stream_type} - not implemented`);
      // not sure what these are for, there's one per frame. maybe alignment?
    }
  } else {
    const JPEG_HEADER = [0xff, 0xd8, 0xff, 0xdb];
    // a new JPEG image may begin either
    // - as a frame with stream_type == 0x03
    // - as unframed data, started by JPEG_HEADER
    // but for both types of cameras, unframed data which does not start with
    // JPEG_HEADER are segments of the (potentially already started) JPEG image
    const data = dv.add(8).readByteArray(pkt_len - 4);
    // this only happens on un-framed-cameras, which start the JPEG image
    // directly
    let is_new_image = m_hdr.startsWith(JPEG_HEADER);

    if (is_new_image) {
      startNewFrame(data.buffer);
    } else {
      if (pkt_id <= session.rcvSeqId) {
        // retransmit
        return;
      }
      if (session.curImage.length == 0) return; // missed the start-of-frame packet

      let b = Buffer.from(data.buffer);

      if (pkt_id > session.rcvSeqId + 1) {
        if (!session.frame_is_bad) {
          session.frame_is_bad = true;
          logger.debug(`Dropping corrupt frame ${pkt_id}, expected ${session.rcvSeqId + 1}`);
        }
        // this should always be enabled but currently it seems to cause more
        // visual distortion than just missing some frames
        if (!config.cameras[session.devName]?.fix_packet_loss) {
          return;
        }

        if (session.curImage.length == 1) return; // header does not have markers

        let lastFrameSlice = session.curImage[session.curImage.length - 1];
        const lastResetMarker = findAllResetMarkers(lastFrameSlice).pop();
        if (lastResetMarker == undefined) {
          // not storing rcvSeqId as this frame did not put us back in track
          return;
        }

        const firstResetMarker = findAllResetMarkers(b).shift();
        if (firstResetMarker == undefined) {
          // not storing rcvSeqId as this frame did not put us back in track
          return;
        }

        session.curImage[session.curImage.length - 1] = Buffer.from(lastFrameSlice.subarray(0, lastResetMarker));
        b = Buffer.from(b.subarray(firstResetMarker));
        session.frame_is_bad = false;
        session.frame_was_fixed = true;
      }

      session.rcvSeqId = pkt_id;
      if (session.curImage != null) {
        session.curImage.push(b);
      }
    }
  }
};

const findAllResetMarkers = (b: Buffer): number[] => {
  // a reset marker is a byte 0xff followed by a byte 0xd0-0xd7
  let ret = [];
  for (let i = 0; i < b.length - 1; i++) {
    if (b[i] == 0xff) {
      const nb = b[i + 1];
      if (nb >= 0xd0 && nb <= 0xd7) {
        ret.push(i);
      }
    }
  }
  return ret;
};

const makeDrwAck = (dv: DataView): DataView => {
  const pkt_id = dv.add(6).readU16();
  const m_stream = dv.add(5).readU8(); // data = 1, control = 0
  const item_count = 1; // TODO coalesce acks
  const reply_len = item_count * 2 + 4; // 4 hdr, 2b per item
  const outbuf = new DataView(new Uint8Array(32).buffer);
  outbuf.writeU16(Commands.DrwAck);
  outbuf.add(2).writeU16(reply_len);
  outbuf.add(4).writeU8(0xd2);
  outbuf.add(5).writeU8(m_stream);
  outbuf.add(6).writeU16(item_count);
  for (let i = 0; i < item_count; i++) {
    outbuf.add(8 + i * 2).writeU16(pkt_id);
  }
  return outbuf;
};

export const handle_DrwAck = (session: Session, dv: DataView) => {
  const packetlen = dv.add(2).readU16();
  const str_type = dv.add(4).readU8();
  const str_id = dv.add(5).readU8();
  const ack_count = dv.add(6).readU16();
  for (let i = 0; i < ack_count; i++) {
    const ack_id = dv.add(8 + i * 2).readU16();
    session.ackDrw(ack_id);
  }
};
export const handle_Drw = (session: Session, dv: DataView) => {
  const ack = makeDrwAck(dv);
  session.send(ack);

  const m_stream = dv.add(5).readU8(); // data = 1, control = 0
  if (m_stream == 1) {
    deal_with_data(session, dv);
  } else if (m_stream == 0) {
    const b = createResponseForControlCommand(session, dv);
    b.forEach(session.send);
  } else {
    logger.warning(`Received a Drw packet with stream tag: ${m_stream}, which is not implemented`);
  }
};
export const handle_Close = (session: Session, dv: DataView) => {
  const ack = makeDrwAck(dv);
  session.send(ack);
  logger.info("Requested to close connection");
  session.close();
};
