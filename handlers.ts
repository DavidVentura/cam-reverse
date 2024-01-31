import { RemoteInfo } from "node:dgram";

import { Commands, CommandsByValue, ControlCommands } from "./datatypes.js";
import { XqBytesDec } from "./func_replacements.js";
import { hexdump } from "./hexdump.js";
import { parse_PunchPkt, create_P2pRdy, SendListWifi, SendUsrChk, DevSerial } from "./impl.js";
import { Session } from "./session.js";
import { u16_swap, u32_swap } from "./utils.js";

let curImage: Buffer | null = null;

export const notImpl = (_: Session, dv: DataView) => {
  const raw = dv.readU16();
  const cmd = CommandsByValue[raw];
  console.log(`^^ ${cmd} (${raw.toString(16)}) and it's not implemented yet`);
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
  const b = SendUsrChk(session, "admin", "admin");
  session.send(b);
};

export const makePunchPkt = (dev: DevSerial): DataView => {
  const len = dev.prefix.length + dev.suffix.length + 8;
  const outbuf = new DataView(new Uint8Array(0x14).buffer); // 8 = serial u64
  console.log(len, dev.prefix.length, dev.serialU64, dev.suffix.length);
  console.log(dev.prefix, dev.serialU64, dev.suffix);
  outbuf.add(0).writeString(dev.prefix);
  outbuf.add(4).writeU64(dev.serialU64);
  outbuf.add(8 + dev.prefix.length).writeString(dev.suffix);
  return create_P2pRdy(outbuf);
};
export const handle_PunchPkt = (session: Session, dv: DataView, rinfo: RemoteInfo) => {
  const dev = parse_PunchPkt(dv);
  session.eventEmitter.emit("connect", dev.devId, rinfo);
  console.log("connect????");
  session.send(makePunchPkt(dev));
};

export const createResponseForControlCommand = (session: Session, dv: DataView): DataView[] => {
  const start_type = dv.add(8).readU16(); // 0xa11 on control; data starts here on DATA pkt
  const cmd_id = dv.add(10).readU16(); // 0x1120
  const payload_len = u16_swap(dv.add(0xc).readU16());

  if (start_type != 0x110a) {
    console.error(`Expected start_type to be 0xa11, got 0x${start_type.toString(16)}`);
    return [];
  }
  const rotate_chr = 4;
  if (payload_len > rotate_chr) {
    // 20 = 16 (header) + 4 (??)
    XqBytesDec(dv.add(20), payload_len - 4, rotate_chr);
    console.log("Decrypted");
    console.log(hexdump(dv));
  }

  if (cmd_id == ControlCommands.ConnectUserAck) {
    let c = new Uint8Array(dv.add(0x18).readByteArray(4).buffer);
    session.ticket = [...c];
    session.eventEmitter.emit("login");
    return [];
  }

  if (cmd_id == ControlCommands.DevStatusAck) {
    // ParseDevStatus -> offset relevant?
    let charging = u32_swap(dv.add(0x28).readU32()) & 1; // 0x14000101 v 0x14000100
    let power = u16_swap(dv.add(0x18).readU16()); // '3730' or '3765', milliVolts?
    let dbm = dv.add(0x24).readU8() - 0x100; // 0xbf - 0x100 = -65dbm .. constant??
    // > -50 = excellent, -50 to -60 good, -60 to -70 fair, <-70 weak

    console.log(`charging? ${charging}, batlevel? ${power}, wifi dbm: ${dbm}`);
  }

  if (cmd_id == ControlCommands.WifiSettingsAck) {
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
    console.log(`Current wifi settings: ${JSON.stringify(wifiSettings, null, 2)}`);
    return [buf];
  }

  if (cmd_id == ControlCommands.ListWifiAck) {
    let startat = 0x10;
    let msg_len = 91;
    console.log("payload len", payload_len);
    let msg_count = (payload_len - 9) / msg_len;
    let remote_msg_count = dv.add(startat).readU32LE();
    console.log("should get messages:", msg_count, "in payload: ", remote_msg_count);
    startat += 4;
    let items = [];
    for (let i = 0; i < msg_count; i++) {
      const wifiListItem = {
        // startat = msg_len * i + 0x14;
        ssid: dv.add(startat).readString(0x40),
        mac: dv.add(startat + 0x40).readByteArray(8),
        security: dv.add(startat + 0x48).readU32LE(),
        dbm0: dv.add(startat + 0x4c).readU32LE(),
        dbm1: dv.add(startat + 0x50).readU32LE(),
        mode: dv.add(startat + 0x54).readU32LE(),
        channel: dv.add(startat + 0x58).readU32LE(),
      };
      console.log(`Wifi Item: ${JSON.stringify(wifiListItem, null, 2)}`);
      startat += msg_len;
      console.log("ended at", startat);
      items.push(wifiListItem);
    }
  }
  return [];
};

let seq = 0;
let frame_is_bad = false;
const deal_with_data = (session: Session, dv: DataView) => {
  const pkt_len = dv.add(2).readU16();
  // data
  const JPEG_HEADER = [0xff, 0xd8, 0xff, 0xdb];
  const AUDIO_HEADER = [0x55, 0xaa, 0x15, 0xa8];
  const m_hdr = dv.add(8).readByteArray(4);
  let is_new_image = true;
  let audio = true;
  const pkt_id = dv.add(6).readU16();
  for (let i = 0; i < 4; i++) {
    is_new_image = is_new_image && m_hdr.add(i).readU8() == JPEG_HEADER[i];
    audio = audio && m_hdr.add(i).readU8() == AUDIO_HEADER[i];
  }

  if (audio) {
    // "stream_head_t->type == 0x06" per pdf
    if (dv.add(12).readU8() == 0x06) {
      const audio_len = u16_swap(dv.add(8 + 16).readU16());
      const audio_buf = dv.add(32 + 8).readByteArray(audio_len).buffer; // 8 for pkt header, 32 for `stream_head_t`
      session.eventEmitter.emit("audio", Buffer.from(audio_buf));
    } else {
      // not sure what these are for, there's one per frame. maybe alignment?
    }
  } else {
    const data = dv.add(8).readByteArray(pkt_len - 4);
    if (is_new_image) {
      if (curImage != null && !frame_is_bad) {
        session.eventEmitter.emit("frame", curImage);
      }

      frame_is_bad = false;
      curImage = Buffer.from(data.buffer);
      seq = pkt_id;
    } else {
      if (pkt_id <= seq) {
        // retransmit
        return;
      }
      if (frame_is_bad) {
        return;
      }
      if (pkt_id > seq + 1) {
        // missed some packets -- filling with zeroes still produces a broken
        // image
        frame_is_bad = true;
        return;
      }
      seq = pkt_id;
      if (curImage != null) {
        curImage = Buffer.concat([curImage, Buffer.from(data.buffer)]);
      }
    }
  }
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
export const handle_Drw = (session: Session, dv: DataView) => {
  const ack = makeDrwAck(dv);
  session.send(ack);

  const m_stream = dv.add(5).readU8(); // data = 1, control = 0
  if (m_stream == 1) {
    deal_with_data(session, dv);
  } else {
    const b = createResponseForControlCommand(session, dv);
    b.forEach(session.send);
  }
};
