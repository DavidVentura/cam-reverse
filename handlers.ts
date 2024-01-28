import { Commands, CommandsByValue, ControlCommands } from "./datatypes.js";
import { create_P2pRdy, SendStartVideo, SendDevStatus, SendUsrChk } from "./impl.js";
import { Session } from "./server.js";
import { u16_swap, u32_swap } from "./utils.js";
import { hexdump } from "./hexdump.js";
import { XqBytesDec } from "./func_replacements.js";

let curImage = null;

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
export const handle_PunchPkt = (session: Session, dv: DataView) => {
  const punchCmd = dv.readU16();
  const len = dv.add(2).readU16();
  const prefix = dv.add(4).readString(4);
  const serial = dv.add(8).readU64().toString();
  const suffix = dv.add(16).readString(len - 16 + 4); // 16 = offset, +4 header
  // f141 20 BATC 609531 EXLVS
  session.eventEmitter.emit("connect", prefix.toString() + serial + suffix.toString());
  session.send(create_P2pRdy(dv.add(4).readByteArray(len)));
};

export const createResponseForControlCommand = (session: Session, dv: DataView): DataView | null => {
  const start_type = dv.add(8).readU16(); // 0xa11 on control; data starts here on DATA pkt
  const cmd_id = dv.add(10).readU16(); // 0x1120
  const payload_len = u16_swap(dv.add(0xc).readU16());

  if (start_type != 0x110a) {
    console.error(`Expected start_type to be 0xa11, got 0x${start_type.toString(16)}`);
    return;
  }
  const rotate_chr = 4;
  if (payload_len > rotate_chr) {
    // 20 = 16 (header) + 4 (??)
    XqBytesDec(dv.add(20), payload_len - 4, rotate_chr);
    // console.log(hexdump(dv));
  }

  if (cmd_id == ControlCommands.ConnectUserAck) {
    let c = new Uint8Array(dv.add(0x18).readByteArray(4).buffer);
    session.ticket = [...c];
    const buf = SendStartVideo(session);
    return buf;
  }

  if (cmd_id == ControlCommands.DevStatusAck) {
    let charging = u32_swap(dv.add(0x28).readU32()) & 1; // 0x14000101 v 0x14000100
    let power = u16_swap(dv.add(0x18).readU16()); // '3730' or '3765', milliVolts?
    let dbm = dv.add(0x24).readU8() - 0x100; // 0xbf - 0x100 = -65dbm .. constant??
    // > -50 = excellent, -50 to -60 good, -60 to -70 fair, <-70 weak

    console.log(`charging? ${charging}, batlevel? ${power}, wifi dbm: ${dbm}`);
  }
  // 0x6102 = parseWifisetting
  /*
   *   01-28 18:19:55.558 12566  3872 F LogUtils: cmdParser,setting:WifiSettingBean{ssid='FTYC477259EDEDE', psk='12345678', ip='0.255.255.255', mask='0.0.0.0', gw='0.0.0.0', dns1='0.0.0.0', dns2='0.0.0.0', enable=0, wifiStatus=0  , mode=2, channel=0, authtype=0, dhcp=0}  [ file:IpcByte2ObjectParser.java, line:1361, method:ParseWifiSetting, class:com.ilnk.callback.IpcByte2ObjectParser ]
  decrypted data
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
  00000000  f1 d0 01 18 d1 00 00 c9 11 0a 02 61 0c 01 00 00  ...........a....
  00000010  00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00  ................
  00000020  00 00 00 00 00 00 00 00 00 00 00 00 46 54 59 43  ............FTYC
  00000030  34 37 37 32 35 39 45 44 45 44 45 00 00 00 00 00  477259EDEDE.....
  00000040  00 00 00 00 00 00 00 00 00 00 00 00 31 32 33 34  ............1234
  00000050  35 36 37 38 00 00 00 00 00 00 00 00 00 00 00 00  5678............
  00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00000070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  000000a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  000000b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  000000c0  00 00 00 00 00 00 00 00 00 00 00 00 30 2e 32 35  ............0.25
  000000d0  35 2e 32 35 35 2e 32 35 35 00 00 00 30 2e 30 2e  5.255.255...0.0.
  000000e0  30 2e 30 00 00 00 00 00 00 00 00 00 30 2e 30 2e  0.0.........0.0.
  000000f0  30 2e 30 00 00 00 00 00 00 00 00 00 30 2e 30 2e  0.0.........0.0.
  00000100  30 2e 30 00 00 00 00 00 00 00 00 00 30 2e 30 2e  0.0.........0.0.
  00000110  30 2e 30 00 00 00 00 00 01 01 01 01              0.0.........

  */
};

const deal_with_data = (session: Session, dv: DataView) => {
  const pkt_len = dv.add(2).readU16();
  // data
  const JPEG_HEADER = [0xff, 0xd8, 0xff, 0xdb];
  const AUDIO_HEADER = [0x55, 0xaa, 0x15, 0xa8];
  const m_hdr = dv.add(8).readByteArray(4);
  let is_new_image = true;
  let audio = true;
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
      if (curImage != null) {
        session.eventEmitter.emit("frame", curImage);
      }
      curImage = Buffer.from(data.buffer);
    } else {
      curImage = Buffer.concat([curImage, Buffer.from(data.buffer)]);
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
    if (b != null) {
      session.send(b);
    }
  }
};

export const handle_P2PRdy = (session: Session, _: DataView) => {
  const b = SendUsrChk("admin", "admin", session.outgoingCommandId);
  session.send(b);
};
