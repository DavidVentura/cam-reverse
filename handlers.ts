import { Commands, CommandsByValue, ControlCommands } from "./datatypes.js";
import { create_P2pRdy, SendStartVideo, SendUsrChk } from "./impl.js";
import { Session } from "./server.js";
import { u16_swap } from "./utils.js";

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
  const suffix = dv.add(16).readString(4);
  // f141 20 BATC 609531 EXLV
  session.send(create_P2pRdy(dv.add(4).readByteArray(len)));
};

export const createResponseForControlCommand = (session: Session, dv: DataView): DataView | null => {
  const start_type = dv.add(8).readU16(); // 0xa11 on control; data starts here on DATA pkt
  const cmd_id = dv.add(10).readU16(); // 0x1120

  if (start_type != 0x110a) {
    console.error(`Expected start_type to be 0xa11, got 0x${start_type.toString(16)}`);
    return;
  }

  if (cmd_id == ControlCommands.ConnectUserAck) {
    let c = new Uint8Array(dv.add(0x14).readByteArray(4).buffer);
    session.ticket[0] = c[0] % 2 == 0 ? c[0] + 1 : c[0] - 1;
    session.ticket[1] = c[1] % 2 == 0 ? c[1] + 1 : c[1] - 1;
    session.ticket[2] = c[2] % 2 == 0 ? c[2] + 1 : c[2] - 1;
    session.ticket[3] = c[3] % 2 == 0 ? c[3] + 1 : c[3] - 1;
    const buf = SendStartVideo(session);
    return buf;
  }
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
