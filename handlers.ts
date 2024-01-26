import { sock } from "./server.js";
import { ControlCommands, Commands, CommandsByValue } from "./datatypes.js";
import { createWriteStream } from "node:fs";
import { SendUsrAck, SendUsrChk, create_P2pRdy } from "./impl.js";

let image_fds = [];
let cur_image_index = 0;
let size_so_far = 0;

export const notImpl = (_: sock, dv: DataView) => {
  const raw = dv.readU16();
  const cmd = CommandsByValue[raw];
  console.log(`^^ ${cmd} (${raw.toString(16)}) and it's not implemented yet`);
};

export const noop = (_: sock, __: DataView) => {};
const create_P2pAliveAck = (): DataView => {
  const outbuf = new DataView(new Uint8Array(4).buffer);
  outbuf.writeU16(Commands.P2PAliveAck);
  outbuf.add(2).writeU16(0);
  return outbuf;
};

export const handle_P2PAlive = (sock: sock, _: DataView) => {
  const b = create_P2pAliveAck();
  sock.send(b);
};
export const handle_PunchPkt = (sock: sock, dv: DataView) => {
  const punchCmd = dv.readU16();
  const len = dv.add(2).readU16();
  const prefix = dv.add(4).readString(4);
  const serial = dv.add(8).readU64().toString();
  const suffix = dv.add(16).readString(4);
  // f141 20 BATC 609531 EXLV
  sock.send(create_P2pRdy(dv.add(4).readByteArray(len)));
};

const deal_with_control = (sock: sock, dv: DataView) => {
  const start_type = dv.add(8).readU16(); // 0xa11 on control; data starts here on DATA pkt
  const cmd_id = dv.add(10).readU16(); // 0x1120

  if (start_type != 0x110a) {
    console.error(`Expected start_type to be 0xa11, got 0x${start_type.toString(16)}`);
    return;
  }

  if (cmd_id == ControlCommands.ConnectUserAck) {
    /*
      00000000  f1 d0 00 18 d1 00 00 00 11 0a 20 11 0c 00 ff 00  .......... .....
      00000010  00 00 00 00 34 54 63 4d fe 01 01 01              ....4TcM....
                            ^^^^^^^^^^^
                            some kind of challenge
                            need to send the 0x3010
                            command with these 4 bytes 'encrypted'
      */
    let challenge = [0, 0, 0, 0];
    challenge[0] = dv.add(0x14).readU8();
    challenge[1] = dv.add(0x15).readU8();
    challenge[2] = dv.add(0x16).readU8();
    challenge[3] = dv.add(0x17).readU8();
    const buf = SendUsrAck(challenge);
    sock.send(buf);
  }
};

const deal_with_data = (dv: DataView) => {
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
    // TODO audio pkt
  } else {
    if (is_new_image) {
      size_so_far = 0;
      if (cur_image_index > 0) {
        image_fds[cur_image_index - 1].close();
      }
      const fname = `captures/${cur_image_index.toString().padStart(4, "0")}.jpg`;
      let cur_image = createWriteStream(fname);
      cur_image.cork();
      image_fds[cur_image_index] = cur_image;
      cur_image_index++;
    }

    const data = dv.add(8).readByteArray(pkt_len - 4);
    image_fds[cur_image_index - 1].write(Buffer.from(data.buffer));
    size_so_far += pkt_len - 4;
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
export const handle_Drw = (sock: sock, dv: DataView) => {
  const ack = makeDrwAck(dv);
  sock.send(ack);

  const m_stream = dv.add(5).readU8(); // data = 1, control = 0
  if (m_stream == 1) {
    deal_with_data(dv);
  } else {
    deal_with_control(sock, dv);
  }
};

export const handle_P2PRdy = (sock: sock, _: DataView) => {
  const b = SendUsrChk("admin", "admin");
  sock.send(b);
};
