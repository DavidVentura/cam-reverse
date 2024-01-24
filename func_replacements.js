import { swap_endianness_u32, swap_endianness_u16, u16_swap } from "./utils.js";
export const Commands = {
  Close: 0xf1f0,
  LanSearchExt: 0xf132,
  LanSearch: 0xf130,
  P2PAlive: 0xf1e0,
  P2PAliveAck: 0xf1e1,
  Hello: 0xf100,
  P2pRdy: 0xf142,
  P2pReq: 0xf120,
  LstReq: 0xf167,
  DrwAck: 0xf1d1,
  Drw: 0xf1d0,

  // From CSession_CtrlPkt_Proc, incomplete
  PunchTo: 0xf140,
  PunchPkt: 0xf141,
  HelloAck: 0xf101,
  RlyTo: 0xf102,
  DevLgnAck: 0xf111,
  P2PReqAck: 0xf121,
  ListenReqAck: 0xf169,
  RlyHelloAck: 0xf170, // always
  RlyHelloAck2: 0xf171, // if len >1??
};

export const CommandsByValue = Object.keys(Commands).reduce((acc, cur) => {
  acc[Commands[cur]] = cur;
  return acc;
}, {});

const writeCommand2 = (command, buf) => {
  buf.writeByteArray([(command & 0xff00) >> 8, command & 0xff]);
};
const writeCommand4 = (command, buf) => {
  buf.writeByteArray([(command & 0xff00) >> 8, command & 0xff, 0x00, 0x00]);
};

export const XqBytesDec = (inoutbuf, buflen, rotate) => {
  let new_buf = new Uint8Array(buflen);
  new_buf.fill(0x1);
  for (let i = 0; i < buflen; i++) {
    let b = inoutbuf.add(i).readU8();
    if ((b & 1) != 0) {
      new_buf[i] = b - 1;
    } else {
      new_buf[i] = b + 1;
    }
  }
  for (let i = rotate; i < buflen; i++) {
    inoutbuf.add(i).writeU8(new_buf[i - rotate]);
  }
  for (let i = 0; i < rotate; i++) {
    inoutbuf.add(i).writeU8(new_buf[buflen - rotate + i]);
  }
};

export const XqBytesEnc = (inoutbuf, buflen, rotate) => {
  let new_buf = new Uint8Array(buflen);
  new_buf.fill(0x1);
  for (let i = 0; i < buflen; i++) {
    let b = inoutbuf.add(i).readU8();
    if ((b & 1) != 0) {
      new_buf[i] = b - 1;
    } else {
      new_buf[i] = b + 1;
    }
  }
  for (let i = 0; i < buflen - rotate; i++) {
    inoutbuf.add(i).writeU8(new_buf[i + rotate]);
  }
  for (let i = 0; i < rotate; i++) {
    inoutbuf.add(buflen - rotate + i).writeU8(new_buf[i]);
  }
};

const compare_buf = (a, b, len) => {
  console.log(`comparin len ${len}`);
  const ba = new Uint8Array(a.readByteArray(len));
  const bb = new Uint8Array(b.readByteArray(len));

  let deltas = new Uint8Array(len);
  let bad = false;
  for (let i = 0; i < len; i++) {
    if (ba[i] == bb[i]) {
      deltas[i] = 0;
    } else {
      deltas[i] = 0xff;
      bad = true;
    }
  }
  if (bad) {
    console.log("deltas");
    console.log(deltas.buffer);
    console.log("buf a");
    console.log(ba.buffer);
    console.log("buf b");
    console.log(bb.buffer);
    console.log("####");
  }
};

const reply_Drw = (inbuf, outbuf) => {
  /*
  -> cmd = inbuf+10
  -> chan = inbuf+9
  -> param2 = lock ? 0xd1 : 0xd2 (never lock branch) => 0xd2
  -> Send_Pkt_DrwAck(10,0xd2,channel,1,&cmd_,sock_fd,ipaddr_);
    -> create_DrwAck(bare_drwack, 0xd2, chan, halflen??, inbuf)
    -> pack_P2pHdr(bare_drwack, pkt_hdr)
    -> pack_DrwAck(bare_drwack+4, len = swapped(bare_drwack[1]), pkt_hdr +
  hdr_len)
    -> send_udp(pkt_hdr, max(hdr_len, 0x20)??)
   */
  const chan = inbuf.add(9).readU16();
  const cmd = inbuf.add(10).readU16();
  const param2 = 0xd2; // ?
  const half_len = 1; // FIXME u16_swap(inbuf.add(0xc).readU16());
  const bare_ack = Memory.alloc(half_len * 2 + 8 + 4); // fixme +4
  create_DrwAck(bare_ack, param2, chan, half_len, inbuf);
  const hdr_len = pack_P2pHdr(bare_ack, outbuf);
  pack_DrwAck(bare_ack.add(4), half_len * 2 + 4, outbuf.add(hdr_len));
};
const pack_P2pHdr = (inbuf, out_buf) => {
  // shitty memcpy
  out_buf.writeByteArray(inbuf.readByteArray(4));
  return 4;
};
const create_Close = (buf) => {
  writeCommand4(Commands.Close, buf);
  return 4;
};

const create_LanSearchExt = (buf) => {
  writeCommand4(Commands.LanSearchExt, buf);
  return 4;
};

const create_LanSearch = (buf) => {
  writeCommand4(Commands.LanSearch, buf);
  return 4;
};

const create_P2pAliveAck = (buf) => {
  writeCommand4(Commands.P2PAliveAck, buf);
  return 4;
};
const create_P2pAlive = (buf) => {
  writeCommand4(Commands.P2PAlive, buf);
  return 4;
};

const create_Hello = (buf) => {
  writeCommand4(Commands.Hello, buf);
  return 4;
};

// 							 : Pointer
const create_P2pRdy = (outbuf, inbuf) => {
  // TODO: this is literlly the same as create_LstReq, just different command
  const P2PRDY_SIZE = 0x14;
  writeCommand2(Commands.P2pRdy, outbuf);
  // outbuf[2] = P2PRDY_SIZE
  outbuf.add(2).writeU16(P2PRDY_SIZE << 8);
  outbuf.add(8).writeU64(inbuf.readU64());
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  outbuf.add(2 * 0xc).writeU32(inbuf.add(16).readU32());
  return P2PRDY_SIZE + 4;
};

const create_P2pReq = (outbuf, inbuf, m_s_addr, addr_fam) => {
  const P2PREQ_SIZE = 0x24;
  writeCommand2(Commands.P2pReq, outbuf);
  outbuf.add(2).writeU16(P2PREQ_SIZE << 8);
  outbuf.add(8).writeU64(inbuf.readU64());
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  outbuf.add(2 * 0xc).writeU32(inbuf.add(16).readU32());

  outbuf.add(2 * 0xe).writeByteArray(swap_endianness_u16(m_s_addr));
  outbuf.add(2 * 0xf).writeByteArray(swap_endianness_u16(m_s_addr.add(2)));

  outbuf.add(2 * 0x12).writeU64(0);
  outbuf.add(2 * 0x10).writeByteArray(swap_endianness_u32(m_s_addr.add(4))); // ip address

  return P2PREQ_SIZE + 4;
};

const create_LstReq = (outbuf, inbuf) => {
  const LISTREQ_SIZE = 0x14;
  writeCommand2(Commands.LstReq, outbuf);
  outbuf.add(2).writeU16(LISTREQ_SIZE << 8);

  // 4 * sizeof(short)
  outbuf.add(8).writeU64(inbuf.readU64());
  // 8 * sizeof(short)
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  // 0xc * sizeof(short)
  outbuf.add(2 * 0xc).writeU32(inbuf.add(0x10).readU32());

  return LISTREQ_SIZE + 4; // this is actually wrong (and unused) in the code -- it is 0x1c
};

const create_DrwAck = (outbuf, idk_param2, channel, half_len, inbuf) => {
  console.log(`DrwAck: 2: ${idk_param2} 3: ${channel}, halflen: ${half_len}`);
  //  param2 is 0xd1 if "unlocked" and 0xd2 if "locked"?
  const copyLen = half_len * 2;
  writeCommand2(Commands.DrwAck, outbuf);
  outbuf.add(2).writeU16(u16_swap(copyLen + 4));
  outbuf.add(8).writeU8(idk_param2);
  outbuf.add(9).writeU8(channel);
  outbuf.add(10).writeU16(u16_swap(half_len));
  outbuf.add(12).writeByteArray(inbuf.readByteArray(copyLen));
  return half_len * 2 + 8;
};

const dbg_create_Drw = (og_func) => {
  const create_Drw = (outbuf, idk_param2, idk_param3, idk_param4, copy_len, inbuf) => {
    /// idk_param4 goes up by 0x100 per call

    // console.log(
    //   `2: ${idk_param2.toString(16)} 3: ${idk_param3.toString(16)} 4:
    //   ${idk_param4.toString(16)} copylen: ${copy_len}`,
    //);
    const copy_len_swapped = u16_swap(copy_len + 4);
    writeCommand2(Commands.Drw, outbuf);
    outbuf.add(2).writeU16(copy_len_swapped);
    outbuf.add(8).writeU8(0xd1);
    outbuf.add(10).writeU16(idk_param4);
    outbuf.add(12).writeByteArray(inbuf.readByteArray(copy_len));

    return copy_len + 8;
  };
  return create_Drw;
};
const dbg_pack_ClntPkt = (og_func) => {
  const pack_ClntPkt = (addr_fam, inbuf, outbuf) => {
    const cmd = u16_swap(inbuf.readU16());
    console.log(`pack_ClntPkt: cmd 0x${cmd.toString(16)} = ${CommandsByValue[cmd]}; fam ${addr_fam}; inbuf =>`);
    const hdrLen = pack_P2pHdr(inbuf, outbuf);
    const packFn = {
      [Commands.LanSearch]: () => hdrLen,
      [Commands.LanSearchExt]: () => hdrLen,
      [Commands.Close]: () => hdrLen,
      [Commands.Hello]: () => hdrLen,
      [Commands.P2pReq]: () => hdrLen + pack_P2pReq4(inbuf.add(8), outbuf.add(hdrLen)),
      [Commands.LstReq]: () => hdrLen + pack_P2pId(inbuf.add(8), outbuf.add(hdrLen)),
      [Commands.DrwAck]: () => {
        const pkt_size = u16_swap(inbuf.add(2).readU16());
        return hdrLen + pack_DrwAck(inbuf.add(8), pkt_size, outbuf.add(hdrLen));
      },
      [Commands.Drw]: () => {
        const pkt_size = u16_swap(inbuf.add(2).readU16());
        return hdrLen + pack_Drw(inbuf.add(8), pkt_size, outbuf.add(hdrLen));
      },
    };
    /*
	  P2PAlive: 0xf1e0,
	  P2PAliveAck: 0xf1e1,
	  P2pRdy: 0xf142, // idk??
	  */

    const fn = packFn[cmd];
    if (fn == undefined) {
      console.error(`IDK how to handle ${cmd}`);
    } else {
      const my_ret = fn();
      // compare_buf(outbuf, new_outbuf, ret);
      // console.log(new_outbuf.readByteArray(ret));
      return my_ret;
    }
    return -1;
  };
  return pack_ClntPkt;
};

const pack_Drw = (inbuf, m_pkt_size, outbuf) => {
  // a shitty memcpy?
  const DRW_HDR_SIZE = 0x4;

  outbuf.writeU8(inbuf.readU8());
  outbuf.add(1).writeU8(inbuf.add(1).readU8());
  outbuf.add(2).writeU16(inbuf.add(2).readU16());
  outbuf.add(4).writeByteArray(inbuf.add(4).readByteArray(m_pkt_size - DRW_HDR_SIZE));

  return m_pkt_size;
};
// FIXME literally identical to pack_Drw
const pack_DrwAck = (inbuf, m_pkt_size, outbuf) => {
  // a shitty memcpy?
  const DRW_ACK_HDR_SIZE = 0x4;

  outbuf.writeU8(inbuf.readU8());
  outbuf.add(1).writeU8(inbuf.add(1).readU8());
  outbuf.add(2).writeU16(inbuf.add(2).readU16());
  outbuf.add(4).writeByteArray(inbuf.add(4).readByteArray(m_pkt_size - DRW_ACK_HDR_SIZE));

  return m_pkt_size;
};

const pack_P2pId = (inbuf, outbuf) => {
  outbuf.writeU64(inbuf.readU64());
  outbuf.add(8).writeU32(inbuf.add(8).readU32());
  outbuf.add(0xc).writeU64(inbuf.add(0xc).readU32());

  return 0x14;
};

const pack_P2pReq4 = (inbuf, outbuf) => {
  // a shitty memcpy?
  Memory.copy(outbuf, inbuf, 0x24);
  return 0x24;
};

const replace_func = (stub, ret, args) => {
  const name_in_elf = stub.name.replace("dbg_", ""); // UGH  FIXME
  const symbol_addr = DebugSymbol.fromName(name_in_elf).address;
  if (symbol_addr == 0) {
    console.error(`Could not find ${name_in_elf}`);
    return;
  }

  const orig_func = new NativeFunction(symbol_addr, ret, args);

  let replacement_func;
  if (stub.name.startsWith("dbg_")) {
    replacement_func = stub(orig_func);
  } else {
    replacement_func = stub;
  }

  console.log(`Replacing ${name_in_elf}, signature "${ret} ${name_in_elf}(${args})"`);

  Interceptor.replace(symbol_addr, new NativeCallback(replacement_func, ret, args));
};

/* Send_Pkt_LanSearch =
 * create_LanSearch(buf)
 * pack_ClntPkt(2, buf, &packed_buf)
 * UdpPktSend(packed_buf)
 */
/* Send_Pkt_Hello =
 * create_Hello
 * pack_ClntPkt
 * UdpPktSend
 */

// CSession_DataPkt_Proc(struct, *cmd) == Drw_Deal
// CSession_CtrlPkt_Proc(struct, *cmd) == control?
export const replaceFunctions = () => {
  const replacements = [
    [create_P2pAlive, "uint8", ["pointer"]],
    [create_P2pAliveAck, "uint8", ["pointer"]],
    [create_LanSearch, "uint8", ["pointer"]],
    [create_LanSearchExt, "uint8", ["pointer"]],
    [create_Hello, "uint8", ["pointer"]],
    [create_Close, "uint8", ["pointer"]],
    [dbg_create_Drw, "uint", ["pointer", "uint64", "uint8", "uint16", "uint32", "pointer"]],
    [create_DrwAck, "uint", ["pointer", "uint8", "uint8", "uint16", "pointer"]],
    [create_P2pReq, "uint8", ["pointer", "pointer", "pointer", "uint"]],
    [create_LstReq, "uint8", ["pointer", "pointer"]],
    [create_P2pRdy, "uint8", ["pointer", "pointer"]],
    [pack_P2pHdr, "uint8", ["pointer", "pointer"]],
    [pack_Drw, "uint8", ["pointer", "uint16", "pointer"]],
    [pack_DrwAck, "uint8", ["pointer", "uint16", "pointer"]],
    [pack_P2pId, "uint32", ["pointer", "pointer"]],
    [pack_P2pReq4, "uint64", ["pointer", "pointer"]],
    [dbg_pack_ClntPkt, "uint32", ["uint32", "pointer", "pointer"]],
  ];

  replacements.forEach((x) => replace_func(...x));
  return replacements.map((x) => x[0].name.replace("dbg_", ""));
};
