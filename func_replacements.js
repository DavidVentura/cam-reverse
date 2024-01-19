const pack_P2pHdr = (in_buf, out_buf) => {
  // shitty memcpy
  out_buf.writeByteArray(in_buf.readByteArray(4));
  return 4;
};

const create_Close = (buf) => {
  buf.writeByteArray([0xf1, 0xf0, 0x00, 0x00]);
  return 4;
};

const create_LanSearchExt = (buf) => {
  buf.writeByteArray([0xf1, 0x32, 0x00, 0x00]);
  return 4;
};

const create_LanSearch = (buf) => {
  buf.writeByteArray([0xf1, 0x30, 0x00, 0x00]);
  return 4;
};

const create_P2pAliveAck = (buf) => {
  buf.writeByteArray([0xf1, 0xe1, 0x00, 0x00]);
  return 4;
};
const create_P2pAlive = (buf) => {
  buf.writeByteArray([0xf1, 0xe0, 0x00, 0x00]);
  return 4;
};

const create_Hello = (buf) => {
  buf.writeByteArray([0xf1, 0x0, 0x0, 0x0]);
  return 4;
};

const create_P2pRdy = (outbuf, inbuf) => {
  // TODO: this is literlly the same as create_LstReq, just different command
  /*
         * in
                                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E
     F  0123456789ABCDEF 00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c
     56  BATC......L.EXLV 00000010  53 00 00 00 S...

                out
                                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E
     F  0123456789ABCDEF 00000000  f1 42 00 14 00 00 00 00 42 41 54 43 00 00 00
     00  .B......BATC.... 00000010  00 09 4c fb 45 58 4c 56 53 00 00 00
     ..L.EXLVS... retval 0x18
        */
  const P2PRDY_SIZE = 0x14;
  outbuf.writeU16(0x42f1);
  outbuf.add(2).writeU16(P2PRDY_SIZE << 8);
  outbuf.add(8).writeU64(inbuf.readU64());
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  outbuf.add(2 * 0xc).writeU32(inbuf.add(16).readU32());
  return P2PRDY_SIZE + 4;
};

const create_P2pReq = (outbuf, inbuf, m_s_addr, addr_fam) => {
  const P2PREQ_SIZE = 0x24;

  /*
          P2P req addr_fam 2 m_s_addr
                       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  02 00 00 00 c0 a8 01 64 00 00 00 00 00 00 00 00
     .......d........

         at byte 4 is c0 a8 01 64 which is 192 168 1 100

         in
                           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56
     BATC......L.EXLV

        mine
                           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  f1 20 00 24 00 00 00 00 42 41 54 43 00 00 00 00
     . .$....BATC.... 00000010  00 09 4c fb 45 58 4c 56 53 00 00 00 00 00 00 00
     ..L.EXLVS....... 00000020  00 00 00 00 00 00 00 00 ........

        original
                           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  f1 20 00 24 00 00 00 00 42 41 54 43 00 00 00 00
     . .$....BATC.... 00000010  00 09 4c fb 45 58 4c 56 53 00 00 00 00 02 00 00
     ..L.EXLVS....... 00000020  64 01 a8 c0 00 00 00 00 d.......

        */

  // let new_outbuf = Memory.alloc(0x2c);
  outbuf.writeU16(0x20f1);
  outbuf.add(2).writeU16(P2PREQ_SIZE << 8);
  outbuf.add(8).writeU64(inbuf.readU64());
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  outbuf.add(2 * 0xc).writeU32(inbuf.add(16).readU32());

  outbuf.add(2 * 0xe).writeByteArray(swap_endianness_u16(m_s_addr));
  outbuf.add(2 * 0xf).writeByteArray(swap_endianness_u16(m_s_addr.add(2)));

  outbuf.add(2 * 0x12).writeU64(0);
  outbuf.add(2 * 0x10).writeByteArray(swap_endianness_u32(m_s_addr.add(4))); // ip address

  // og_func(outbuf, inbuf, m_s_addr, addr_fam);
  // console.log("in");
  // console.log(inbuf.readByteArray(0x10));
  // console.log("mine");
  // console.log(new_outbuf.readByteArray(0x28));
  // console.log("original");
  // console.log(outbuf.readByteArray(0x28));

  return P2PREQ_SIZE + 4;
};

const swap_endianness_u16 = (ptr) => {
  const bytes = ptr.readU16();
  const swapped = [(bytes & 0xff00) >> 8, bytes & 0x00ff];
  return swapped;
};
const swap_endianness_u32 = (ptr) => {
  const bytes = ptr.readU32();
  const swapped = [
    (bytes & 0xff000000) >> 24,
    (bytes & 0x00ff0000) >> 16,
    (bytes & 0x0000ff00) >> 8,
    bytes & 0x000000ff,
  ];
  return swapped;
};
const create_LstReq = (outbuf, inbuf) => {
  /* original
        in
                                 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56
     BATC......L.EXLV 00000010  53 00 00 00 00 00 00 00 00 00 00 00 S...........

        out
                                         0  1  2  3  4  5  6  7  8  9  A  B  C
     D  E  F 0123456789ABCDEF 00000000  f1 67 00 14 00 00 00 00 42 41 54 43 00
     00 00 00 .g......BATC.... 00000010  00 09 4c fb 45 58 4c 56 53 00 00 00
     ..L.EXLVS... retval 0x18

        */
  const LISTREQ_SIZE = 0x14;
  outbuf.writeU16(0x67f1);
  outbuf.add(2).writeU16(LISTREQ_SIZE << 8);

  // 4 * sizeof(short)
  outbuf.add(8).writeU64(inbuf.readU64());
  // 8 * sizeof(short)
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  // 8 * sizeof(short)
  outbuf.add(2 * 0xc).writeU32(inbuf.add(0x10).readU32());

  /*
  let new_outbuf = Memory.alloc(0x1c);
  og_func(new_outbuf, inbuf);
  console.log("mine");
  console.log(outbuf.readByteArray(0x1c));
  console.log("original");
  console.log(new_outbuf.readByteArray(0x1c));
  */

  return LISTREQ_SIZE + 4; // this is actually wrong (and unused) in the code -- it is 0x1c
};

const dbg_create_DrwAck = (og_func) => {
  const create_DrwAck = (outbuf, idk_param2, idk_param3, half_len, inbuf) => {
    console.log(`2: ${idk_param2} 3: ${idk_param3}, halflen: ${half_len}`);
    console.log("inbuf");
    const copyLen = half_len * 2;
    //console.log(inbuf.readByteArray(copyLen));

    //console.log("outbuf BEFORE");
    //console.log(outbuf.readByteArray(copyLen + 12));

    //const retval = og_func(outbuf, idk_param2, idk_param3, half_len, inbuf);
    //console.log("outbuf");
    //console.log(outbuf.readByteArray(copyLen + 12));

    //const new_outbuf = Memory.alloc(copyLen + 12);
    outbuf.writeU16(0xd1f1);
    outbuf.add(2).writeU16(u16_swap(copyLen + 4));
    outbuf.add(8).writeU8(idk_param2);
    outbuf.add(9).writeU8(idk_param3);
    outbuf.add(10).writeU16(u16_swap(half_len));
    outbuf.add(12).writeByteArray(inbuf.readByteArray(copyLen));

    //console.log("my outbuf");
    //console.log(new_outbuf.readByteArray(copyLen + 12));
    return half_len * 2 + 8; // this is wrong in the code as well - should be +12
  };
  return create_DrwAck;
};

const u16_swap = (x) => ((x & 0xff00) >> 8) | ((x & 0x00ff) << 8);
const dbg_create_Drw = (og_func) => {
  const create_Drw = (
    outbuf,
    idk_param2,
    idk_param3,
    idk_param4,
    copy_len,
    inbuf,
  ) => {
    /// idk_param4 goes up by 0x100 per call

    //console.log(
    //  `2: ${idk_param2.toString(16)} 3: ${idk_param3.toString(16)} 4: ${idk_param4.toString(16)} copylen: ${copy_len}`,
    //);
    /*
     * 2: ffffffd1 3: 0 4: 3100 copylen: 44
	In buffer
			   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
	00000000  11 0a 31 10 24 00 00 00 75 39 4c 74 01 01 01 01  ..1.$...u9Lt....
	00000010  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
	00000020  01 01 01 01 01 01 01 01 01 01 01 00              ............
	OG retval 52
	OG out buffer
			   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
	00000000  f1 d0 00 30 00 00 00 00 d1 00 00 31 11 0a 31 10  ...0.......1..1.
	00000010  24 00 00 00 75 39 4c 74 01 01 01 01 01 01 01 01  $...u9Lt........
	00000020  01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01  ................
	00000030  01 01 01 01
	*/

    const copy_len_swapped = u16_swap(copy_len + 4);
    outbuf.writeU16(0xd0f1);
    outbuf.add(2).writeU16(copy_len_swapped);
    outbuf.add(8).writeU8(0xd1);
    outbuf.add(10).writeU16(idk_param4);
    outbuf.add(12).writeByteArray(inbuf.readByteArray(copy_len));

    return copy_len + 8;
  };
  return create_Drw;
};
const debugInOut = (inbuf, outbuf, og_func, insize, outsize) => {
  console.log("In buffer");
  console.log(inbuf.readByteArray(insize));

  let og_outbuf = Memory.alloc(outsize);
  console.log("OG retval", og_func(inbuf, og_outbuf));
  console.log("OG out buffer");
  console.log(og_outbuf.readByteArray(outsize));

  console.log("My out buffer");
  console.log(outbuf.readByteArray(outsize));
};

const pack_Drw = (inbuf, m_pkt_size, outbuf) => {
  // a shitty memcpy?
  const DRW_HDR_SIZE = 0x4;

  outbuf.writeU8(inbuf.readU8());
  outbuf.add(1).writeU8(inbuf.add(1).readU8());
  outbuf.add(2).writeU16(inbuf.add(2).readU16());
  outbuf
    .add(4)
    .writeByteArray(inbuf.add(4).readByteArray(m_pkt_size - DRW_HDR_SIZE));

  return m_pkt_size;
};
// FIXME literally identical
const pack_DrwAck = (inbuf, m_pkt_size, outbuf) => {
  // a shitty memcpy?
  const DRW_ACK_HDR_SIZE = 0x4;

  outbuf.writeU8(inbuf.readU8());
  outbuf.add(1).writeU8(inbuf.add(1).readU8());
  outbuf.add(2).writeU16(inbuf.add(2).readU16());
  outbuf
    .add(4)
    .writeByteArray(inbuf.add(4).readByteArray(m_pkt_size - DRW_ACK_HDR_SIZE));

  return m_pkt_size;
};

const pack_P2pId = (inbuf, outbuf) => {
  // TODO not verified correct but works ?
  outbuf.writeU64(inbuf.readU64());
  outbuf.add(8).writeU32(inbuf.add(8).readU32());
  outbuf.add(0xc).writeU64(inbuf.add(0xc).readU32());

  return 0x14;
};

const pack_P2pReq4 = (inbuf, outbuf) => {
  // a shitty memcpy?
  /*
	   In buffer
				   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56  BATC......L.EXLV
		00000010  53 00 00 00 00 02 00 00 64 01 a8 c0 00 00 00 00  S.......d.......
		OG retval 36
		OG out buffer
				   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56  BATC......L.EXLV
		00000010  53 00 00 00 00 02 00 00 64 01 a8 c0 00 00 00 00  S.......d.......
		My out buffer
				   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

	*/
  Memory.copy(outbuf, inbuf, 0x24);
  //debugInOut(inbuf, outbuf, og_func, 0x20, 0x20); // probably 0x18
  return 0x24;
};
export const replace_func = (stub, ret, args) => {
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

  console.log(
    `Replacing ${name_in_elf}, signature "${ret} ${name_in_elf}(${args})"`,
  );

  Interceptor.replace(
    symbol_addr,
    new NativeCallback(replacement_func, ret, args),
  );
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

/* pack_ClntPkt =
 * pack_P2pHdr
 * pack_
 * 	RSLgnEx, RlyReq4, RlyPortAck, RlyPortExAck, RlyReqEx, Drw, HelloToAck,
 * DrwAck, DevLgn4, LanSearchExtAck, P2pReq4, RSLGn
 */
/*
 hard
 [NOT REPLACED] pack_ClntPkt
 */
export const replaceFunctions = () => {
  const replacements = [
    [create_P2pAlive, "uint8", ["pointer"]],
    [create_P2pAliveAck, "uint8", ["pointer"]],
    [create_LanSearch, "uint8", ["pointer"]],
    [create_LanSearchExt, "uint8", ["pointer"]],
    [create_Hello, "uint8", ["pointer"]],
    [create_Close, "uint8", ["pointer"]],
    [
      dbg_create_Drw,
      "uint",
      ["pointer", "uint64", "uint8", "uint16", "uint32", "pointer"],
    ],
    [
      dbg_create_DrwAck,
      "uint",
      ["pointer", "uint8", "uint8", "uint16", "pointer"],
    ],
    [create_P2pReq, "uint8", ["pointer", "pointer", "pointer", "uint"]],
    [create_LstReq, "uint8", ["pointer", "pointer"]],
    [create_P2pRdy, "uint8", ["pointer", "pointer"]],
    [pack_P2pHdr, "uint8", ["pointer", "pointer"]],
    [pack_Drw, "uint8", ["pointer", "uint16", "pointer"]],
    [pack_DrwAck, "uint8", ["pointer", "uint16", "pointer"]],
    [pack_P2pId, "uint32", ["pointer", "pointer"]],
    [pack_P2pReq4, "uint64", ["pointer", "pointer"]],
  ];

  replacements.forEach((x) => replace_func(...x));
  return replacements.map((x) => x[0].name.replace("dbg_", ""));
};
