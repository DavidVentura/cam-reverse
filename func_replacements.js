const pack_P2pHdr = (in_buf, out_buf) => {
  // shitty memcpy
  out_buf.writeByteArray(in_buf.readByteArray(4));
  // out_buf.writeU16(in_buf.readU16());
  // out_buf.add(2).writeU16(in_buf.add(2).readU16());
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
				   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56  BATC......L.EXLV
		00000010  53 00 00 00                                      S...

		out
				   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  f1 42 00 14 00 00 00 00 42 41 54 43 00 00 00 00  .B......BATC....
		00000010  00 09 4c fb 45 58 4c 56 53 00 00 00              ..L.EXLVS...
		retval 0x18
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

  console.log("new p2preq");
  /*
	  P2P req addr_fam 2 m_s_addr
           	       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
		00000000  02 00 00 00 c0 a8 01 64 00 00 00 00 00 00 00 00  .......d........
	 
	 at byte 4 is c0 a8 01 64 which is 192 168 1 100

	 in
			   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
	00000000  42 41 54 43 00 00 00 00 00 09 4c fb 45 58 4c 56  BATC......L.EXLV

	mine
			   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
	00000000  f1 20 00 24 00 00 00 00 42 41 54 43 00 00 00 00  . .$....BATC....
	00000010  00 09 4c fb 45 58 4c 56 53 00 00 00 00 00 00 00  ..L.EXLVS.......
	00000020  00 00 00 00 00 00 00 00                          ........

	original
			   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
	00000000  f1 20 00 24 00 00 00 00 42 41 54 43 00 00 00 00  . .$....BATC....
	00000010  00 09 4c fb 45 58 4c 56 53 00 00 00 00 02 00 00  ..L.EXLVS.......
	00000020  64 01 a8 c0 00 00 00 00                          d.......

	*/

  //let new_outbuf = Memory.alloc(0x2c);
  outbuf.writeU16(0x20f1);
  outbuf.add(2).writeU16(P2PREQ_SIZE << 8);
  outbuf.add(8).writeU64(inbuf.readU64());
  outbuf.add(16).writeU64(inbuf.add(8).readU64());
  outbuf.add(2 * 0xc).writeU32(inbuf.add(16).readU32());

  outbuf.add(2 * 0xe).writeByteArray(swap_endianness_u16(m_s_addr));
  outbuf.add(2 * 0xf).writeByteArray(swap_endianness_u16(m_s_addr.add(2)));

  outbuf.add(2 * 0x12).writeU64(0);
  outbuf.add(2 * 0x10).writeByteArray(swap_endianness_u32(m_s_addr.add(4))); // ip address

  //og_func(outbuf, inbuf, m_s_addr, addr_fam);
  //console.log("in");
  //console.log(inbuf.readByteArray(0x10));
  //console.log("mine");
  //console.log(new_outbuf.readByteArray(0x28));
  //console.log("original");
  //console.log(outbuf.readByteArray(0x28));

  return P2PREQ_SIZE + 4;
};
const dbg_create_P2pReq = (og_func) => {
  return create_P2pReq;
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
                           		 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     0123456789ABCDEF 00000000  f1 67 00 14 00 00 00 00 42 41 54 43 00 00 00 00
     .g......BATC.... 00000010  00 09 4c fb 45 58 4c 56 53 00 00 00 ..L.EXLVS...
        retval 0x18

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

export const replace_func = (stub, ret, args, pass_orig) => {
  const name_in_elf = stub.name.replace("dbg_", ""); // UGH  FIXME
  const symbol_addr = DebugSymbol.fromName(name_in_elf).address;
  if (symbol_addr == 0) {
    console.error(`Could not find ${name_in_elf}`);
    return;
  }

  const orig_func = new NativeFunction(symbol_addr, ret, args);

  let replacement_func;
  if (pass_orig) {
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
 [NOT REPLACED] create_Drw
 [NOT REPLACED] create_DrwAck
 [NOT REPLACED] create_P2pReq
 */
export const replaceFunctions = () => {
  const replacements = [
    [create_P2pAlive, "uchar", ["pointer"]],
    [create_P2pAliveAck, "uchar", ["pointer"]],
    [create_LanSearch, "uchar", ["pointer"]],
    [create_LanSearchExt, "uchar", ["pointer"]],
    [create_Hello, "uchar", ["pointer"]],
    [create_Close, "uchar", ["pointer"]],
    /*
    [
      dbg_create_P2pReq,
      "uchar",
      ["pointer", "pointer", "pointer", "uint"],
      true,
    ],
	*/
    [create_P2pReq, "uchar", ["pointer", "pointer", "pointer", "uint"]],
    [create_LstReq, "uchar", ["pointer", "pointer"]],
    [create_P2pRdy, "uchar", ["pointer", "pointer"]],
    [pack_P2pHdr, "uchar", ["pointer", "pointer"]],
  ];

  replacements.forEach((x) => replace_func(...x));
  return replacements.map((x) => x[0].name);
};
