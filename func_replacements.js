const pack_P2pHdr = (in_buf, out_buf) => {
  // shitty memcpy
  out_buf.writeByteArray(in_buf.readByteArray(4));
  //out_buf.writeU16(in_buf.readU16());
  //out_buf.add(2).writeU16(in_buf.add(2).readU16());
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
  buf.writeU16(0xf1);
  buf.add(2).writeU16(0x0);
};

export const replace_func = (stub, ret, args) => {
  const name_in_elf = stub.name;
  const symbol_addr = DebugSymbol.fromName(name_in_elf).address;
  if (symbol_addr == 0) {
    console.error(`Could not find ${name_in_elf}`);
    return;
  }
  console.log(
    `Replacing ${name_in_elf}, signature "${ret} ${name_in_elf}(${args})"`,
  );
  Interceptor.replace(symbol_addr, new NativeCallback(stub, ret, args));
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
 * 	RSLgnEx, RlyReq4, RlyPortAck, RlyPortExAck, RlyReqEx, Drw, HelloToAck, DrwAck, DevLgn4, LanSearchExtAck, P2pReq4, RSLGn
 */
export const replaceFunctions = () => {
  const replacements = [
    [create_P2pAlive, "uchar", ["pointer"]],
    [create_P2pAliveAck, "uchar", ["pointer"]],
    [create_LanSearch, "uchar", ["pointer"]],
    [create_Hello, "uchar", ["pointer"]],
    [pack_P2pHdr, "uchar", ["pointer", "pointer"]],
  ];

  replacements.forEach((x) => replace_func(...x));
  return replacements.map((x) => x[0].name);
};
