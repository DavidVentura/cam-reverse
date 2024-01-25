import "./shim.ts";
import { u16_swap } from "./utils.js";
import { hexdump } from "./hexdump.js";
import { XqBytesEnc } from "./func_replacements.js";

const str2byte = (s: string): number[] => {
  return Array.from(s).map((_, i) => s.charCodeAt(i));
};

export const SendUsrChk = (username: string, password: string): DataView => {
  // type is char account[0x20]; char password[0x80];
  let buf = new Uint8Array(0x20 + 0x80);
  buf.fill(0);
  let cmd_payload = new DataView(buf.buffer);
  cmd_payload.writeByteArray(str2byte(username));
  cmd_payload.add(0x20).writeByteArray(str2byte(password));

  const dest = u16_swap(0xff);
  const cmd = u16_swap(0x1020);
  const len = u16_swap(0x20 + 0x80 + 4);
  let cmdHeader = new DataView(new Uint8Array(8).buffer);
  cmdHeader.writeU16(u16_swap(0xa11));
  cmdHeader.add(2).writeU16(cmd);
  cmdHeader.add(4).writeU16(len);
  cmdHeader.add(6).writeU16(dest);

  let ret = new DataView(new Uint8Array(12 + 0x20 + 0x80).buffer);
  ret.writeByteArray(new Uint8Array(cmdHeader.buffer));
  XqBytesEnc(cmd_payload, 0x20 + 0x80, 4);
  ret.add(12).writeByteArray(new Uint8Array(cmd_payload.buffer));

  // need to encapsulate this into create_Drw(outbuf, 0xd1, param4?, svar1?, copy_len, inbuf);
  // seems like param4/svar1 are overflowing == maybe '0xa' and '0x2010'??
  let retret = new DataView(new Uint8Array(8 + 12 + 0x20 + 0x80).buffer);
  retret.writeU16(0xf1d0);
  retret.add(2).writeU16(8 + 12 + 0x20 + 0x80 - 4);
  retret.add(4).writeU16(u16_swap(0xd1));
  retret.add(6).writeU16(0x0); // chan? hardcoded
  retret.add(8).writeByteArray(new Uint8Array(ret.buffer));
  return retret;
};

//console.log(hexdump(SendUsrChk("admin", "admin").buffer, { ansi: true }));
