import "./shim.ts";

const str2byte = (s: string): number[] => {
  return Array.from(s).map((_, i) => s.charCodeAt(i));
};

const SendUsrChk = (username: string, password: string): DataView => {
  // type is char account[0x20]; char password[0x80];
  let buf = new Uint8Array(0x20 + 0x80);
  buf.fill(0);
  let cmd_payload = new DataView(buf.buffer);
  cmd_payload.writeByteArray(str2byte(username));
  cmd_payload.add(0x20).writeByteArray(str2byte(password));
  return cmd_payload;
};

console.log(SendUsrChk("admin", "admin"));
