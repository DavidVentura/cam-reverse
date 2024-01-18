const create_LanSearch = (buf) => {
  // buf is u16*
  buf.writeU16(0x30f1);
  buf.add(2).writeU16(0x0);
  return 4; // 2 x u16 entries = 4bytes
};

const create_P2pAliveAck = (buf) => {
  // buf is u16*
  buf.writeU16(0xe1f1);
  buf.add(2).writeU16(0x0);
  return 4; // 2 x u16 entries = 4bytes
};
const create_P2pAlive = (buf) => {
  // buf is u16*
  buf.writeU16(0xe0f1);
  buf.add(2).writeU16(0x0);
  return 4; // 2 x u16 entries = 4bytes
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

export const replaceFunctions = () => {
  const replacements = [
    [create_P2pAlive, "uchar", ["pointer"]],
    [create_P2pAliveAck, "uchar", ["pointer"]],
    [create_LanSearch, "uchar", ["pointer"]],
  ];

  replacements.forEach((x) => replace_func(...x));
  return replacements.map((x) => x[0].name);
};
