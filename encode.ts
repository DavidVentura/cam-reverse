const KEY_TABLE = new Uint8Array([
  0x7c, 0x9c, 0xe8, 0x4a, 0x13, 0xde, 0xdc, 0xb2, 0x2f, 0x21, 0x23, 0xe4, 0x30, 0x7b, 0x3d, 0x8c, 0xbc, 0x0b, 0x27,
  0x0c, 0x3c, 0xf7, 0x9a, 0xe7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xef, 0xc1, 0x1f, 0xc4, 0xdb, 0xa1, 0xc2, 0xeb,
  0xd9, 0x01, 0xfa, 0xba, 0x3b, 0x05, 0xb8, 0x15, 0x87, 0x83, 0x28, 0x72, 0xd1, 0x8b, 0x5a, 0xd6, 0xda, 0x93, 0x58,
  0xfe, 0xaa, 0xcc, 0x6e, 0x1b, 0xf0, 0xa3, 0x88, 0xab, 0x43, 0xc0, 0x0d, 0xb5, 0x45, 0x38, 0x4f, 0x50, 0x22, 0x66,
  0x20, 0x7f, 0x07, 0x5b, 0x14, 0x98, 0x1d, 0x9b, 0xa7, 0x2a, 0xb9, 0xa8, 0xcb, 0xf1, 0xfc, 0x49, 0x47, 0x06, 0x3e,
  0xb1, 0x0e, 0x04, 0x3a, 0x94, 0x5e, 0xee, 0x54, 0x11, 0x34, 0xdd, 0x4d, 0xf9, 0xec, 0xc7, 0xc9, 0xe3, 0x78, 0x1a,
  0x6f, 0x70, 0x6b, 0xa4, 0xbd, 0xa9, 0x5d, 0xd5, 0xf8, 0xe5, 0xbb, 0x26, 0xaf, 0x42, 0x37, 0xd8, 0xe1, 0x02, 0x0a,
  0xae, 0x5f, 0x1c, 0xc5, 0x73, 0x09, 0x4e, 0x69, 0x24, 0x90, 0x6d, 0x12, 0xb3, 0x19, 0xad, 0x74, 0x8a, 0x29, 0x40,
  0xf5, 0x2d, 0xbe, 0xa5, 0x59, 0xe0, 0xf4, 0x79, 0xd2, 0x4b, 0xce, 0x89, 0x82, 0x48, 0x84, 0x25, 0xc6, 0x91, 0x2b,
  0xa2, 0xfb, 0x8f, 0xe9, 0xa6, 0xb0, 0x9e, 0x3f, 0x65, 0xf6, 0x03, 0x31, 0x2e, 0xac, 0x0f, 0x95, 0x2c, 0x5c, 0xed,
  0x39, 0xb7, 0x33, 0x6c, 0x56, 0x7e, 0xb4, 0xa0, 0xfd, 0x7a, 0x81, 0x53, 0x51, 0x86, 0x8d, 0x9f, 0x77, 0xff, 0x6a,
  0x80, 0xdf, 0xe2, 0xbf, 0x10, 0xd7, 0x75, 0x64, 0x57, 0x76, 0xf3, 0x55, 0xcd, 0xd0, 0xc8, 0x18, 0xe6, 0x36, 0x41,
  0x62, 0xcf, 0x99, 0xf2, 0x32, 0x4c, 0x67, 0x60, 0x61, 0x92, 0xca, 0xd3, 0xea, 0x63, 0x7d, 0x16, 0xb6, 0x8e, 0xd4,
  0x68, 0x35, 0xc3, 0x52, 0x9d, 0x46, 0x44, 0x1e, 0x17,
]);

const ENC_KEY = new Uint8Array([0x69, 0x97, 0xcc, 0x19]);

export const decode = (dv: DataView): DataView => {
  let prevByte = 0;
  let buf = new Uint8Array(dv.byteLength);
  for (let i = 0; i < dv.byteLength; i++) {
    const index = (ENC_KEY[prevByte & 0x03] + prevByte) & 0xff;
    const origByte = dv.getUint8(i);
    buf[i] = origByte ^ KEY_TABLE[index];
    prevByte = origByte;
  }
  return new DataView(buf.buffer);
};

export const encode = (dv: DataView): DataView => {
  let prevByte = 0;
  let buf = new Uint8Array(dv.byteLength);
  for (let i = 0; i < dv.byteLength; i++) {
    const index = (ENC_KEY[prevByte & 0x03] + prevByte) & 0xff;
    buf[i] = dv.getUint8(i) ^ KEY_TABLE[index];
    prevByte = buf[i];
  }
  return new DataView(buf.buffer);
};