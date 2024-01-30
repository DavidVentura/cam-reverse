DataView.prototype.add = function (offset) {
  return new DataView(this.buffer, offset + this.byteOffset);
};
DataView.prototype.writeU8 = function (val) {
  return this.setUint8(0, val);
};
DataView.prototype.writeU16 = function (val) {
  return this.setUint16(0, val);
};
DataView.prototype.writeU32 = function (val) {
  return this.setUint32(0, val);
};
DataView.prototype.writeU64 = function (val) {
  return this.setBigUint64(0, val);
};
DataView.prototype.readU8 = function () {
  return this.getUint8(0);
};
DataView.prototype.readU16 = function () {
  return this.getUint16(0);
};
DataView.prototype.readU16LE = function () {
  return this.getUint16(0, true);
};
DataView.prototype.readU32 = function () {
  return this.getUint32(0);
};
DataView.prototype.readU32LE = function () {
  return this.getUint32(0, true);
};
DataView.prototype.readU64 = function () {
  return this.getBigUint64(0);
};
const isU8Array = (x: Uint8Array | number[]): x is Uint8Array => {
  return x instanceof Uint8Array;
};

DataView.prototype.writeByteArray = function (arr) {
  const len = isU8Array(arr) ? arr.byteLength : arr.length;
  for (let i = 0; i < len; i++) {
    this.setUint8(i, arr[i]);
  }
};
DataView.prototype.readByteArray = function (len) {
  let ret = new DataView(new ArrayBuffer(len));
  for (let i = 0; i < len; i++) {
    ret.setUint8(i, this.getUint8(i));
  }
  return ret;
};
DataView.prototype.readString = function (len) {
  const ba = this.readByteArray(len);
  const s = String.fromCharCode.apply(null, new Uint8Array(ba.buffer));
  const nullByte = s.indexOf("\0");
  if (nullByte !== -1) return s.substring(0, nullByte);
  return s;
};

declare global {
  interface DataView {
    add(offset: number): DataView;
    readByteArray(len: number): DataView;
    readString(len: number): string;
    readU16(): number;
    readU16LE(): number;
    readU32(): number;
    readU32LE(): number;
    readU64(): bigint;
    readU8(): number;
    writeByteArray(arr: Uint8Array | number[]): void;
    writeU16(n: number): void;
    writeU32(n: number): void;
    writeU64(n: bigint): void;
    writeU8(n: number): void;
  }
}
export default global;
