DataView.prototype.add = function (offset) {
  return new DataView(this.buffer, offset);
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
  return this.setUint64(0, val);
};
DataView.prototype.readU8 = function () {
  return this.getUint8(0);
};
DataView.prototype.readU16 = function () {
  return this.getUint16(0);
};
DataView.prototype.readU32 = function () {
  return this.getUint32(0);
};
DataView.prototype.readU64 = function () {
  return this.getUint64(0);
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

const Memory = {
  alloc: (len: number) => new DataView(new ArrayBuffer(len + 1)),
  copy: (outbuf: DataView, inbuf: DataView, len: number) =>
    outbuf.writeByteArray(new Uint8Array(inbuf.readByteArray(len).buffer)),
};

declare global {
  interface DataView {
    add(offset: number): DataView;
    readByteArray(len: number): DataView;
    readU16(): undefined;
    readU32(): undefined;
    readU64(): undefined;
    readU8(): undefined;
    writeByteArray(arr: Uint8Array | number[]): undefined;
    writeU16(n: number): undefined;
    writeU32(n: number): undefined;
    writeU64(n: number): undefined;
    writeU8(n: number): undefined;
  }
}
export default global;
