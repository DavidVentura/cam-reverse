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
DataView.prototype.writeByteArray = function (arr) {
  for (let i = 0; i < (arr.byteLength || arr.length); i++) {
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
