// Create a minimal EXIF segment with orientation
export const createExifOrientation = (orientation: number) => {
  const tiffHeader = Buffer.from("49492A0008000000", "hex");
  const ifdEntry = Buffer.concat([
    Buffer.from("0100", "hex"), // Number of IFD entries
    Buffer.from("1201030001000000", "hex"), // Tag, Type, Count
    Buffer.from(orientation.toString(16).padStart(2, "0"), "hex"), // Orientation value
    Buffer.from("0000", "hex"), // No more IFDs
    Buffer.from("0000000000", "hex"), // padding??
  ]);

  const exifData = Buffer.concat([Buffer.from("457869660000", "hex"), tiffHeader, ifdEntry]);
  const segmentLength = Buffer.from([(exifData.length + 2) >> 8, (exifData.length + 2) & 0xff]);
  const exifHeader = Buffer.concat([Buffer.from("FFE1", "hex"), segmentLength]);

  return Buffer.concat([exifHeader, exifData]);
};

export const addExifToJpeg = (jpegData: Buffer, exifSegment: Buffer) => {
  // Check for existing EXIF (simplified check)
  if (jpegData.includes(Buffer.from("FFE1", "hex"))) {
    throw new Error("JPEG already contains EXIF segment");
  }

  const soiEnd = 2; // After FFD8
  const modifiedJpeg = Buffer.concat([jpegData.subarray(0, soiEnd), exifSegment, jpegData.subarray(soiEnd)]);
  return modifiedJpeg;
};
