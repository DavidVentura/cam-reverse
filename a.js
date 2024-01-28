import beamcoder from "beamcoder";
import EventEmitter from "node:events";
import fs from "node:fs";
import Stream from "node:stream";

const sleep = (waitTimeInMs) => new Promise((resolve) => setTimeout(resolve, waitTimeInMs));
let c = 10;
const readableStream = new Stream.Readable({
  async read() {
    await sleep(10);
    if (c < 810) {
      const data = fs.readFileSync(
        `captures/${parseInt(c / 10)
          .toString()
          .padStart(4, "0")}.jpg`,
      );
      this.push(data);
    } else {
      this.push(null);
    }
    c++;
  },
});

const ee = new EventEmitter();

let demuxers = beamcoder.demuxers();
// console.log(demuxers);

ee.on("inputFrame", (f) => {});

const makeEncoder = (frame, frameRate) => {
  return beamcoder.encoder({
    name: "libx264",
    width: frame.width,
    height: frame.height,
    bit_rate: 400000,
    // qmin: 22,
    time_base: [1, frameRate],
    framerate: [frameRate, 1],
    pix_fmt: "yuv420p",
    preset: "faster",
    gop_size: 10,
    max_b_frames: 1,
  });
};
async function imageToVideo(imagePath, duration, frameRate = 20) {
  const muxTimeBase = 90000;
  let demuxerStream = beamcoder.demuxerStream({ highwaterMark: 65536 });

  console.log("piping");
  readableStream.pipe(demuxerStream);
  console.log("creating demuxer");
  // Create a demuxer for the JPEG image
  // let demuxer = await beamcoder.demuxer(imagePath);
  let demuxer = await demuxerStream.demuxer({ name: "jpeg_pipe" });
  // Create a decoder for the image
  let decoder = beamcoder.decoder({ demuxer: demuxer, name: "mjpeg" });

  // Read the image packet
  console.log("wait demuxer");
  // let packet = await demuxer.read();
  let encoder = null;
  let muxer = null;
  let vstr = null;
  let i = 0;
  while (true) {
    let packet = await demuxer.read();
    if (packet == null) break;
    let frames = await decoder.decode(packet);
    let frame = frames.frames[0];
    if (encoder == null) {
      encoder = makeEncoder(frame, frameRate);
      // Create an H.264 encoder
      // https://stackoverflow.com/a/13646293/3530257
      // > the codec unit of measurement is commonly set to the interval between
      // each frame and the next, > so that frame times are successive integers.

      // TODO a muxer per client?
      let stream = beamcoder.muxerStream({});
      stream.pipe(fs.createWriteStream("test.mp4"));
      //  Create a muxer for the output video
      muxer = stream.muxer({ format_name: "mp4" });

      // console.log(demuxer.streams[0].codecpar.extradata); // null
      vstr = muxer.newStream({
        name: "h264",
        time_base: [1, muxTimeBase], // frameRate],
        interleaved: true,
      });

      // the Object.assign is structural (!!)
      Object.assign(vstr.codecpar, {
        width: encoder.width,
        height: encoder.height,
        format: encoder.pix_fmt,
      });

      await muxer.openIO();
      // adding "empty_moov" crashes mpv/ffmpeg
      // await muxer.initOutput({ movflags:
      // "frag_keyframe+default_base_moof+faststart" });
      await muxer.initOutput({ movflags: "frag_keyframe" });
      console.log("inited");
      // Add a video stream to the muxer
      await muxer.writeHeader();
      console.log("header written");
    }
    if (frame) {
      frame.pts = i; // << the successive integers
      frame.dts = i; // << the successive integers
      let encodedPackets = await encoder.encode(frame);

      // Write the encoded packets to the output file
      for (let packet of encodedPackets.packets) {
        packet.duration = 1;
        packet.stream_index = vstr.index;
        packet.pts = (packet.pts * muxTimeBase) / frameRate;
        packet.dts = (packet.dts * muxTimeBase) / frameRate;
        // packet.pts = i;
        await muxer.writeFrame(packet);
        // outFile.write(packet.data);
      }
    }

    i++;
  }
  // Finalize the encoder and muxer
  let encodedPackets = await encoder.flush();
  // after flushing the encoder, we may hve some more packets

  // Write the encoded packets to the output file
  for (let packet of encodedPackets.packets) {
    packet.duration = 1;
    packet.stream_index = vstr.index;
    packet.pts = (packet.pts * muxTimeBase) / frameRate;
    packet.dts = (packet.dts * muxTimeBase) / frameRate;
    await muxer.writeFrame(packet);
  }
  await muxer.writeTrailer();
}

// Usage example
imageToVideo("captures/0010.jpg", 20)
  .then(() => {
    console.log("Video created successfully");
  })
  .catch(console.error);
