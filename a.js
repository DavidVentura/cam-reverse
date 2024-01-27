import fs from "node:fs";
import beamcoder from "beamcoder";

async function imageToVideo(imagePath, duration, frameRate = 30) {
  // Create a demuxer for the JPEG image
  let demuxer = await beamcoder.demuxer(imagePath);

  // Read the image packet
  let packet = await demuxer.read();

  // Create a decoder for the image
  let decoder = beamcoder.decoder({ demuxer: demuxer, name: "mjpeg" });

  // Decode the image to get the frame
  let frames = await decoder.decode(packet);
  // decoder.flush();
  //console.log("frames", frames);
  let frame = frames.frames[0];
  //console.log("frame", frame.width, frame.height);

  // Create an H.264 encoder
  let encoder = beamcoder.encoder({
    name: "libx264",
    width: frame.width,
    height: frame.height,
    bit_rate: 400000,
    //qmin: 22,
    time_base: [1, frameRate],
    framerate: [frameRate, 1],
    pix_fmt: "yuv420p",
    preset: "faster",
    gop_size: 10,
    max_b_frames: 1,
  });

  let stream = beamcoder.muxerStream({});
  stream.pipe(fs.createWriteStream("test.mp4"));
  //  Create a muxer for the output video
  let muxer = stream.muxer({ format_name: "mp4" });

  //console.log(demuxer.streams[0].codecpar.extradata); // null
  let vstr = muxer.newStream({
    name: "h264",
    time_base: [1, 90000], //frameRate],
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
  await muxer.initOutput({ movflags: "frag_keyframe+default_base_moof+faststart" });
  console.log("inited");
  // Add a video stream to the muxer
  await muxer.writeHeader();
  console.log("header written");
  // Number of frames to encode
  let totalFrames = duration * frameRate;

  console.log("making frames", totalFrames);
  for (let i = 0; i < totalFrames; i++) {
    // Encode the frame
    frame.pts = i;
    let encodedPackets = await encoder.encode(frame);
    // console.log(encodedPackets);

    // Write the encoded packets to the output file
    for (let packet of encodedPackets.packets) {
      packet.duration = 1;
      packet.stream_index = vstr.index;
      packet.pts = (packet.pts * 90000) / (frameRate * 1);
      packet.dts = (packet.dts * 90000) / (frameRate * 1);
      //packet.pts = i;
      await muxer.writeFrame(packet);
      // outFile.write(packet.data);
    }
  }

  // Finalize the encoder and muxer
  let encodedPackets = await encoder.flush();
  // after flushing the encoder, we may hve some more packets

  // Write the encoded packets to the output file
  for (let packet of encodedPackets.packets) {
    packet.duration = 1;
    packet.stream_index = vstr.index;
    packet.pts = (packet.pts * 90000) / (frameRate * 1);
    packet.dts = (packet.dts * 90000) / (frameRate * 1);
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
