import { createSocket, RemoteInfo } from "node:dgram";
export const mockServer = (onMessage: (msg: DataView) => Uint8Array[]) => {
  const sock = createSocket("udp4");
  const SEND_PORT = 32108;
  sock.bind(SEND_PORT);
  sock.on("message", (msg, rinfo: RemoteInfo) => {
    const dv = new DataView(new Uint8Array(msg).buffer);
    onMessage(dv).forEach((out) => {
      sock.send(out, rinfo.port, rinfo.address);
    });
  });

  return sock;
};
