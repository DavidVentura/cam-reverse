export const Commands = {
  Close: 0xf1f0,
  LanSearchExt: 0xf132,
  LanSearch: 0xf130,
  P2PAlive: 0xf1e0,
  P2PAliveAck: 0xf1e1,
  Hello: 0xf100,
  P2pRdy: 0xf142,
  P2pReq: 0xf120,
  LstReq: 0xf167,
  DrwAck: 0xf1d1,
  Drw: 0xf1d0,

  // From CSession_CtrlPkt_Proc, incomplete
  PunchTo: 0xf140,
  PunchPkt: 0xf141,
  HelloAck: 0xf101,
  RlyTo: 0xf102,
  DevLgnAck: 0xf111,
  P2PReqAck: 0xf121,
  ListenReqAck: 0xf169,
  RlyHelloAck: 0xf170, // always
  RlyHelloAck2: 0xf171, // if len >1??
};

// Record<keyof typeof Commands,
export const CommandsByValue = Object.keys(Commands).reduce((acc, cur) => {
  acc[Commands[cur]] = cur;
  return acc;
}, {});

export const ControlCommands = {
  ConnectUser: 0x2010,
  ConnectUserAck: 0x2011,
};
