import { replaceFunctions, Commands, CommandsByValue, u16_swap } from "./func_replacements.js";
import { placeholderTypes, sprintf } from "./utils.js";

const hook_fn = (name_in_elf, enter, leave) => {
  var symbol_addr = DebugSymbol.fromName(name_in_elf).address;
  console.log(`${name_in_elf} addr is: ${symbol_addr}, this is ${this}`);
  Interceptor.attach(symbol_addr, {
    onEnter: enter,
    onLeave: leave,
  });
  console.log(`Hooked ${name_in_elf}`);
};

function hook_export_fn(name_in_elf, enter, leave) {
  var symbol_addr = Module.findExportByName("libvdp.so", name_in_elf);
  console.log(`${name_in_elf} addr is: ${symbol_addr}`);
  Interceptor.attach(symbol_addr, {
    onEnter: enter,
    onLeave: leave,
  });
  console.log(`Hooked ${name_in_elf}`);
}

const hook_p2p_read = () => {
  var mangled_sym = "_Z8p2p_readPiihPci";
  hook_export_fn(
    mangled_sym,
    (args) => {
      //    console.log(hexdump(
      //        args[0], {offset : 0, length : 0x200, header : true, ansi :
      //        false}));

      let m_type = args[1];
      let m_unk3 = args[2];

      let m_size = args[4].toInt32();
      console.log(m_type, m_unk3, m_size);
    },
    () => {},
  );
};

const hook___android_log_print = () => {
  const sym = "__android_log_print";
  hook_fn(
    sym,
    (args) => {
      // let _prio = args[0].toInt32();
      let _tag = args[1].readCString();
      let fmt = args[2].readCString();
      const types = placeholderTypes(fmt); // ['s', 'd', ..]`
      // console.log(fmt, types); // debug if crashes due to missing placeholder

      let o = {
        s: (x) => x.readCString(),
        d: (x) => x.toInt32(),
        u: (x) => x.toInt32(),
        z: (x) => x.toInt32(), // FIXME
        l: (x) => x.toInt32(), // FIXME
        x: (x) => x.toInt32().toString(16),
        f: (x) => x.toFloat(),
      };

      const values = types.map((t, idx) => o[t](args[idx + 3]));
      const newStr = sprintf(fmt, values);
      console.log(_tag, newStr);
    },
    () => {},
  );
};

const hook_udpsend = () => {
  hook_fn(
    "XQ_UdpPktSend",
    (args) => {
      const data = args[0].readByteArray(args[1].toInt32());
      const cmd = u16_swap(args[0].readU16());
      const name = CommandsByValue[cmd];
      console.log(`UDP PKT SEND ${name} (0x${cmd.toString(16)})`);
      console.log(data);
    },
    (retval) => {},
  );

  let o = {};
  hook_fn(
    "XqSckRecvfrom", //"XQ_UdpPktRecv",
    (args) => {
      o.buf = args[1];
      o.len = args[2].toInt32();
    },
    (retval) => {
      const data = o.buf.readByteArray(retval.toInt32());
      const cmd = u16_swap(o.buf.readU16());
      const name = CommandsByValue[cmd];
      console.log(`UDP PKT RECV, cmd=${name}, 0x${cmd.toString(16)}, ret=${retval}`);
      console.log(data);
      if (cmd == Commands.Drw) {
      }
    },
  );

  let s = {};
  hook_fn(
    "PktSeq_seqGet",
    (args) => {
      s.buf = args[1];
    },
    (retval) => {
      const data = s.buf.readByteArray(retval.toInt32());
      console.log(`PktSeq GET ret=${retval}`);
      console.log(data);
    },
  );

  let e = {};
  hook_fn(
    "XqBytesEnc",
    (args) => {
      s.buf_ptr = args[0];
      s.m_buflen = args[1].toInt32();
      s.param3 = args[2].toInt32();
      s.buf_in = s.buf_ptr.readByteArray(s.m_buflen);
    },
    (retval) => {
      const bufout = s.buf_ptr.readByteArray(s.m_buflen);
      console.log(`XqBytesEnc buflen: ${s.m_buflen}, param3: ${s.param3}, buf_in:`);
      console.log(s.buf_in);
      console.log(`bufout`);
      console.log(bufout);
    },
  );

  let d = {};
  hook_fn(
    "XqBytesDec",
    (args) => {
      s.buf_ptr = args[0];
      s.m_buflen = args[1].toInt32();
      s.param3 = args[2].toInt32();
      s.buf_in = s.buf_ptr.readByteArray(s.m_buflen);
    },
    (retval) => {
      const bufout = s.buf_ptr.readByteArray(s.m_buflen);
      console.log(`XqBytesDec buflen: ${s.m_buflen}, param3: ${s.param3}, buf_in:`);
      console.log(s.buf_in);
      console.log(`bufout`);
      console.log(bufout);
    },
  );
};

const hook_in_out_buf = (sym, insize, outsize) => {
  let obj = {};
  hook_fn(
    sym,
    (args) => {
      console.log(`onEnter ${sym} ${this}`);
      obj.outbuf = args[0];
      obj.inbuf = args[1];
    },
    (retval) => {
      console.log(`${sym} done, dumping`);
      console.log("in");
      console.log(obj.inbuf.readByteArray(insize));
      console.log("out");
      console.log(obj.outbuf.readByteArray(outsize));
      console.log("retval", retval);
    },
  );
};
let indent = 0;

function doReplaceFunctions() {
  // const prefixes = ["Send_Pkt*", "P2P*", "*RcvTh*", "parse_*"]; // "XQP2P*",
  // const prefixes = ["parse_*", "pack_*", "Send_Pkt*", "create_*"];
  const prefixes = [
    "create_*",
    "pack_*",
    "CSession_CtrlPkt_Proc",
    "CSession_DataPkt_Proc",
    "CSession_*_Deal",
    "PktSeq_seqSet",
    "Cmd*",
    "*Cmd",
    "CSession_DataPkt_Proc", // struct, inbuf == [cmd, ....]; cmd => { 0xf1d0: PktSeq_seqSet, 0xf1d1: PktAck_ackSet }
    "PktSeq_seqSet",
    "Send_Pkt_DrwAck",
  ];
  const spam = ["XQP2P_Check_Buffer", "P2P_ChannelBufferCheck", "create_android_logger"];

  const replaced = replaceFunctions();

  prefixes
    .map((prefix) => DebugSymbol.findFunctionsMatching(prefix))
    .flat()
    .map(DebugSymbol.fromAddress)
    .filter((dbg) => !spam.includes(dbg.name))
    .map((dbg) => {
      Interceptor.attach(dbg.address, {
        onEnter: (args) => {
          indent = indent + 1;
          let flag = !replaced.includes(dbg.name) ? "[NOT REPLACED] " : "";
          if (!dbg.name.startsWith("create") && !dbg.name.startsWith("pack_"))
            console.log(" ".repeat(indent) + flag + dbg.name);
        },
        onLeave: (retval) => {
          indent = indent - 1;
        },
      });
      console.log(`Hooked ${dbg.name}`);
    });
}
function doHooks() {
  var libnative_addr = Module.findBaseAddress("libvdp.so");
  if (libnative_addr) {
    hook___android_log_print();
    // hook_create_P2pRdy();
    // hook_in_out_buf("create_LstReq", 0x1c, 0x1c);
    //hook_in_out_buf("create_P2pRdy", 0x1c, 0x1c);
    hook_udpsend();
    doReplaceFunctions();

    // hook_p2p_read();
    // hook_pack_P2pId();
    // hook_pack_ClntPkt();
  } else {
    console.log("NO WORKING");
  }
}
setImmediate(doHooks);
