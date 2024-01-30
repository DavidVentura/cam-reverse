import { Commands, CommandsByValue } from "./datatypes.js";
import { replaceFunctions, XqBytesDec } from "./func_replacements.js";
import { placeholderTypes, sprintf, u16_swap } from "./utils.js";

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

const hook_Log = () => {
  Java.perform(function () {
    var Log = Java.use("android.util.Log");
    Log.d.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
      console.log("The application reports Log.d(" + a.toString() + ", " + b.toString() + ")");
      return this.d(a, b, c);
    };
    Log.v.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
      console.log("The application reports Log.v(" + a.toString() + ", " + b.toString() + ")");
      return this.v(a, b, c);
    };

    Log.i.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
      console.log("The application reports Log.i(" + a.toString() + ", " + b.toString() + ")");
      return this.i(a, b, c);
    };
    Log.e.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
      console.log("The application reports Log.e(" + a.toString() + ", " + b.toString() + ")");
      return this.e(a, b, c);
    };
    Log.w.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
      console.log("The application reports Log.w(" + a.toString() + ", " + b.toString() + ")");
      return this.w(a, b, c);
    };
    Log.d.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
      console.log("The application reports Log.d(" + a.toString() + ", " + b.toString() + ")");
      return this.d(a, b);
    };
    Log.v.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
      console.log("The application reports Log.v(" + a.toString() + ", " + b.toString() + ")");
      return this.v(a, b);
    };

    Log.i.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
      console.log("The application reports Log.i(" + a.toString() + ", " + b.toString() + ")");
      return this.i(a, b);
    };
    Log.e.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
      console.log("The application reports Log.e(" + a.toString() + ", " + b.toString() + ")");
      return this.e(a, b);
    };
    Log.w.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
      console.log("The application reports Log.w(" + a.toString() + ", " + b.toString() + ")");
      return this.w(a, b);
    };
  });
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
      console.log(_tag, newStr.trim());
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
      if (name != "P2PAliveAck") {
        if (name != "LanSearch" && name != "LanSearchExt") {
          let cmd = "";
          if (name == "Drw") {
            cmd = args[0].add(0xa).readU16().toString(16);
          }
          let tstamp = Date.now();
          console.log(`${tstamp} UDP PKT SEND ${name} (0x${cmd.toString(16)}) - CMD? ${cmd}`);
          console.log(data);
        }
      } else {
        console.log("> P2PAliveAck");
      }
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
      const len = u16_swap(o.buf.add(2).readU16());
      const name = CommandsByValue[cmd];
      if (name != "P2PAlive") {
        let tstamp = Date.now();
        console.log(`${tstamp} UDP PKT RECV, len=${len}, cmd=${name}, 0x${cmd.toString(16)}, ret=${retval}`);
        console.log(data);
      } else {
        console.log("< P2PAlive");
      }
      if (cmd == Commands.Drw) {
        if (len > 0x18) {
          // pos(0xa11) == 8 + 0xc == 0x14 == 20
          const under = data.unwrap().add(0x14); //, len - 0x20;
          XqBytesDec(under, len - 0x10, 4);
          console.log("decrypted data");
          console.log(data);
        }
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

  /*
  hook_fn(
    "_Z10ackRcvProcP12CPPPPChannelP7_JNIEnvP8_jstringP17_CMD_CHANNEL_HEAD",
    (args) => {
      const param1 = args[0];
      const pvar5 = args[2];
      const pkt = args[3];
      console.log("ackRcvProc: pvar5:");
      console.log(pvar5.toInt32());
      console.log("pkt:");
      console.log(pkt.readByteArray(4));
      console.log("param1:");
      console.log(param1.readByteArray(3345));
    },
    (retval) => {},
  );

  hook_fn(
    "_Z10cmdRcvProcP12CPPPPChannelP7_JNIEnvP8_jstringP17_CMD_CHANNEL_HEAD",
    (args) => {
      const param1 = args[0];
      const pvar5 = args[2];
      const pkt = args[3];
      console.log("cmdRcvProc: pvar5:");
      console.log(pvar5.toInt32());
      console.log("pkt:");
      console.log(pkt.readByteArray(4));
      console.log("param1:");
      console.log(param1.readByteArray(3345));
    },
    (retval) => {},
  );
	*/
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
    hook_Log();
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
