import { replaceFunctions } from "./func_replacements.js";

function hook_fn(name_in_elf, enter, leave) {
  var symbol_addr = DebugSymbol.fromName(name_in_elf).address;
  console.log(`${name_in_elf} addr is: ${symbol_addr}`);
  Interceptor.attach(symbol_addr, {
    onEnter: enter,
    onLeave: leave,
  });
  console.log(`Hooked ${name_in_elf}`);
}

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

const hook_pack_ClntPkt = () => {
  let sym = "pack_ClntPkt";
  hook_fn(
    sym,
    (args) => {
      console.log(`onEnter ${sym}`);

      /*
                         * onEnter pack_ClntPkt
        2 0x7b5ef9c640
        onExit pack_ClntPkt, ret=24
                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
        0123456789ABCDEF 00000000  f1 67 00 14 42 41 54 43 00 00 00 00 00 09 4c
        fb .g..BATC......L. 00000010  45 58 4c 56 53 00 00 00 EXLVS...
        */
      // f1 30 00 00 heartbeat?
      // int pack_ClntPkt(int m_type_or_len,ushort *pkt_buf,long
      // something_out)
      let m_ptype = args[0].toInt32();
      // type = 2 == LanSearch, LanSearchExt, ServerReq, Hello, DevQuery
      // 2 = P2P?
      // let m_buf = args[1].readByteArray(m_ptype); // len??
      let m_out = args[2];
      this.outBuf = args[2];
      this.inBuf = args[1];
      var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(
        DebugSymbol.fromAddress,
      );
      for (var j in trace) {
        console.log(trace[j]);
      }
      console.log(m_ptype);
    },
    (retval) => {
      console.log(`onExit ${sym}, ret=${retval.toInt32()}`);
      console.log("out\n", this.outBuf.readByteArray(retval.toInt32()));
      console.log("in\n", this.inBuf.readByteArray(retval.toInt32()));
      console.log(
        "############################################################",
      );
    },
  );
};

const hook___android_log_print = () => {
  const sym = "__android_log_print";
  hook_fn(
    sym,
    (args) => {
      // (ushort *param_1,int param_2,undefined4 *param_3,undefined8 param_4
      let _prio = args[0].toInt32();
      let _tag = args[1].readCString();
      let fmt = args[2].readCString();
      // console.log(fmt); // debug if crashes due to missing placeholder
      const types = placeholderTypes(fmt); // ['s', 'd', ..]`

      let o = {
        s: (x) => x.readCString(),
        d: (x) => x.toInt32(),
        u: (x) => x.toInt32(),
        x: (x) => x.toInt32().toString(16),
        f: (x) => x.toFloat(),
      };

      const values = types.map((t, idx) => o[t](args[idx + 3]));
      const newStr = sprintf(fmt, values);
      console.log(newStr);
    },
    () => {},
  );
};
const hook_pack_P2pId = () => {
  var sym = "pack_P2pId";
  sym = "pack_P2pHdr";
  sym = "Send_Pkt";
  hook_fn(
    sym,
    (args) => {
      console.log(`onEnter ${sym}`);
      // (ushort *param_1,int param_2,undefined4 *param_3,undefined8 param_4
      let m_ptype = args[1].toInt32();
      let m_data = args[0].readByteArray(m_ptype); // len??
      let m_sock = args[2];
      let m_p4 = args[3];
      console.log(m_data, m_ptype, m_sock, m_p4);
    },
    () => {},
  );
};

const hook_create_P2pRdy = () => {
  var sym = "create_P2pRdy";
  hook_fn(
    sym,
    (args) => {
      console.log(`onEnter ${sym}`);
      // (ushort *param_1,int param_2,undefined4 *param_3,undefined8 param_4
      this.out = args[0]; // u16 ptr
      let _in = args[1].readByteArray(2);
      console.log("in", _in);
    },
    (retval) => {
      console.log(`onExit ${sym}, retval ${retval}`);
      console.log(this.out.readByteArray(0x18)); //  _g_p2prdy_size = 0x14, retruns +4
    },
  );
};
let indent = 0;
function doHooks() {
  var libnative_addr = Module.findBaseAddress("libvdp.so");
  // const prefixes = ["Send_Pkt*", "P2P*", "*RcvTh*", "parse_*"]; // "XQP2P*",
  // const prefixes = ["parse_*", "pack_*", "Send_Pkt*", "create_*"];
  const prefixes = ["create_*"];
  const spam = ["XQP2P_Check_Buffer", "P2P_ChannelBufferCheck"];
  if (libnative_addr) {
    hook___android_log_print();
    hook_create_P2pRdy;
    const replaced = replaceFunctions();
    console.log(replaced);
    prefixes
      .map((prefix) => DebugSymbol.findFunctionsMatching(prefix))
      .flat()
      .map(DebugSymbol.fromAddress)
      .filter((dbg) => !spam.includes(dbg.name))
      .map((dbg) => {
        Interceptor.attach(dbg.address, {
          onEnter: (args) => {
            indent = indent + 1;
            let flag = replaced.includes(dbg.name) ? "[REPLACED] " : "";
            console.log(" ".repeat(indent) + flag + dbg.name);
          },
          onLeave: (retval) => {
            indent = indent - 1;
          },
        });
        console.log(`Hooked ${dbg.name}`);
      });

    // hook_p2p_read();
    // hook_pack_P2pId();
    // hook_pack_ClntPkt();
  } else {
    console.log("NO WORKING");
  }
}

const matchy = /%[0-9.-]*([a-z])/g;
const replacy = /(.*?)%[0-9.-]*([a-z])/g;

const placeholderTypes = (str) => {
  // '%-16s, line %4d, %-16s:ret=%d,broadcast lan_seach to %s:%.3f!!!!'
  // =>
  // [ 's', 'd', 's', 'd', 's', 'f' ]
  return [...str.matchAll(matchy)].map((m) => m[1]);
};
const sprintf = (str, values) => {
  // '%-16s, line %4d, %-16s:ret=%d,broadcast lan_seach to %s:%.3f!!!!' +
  // ["asd", 20, ...]
  // =>
  // asd, line 20, ...
  const matches = str.matchAll(replacy);
  return [...matches].map((m, idx) => m[1] + values[idx].toString()).join("");
};
setImmediate(doHooks);
