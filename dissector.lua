-- Create a new protocol for your custom packets
ilnk_proto = Proto("iLnkP2P", "iLnk")

-- Define the fields you want to display in Wireshark
ilnk_proto.fields = {}
ilnk_proto.fields.type = ProtoField.string("iLnkP2P.type", "Type")
ilnk_proto.fields.payload = ProtoField.bytes("iLnkP2P.payload", "Payload")
ilnk_proto.fields.len = ProtoField.uint16("iLnkP2P.len", "Packet length", base.HEX)

ilnk_proto.fields.m_type 		= ProtoField.uint8("iLnkP2P.m_type", "Stream type", base.HEX)
ilnk_proto.fields.m_stream_id 	= ProtoField.uint8("iLnkP2P.m_stream_id", "Stream ID", base.HEX)
ilnk_proto.fields.pkt_seq 		= ProtoField.uint16("iLnkP2P.pkt_seq", "Packet ID", base.HEX)
ilnk_proto.fields.elem_count	= ProtoField.uint16("iLnkP2P.elem_count", "Elem count", base.DEC)

ilnk_proto.fields.cmd_payload_len 	= ProtoField.uint16("iLnkP2P.cmd_payload_len", "CMD Payload Len", base.HEX)
ilnk_proto.fields.cmd 				= ProtoField.uint16("iLnkP2P.cmd", "CMD", base.HEX)
ilnk_proto.fields.start 			= ProtoField.uint16("iLnkP2P.start", "Start", base.HEX)
ilnk_proto.fields.cmd_dest 		= ProtoField.uint16("iLnkP2P.cmd_dest", "Dest", base.HEX)
ilnk_proto.fields.auth_token 		= ProtoField.bytes("iLnkP2P.auth_token", "CMD auth token", base.DASH)
ilnk_proto.fields.cmd_payload 		= ProtoField.bytes("iLnkP2P.payload", "CMD Payload", base.DASH)
-- jpeg | audio | continuation type?
-- ilnk_proto.fields.cmd_payload 		= ProtoField.bytes("iLnkP2P.payload", "Payload", base.DASH)
-- ilnk_proto.fields.cmd_payload 		= ProtoField.bytes("iLnkP2P.payload", "Payload", base.DASH)

ilnk_proto.fields.encrypted 		= ProtoField.bool("iLnkP2P.encrypted", "Encrypted")
ilnk_proto.fields.cmd_type 		= ProtoField.string("iLnkP2P.cmd_type", "Cmd Pkt Type")
ilnk_proto.fields.decrypted_data	= ProtoField.bytes("iLnkP2P.decrypted_data", "Decrypted data")

lut = {
    [0xf1f0] = "Close",
    [0xf132] = "LanSearchExt",
    [0xf130] = "LanSearch",
    [0xf1e0] = "P2PAlive",
    [0xf1e1] = "P2PAliveAck",
    [0xf100] = "Hello",
    [0xf142] = "P2pRdy",
    [0xf120] = "P2pReq",
    [0xf167] = "LstReq",
    [0xf1d1] = "DrwAck",
    [0xf1d0] = "Drw",
    [0xf140] = "PunchTo",
    [0xf141] = "PunchPkt",
    [0xf101] = "HelloAck",
    [0xf102] = "RlyTo",
    [0xf111] = "DevLgnAck",
    [0xf121] = "P2PReqAck",
    [0xf169] = "ListenReqAck",
    [0xf170] = "RlyHelloAck",
    [0xf171] = "RlyHelloAck2",
	__index = function(tbl, key)
		return "UNK " .. string.format("0x%X", key)
	end
}
setmetatable(lut, lut)

-- Define a function to dissect the packets
function ilnk_proto.dissector(buffer, pinfo, tree)
    local packet_length = buffer:len()

	local subtree = tree:add(ilnk_proto, buffer(), "iLnkP2P")

	-- Add the entire packet as a field
	local packetname = lut[buffer(0, 2):uint()]
	subtree:add(ilnk_proto.fields.type, packetname)

	-- Set the protocol description in the packet list
	pinfo.cols.protocol:set("iLnkP2P")
	if packetname == "DrwAck" then
		subtree:add(ilnk_proto.fields.len, buffer(2, 2))
		subtree:add(ilnk_proto.fields.m_type, buffer(4, 1))
		subtree:add(ilnk_proto.fields.m_stream_id, buffer(5, 1))
		subtree:add(ilnk_proto.fields.elem_count, buffer(6, 2))

	end
	if packetname == "Drw" then
		local b_pkt_len = buffer(2, 2)
		local pkt_len = b_pkt_len:uint()
		subtree:add(ilnk_proto.fields.len, b_pkt_len)
		subtree:add(ilnk_proto.fields.m_type, buffer(4, 1))
		subtree:add(ilnk_proto.fields.m_stream_id, buffer(5, 1))
		subtree:add(ilnk_proto.fields.pkt_seq, buffer(6, 2))
		subtree:add_le(ilnk_proto.fields.start, buffer(8, 2))
		subtree:add_le(ilnk_proto.fields.cmd, buffer(0xa, 2))
		local b_payload_len = buffer(0xc, 2)
		local payload_len = buffer(0xc, 2):le_uint()

		if buffer(0xb, 1):uint() % 2 == 1 then
			cmdtype = "ack"
		else
			cmdtype = "cmd"
		end

		subtree:add_le(ilnk_proto.fields.cmd_payload_len, b_payload_len)
		subtree:add_le(ilnk_proto.fields.cmd_dest, buffer(0xe, 2))
		-- inline value for short-payload bytes
		subtree:add(ilnk_proto.fields.auth_token, buffer(0x10, 4))

		subtree:add(ilnk_proto.fields.cmd_type, cmdtype):set_generated()
		subtree:add(ilnk_proto.fields.encrypted, payload_len >= 5):set_generated()
		if payload_len >= 5 then
			local payload = buffer(0x14, payload_len - 4)
			local dec_payload = ByteArray.new()
			dec_payload:set_size(payload_len - 4)
			for i=4,payload_len-5 do -- inclusive upper range
				local v = buffer(0x14 + i-4, 1):uint()
				if (v % 2) == 0 then
					v = v + 1
				else
					v = v - 1
				end
				dec_payload:set_index(i, v)
			end
			for i=0,3 do
				local v = buffer(pkt_len+i, 1):uint()
				if v % 2 == 0 then
					v = v + 1
				else
					v = v - 1
				end
				dec_payload:set_index(i, v)
			end
			local dec_tvb = ByteArray.tvb(dec_payload, "Decrypted payload")
			subtree:add(ilnk_proto.fields.decrypted_data, dec_tvb:range(0, payload_len -4) ):set_generated()

			local payload_tvb = ByteArray.tvb(buffer(0x14, payload_len -4):bytes(), "CMD Payload")
			subtree:add(ilnk_proto.fields.cmd_payload, payload_tvb:range(0, payload_len -4))
		end

		--
		-- subtree:add(ilnk_proto.fields.cmd, buffer(0xc, 2))

	end
	--  AvcLIB = src/IpcSession.cpp, line 1113, CmdSndProc:BATC609531EXLVS[0:0:10] now CmdSend[start=a11,cmd=1032,len=4,dest=0]=12
    -- UDP PKT SEND Drw (0xf1d0)
    --            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    -- 00000000  f1 d0 00 10 d1 00 00 04 11 0a 32 10 04 00 00 00  ..........2.....
    -- 00000010  50 70 77 35                                      Ppw5

	subtree:add(ilnk_proto.fields.payload, buffer(2, packet_length-2))
end

udp_table = DissectorTable.get("udp.port"):add(49512, ilnk_proto)
