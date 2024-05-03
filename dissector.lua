-- Create a new protocol for your custom packets
ilnk_proto = Proto("iLnkP2P", "iLnk")

-- Define the fields you want to display in Wireshark
ilnk_proto.fields = {}
ilnk_proto.fields.type = ProtoField.string("iLnkP2P.type", "Type")
-- ilnk_proto.fields.payload = ProtoField.bytes("iLnkP2P.payload", "Payload")
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
ilnk_proto.fields.warning 			= ProtoField.string("iLnkP2P.warning", "Warning")
--
-- jpeg | audio | continuation type?
ilnk_proto.fields.data_payload 		= ProtoField.bytes("iLnkP2P.data_payload", "Data Payload", base.DASH)
ilnk_proto.fields.payload_type 		= ProtoField.string("iLnkP2P.payload_type", "Payload type")
ilnk_proto.fields.payload_subtype 	= ProtoField.string("iLnkP2P.payload_type", "Payload type")
ilnk_proto.fields.payload_len 		= ProtoField.uint32("iLnkP2P.payload_len", "Payload len")
ilnk_proto.fields.frame_no 			= ProtoField.uint32("iLnkP2P.frame_no", "Frame no")
-- audio
ilnk_proto.fields.audio_header 		= ProtoField.bytes("iLnkP2P.audio_header", "Audio Header")
ilnk_proto.fields.hdr_type 			= ProtoField.uint16("iLnkP2P.hdr_type", "Header Type")
ilnk_proto.fields.hdr_streamid 		= ProtoField.uint16("iLnkP2P.hdr_streamid", "Header Stream ID")
ilnk_proto.fields.hdr_frameno 		= ProtoField.uint32("iLnkP2P.hdr_frameno", "Header Frame")
ilnk_proto.fields.hdr_len 			= ProtoField.uint16("iLnkP2P.hdr_len", "Header Len")
ilnk_proto.fields.hdr_ver 			= ProtoField.uint16("iLnkP2P.hdr_ver", "Header version")
ilnk_proto.fields.hdr_res 			= ProtoField.uint16("iLnkP2P.hdr_red", "Header resolution")

ilnk_proto.fields.encrypted 		= ProtoField.bool("iLnkP2P.encrypted", "Encrypted")
ilnk_proto.fields.cmd_type 		= ProtoField.string("iLnkP2P.cmd_type", "Cmd Pkt Type")
ilnk_proto.fields.decrypted_data	= ProtoField.bytes("iLnkP2P.decrypted_data", "Decrypted data")

-- PunchPkt
ilnk_proto.fields.serial	= ProtoField.string("iLnkP2P.serial", "Serial")

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
}

control_lut = {
	[0x2010] = "ConnectUser",
	[0x2011] = "ConnectUserAck",
	[0x0811] = "ConnectUserAck",
}

-- Define a function to dissect the packets
function ilnk_proto.dissector(buffer, pinfo, tree)
    local packet_length = buffer:len()

	local subtree = tree:add(ilnk_proto, buffer(), "iLnkP2P")

	-- Add the entire packet as a field
	local packettype = buffer(0, 2):uint()
	local packetname = lut[packettype]
	packetname = packetname or "UNK " .. string.format("0x%X", packettype)
	subtree:add(ilnk_proto.fields.type, buffer(0, 2), packetname)

	-- Set the protocol description in the packet list
	pinfo.cols.protocol:set("iLnkP2P")
	pinfo.cols.info:set(packetname)
	if packetname == "PunchPkt" or packetname == "P2pRdy" then
		local len = buffer(2, 2)
		subtree:add(ilnk_proto.fields.len, len)
		local serial_prefix = buffer(4, 4):string()
		local serial_no = UInt64(buffer(12, 4):uint(), buffer(8, 4):uint())
		local serial_suffix = buffer(16, 5):string()
		subtree:add(ilnk_proto.fields.serial, buffer(4, len:uint()-3), serial_prefix..serial_no..serial_suffix)
	end
	if packetname == "DrwAck" then
		subtree:add(ilnk_proto.fields.len, buffer(2, 2))
		subtree:add(ilnk_proto.fields.m_type, buffer(4, 1))
		subtree:add(ilnk_proto.fields.m_stream_id, buffer(5, 1))
		subtree:add(ilnk_proto.fields.elem_count, buffer(6, 2))

	end
	if packetname == "Drw" then
		local b_pkt_len = buffer(2, 2)
		local pkt_len = b_pkt_len:uint()
		local is_data_packet = buffer(5, 1):uint() == 1
		subtree:add(ilnk_proto.fields.len, b_pkt_len)
		subtree:add(ilnk_proto.fields.m_type, buffer(4, 1))
		subtree:add(ilnk_proto.fields.m_stream_id, buffer(5, 1))
		if pkt_len < 12 then
			subtree:add(ilnk_proto.fields.warning, "Short read"):set_generated()
			return
		end
		subtree:add(ilnk_proto.fields.pkt_seq, buffer(6, 2))
		pinfo.cols.info:set(buffer(6, 2):uint())
		local b_payload_len = buffer(0xc, 2)
		local payload_len = buffer(0xc, 2):le_uint()

		if not is_data_packet then
			subtree:add_le(ilnk_proto.fields.start, buffer(8, 2))
			subtree:add_le(ilnk_proto.fields.cmd, buffer(0xa, 2))
			subtree:add_le(ilnk_proto.fields.cmd_payload_len, b_payload_len)
			subtree:add_le(ilnk_proto.fields.cmd_dest, buffer(0xe, 2))
			-- inline value for short-payload bytes
			subtree:add(ilnk_proto.fields.auth_token, buffer(0x10, 4))

			if buffer(0xb, 1):uint() % 2 == 1 then
				cmdtype = "ack"
			else
				cmdtype = "cmd"
			end
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
		else
			local payload_type
			local payload_subtype
			local payload_tvb = ByteArray.tvb(buffer(8, packet_length-8):bytes(), "Data Payload")
			if payload_tvb:range(0, 4):uint() == 0xffd8ffdb then
				payload_subtype = "new frame"
				-- start of new frame
			end
			if payload_tvb:range(0, 4):uint() == 0x55aa15a8 then
				payload_type = "audio"
				subtree:add(ilnk_proto.fields.audio_header, buffer(8, 32))
				subtree:add(ilnk_proto.fields.hdr_type, buffer(12, 1))
				subtree:add(ilnk_proto.fields.hdr_streamid, buffer(13, 1))

				subtree:add(ilnk_proto.fields.hdr_frameno, buffer(20, 4), buffer(20, 4):le_uint())
				subtree:add(ilnk_proto.fields.hdr_len, buffer(24, 4), buffer(24, 4):le_uint())
				subtree:add(ilnk_proto.fields.hdr_ver, buffer(28, 1), buffer(28, 1):le_uint())
				subtree:add(ilnk_proto.fields.hdr_res, buffer(29, 1), buffer(29, 1):le_uint())

				subtree:add(ilnk_proto.fields.payload_len, buffer(24, 4), buffer(24, 4):le_uint())
				subtree:add(ilnk_proto.fields.frame_no, buffer(20, 4), buffer(20, 4):le_uint())
				if payload_tvb:range(4, 1):uint() == 0x06 then
					payload_subtype = "audio data"
				elseif payload_tvb:range(4, 1):uint() == 0x03 then
					payload_subtype = "maybe audio metadata"
				else
					payload_subtype = "REALLY not sure audio data"
				end
			else
				payload_type = "jpeg"
				payload_subtype = "jpeg continuation"
			end
			subtree:add(ilnk_proto.fields.payload_type, buffer(8, 4), payload_type)
			subtree:add(ilnk_proto.fields.payload_subtype, buffer(12, 1), payload_subtype)
			subtree:add(ilnk_proto.fields.data_payload, payload_tvb:range(0, packet_length-8))
		end
	end
	--  AvcLIB = src/IpcSession.cpp, line 1113, CmdSndProc:BATC609531EXLVS[0:0:10] now CmdSend[start=a11,cmd=1032,len=4,dest=0]=12
    -- UDP PKT SEND Drw (0xf1d0)
    --            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    -- 00000000  f1 d0 00 10 d1 00 00 04 11 0a 32 10 04 00 00 00  ..........2.....
    -- 00000010  50 70 77 35                                      Ppw5

	-- subtree:add(ilnk_proto.fields.payload, buffer(2, packet_length-2))
end

local function heuristic_checker(buffer, pinfo, tree)
	length = buffer:len()
    if length < 2 then return false end
	local packetname = lut[buffer(0, 2):uint()]
	if packetname ~= nil then
		ilnk_proto.dissector(buffer, pinfo, tree)
		return true
	end
	return false
end
udp_table2 = DissectorTable.get("udp.port"):add(32108, ilnk_proto)
h = ilnk_proto:register_heuristic("udp", heuristic_checker)
