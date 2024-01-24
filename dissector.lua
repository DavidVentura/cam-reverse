-- Create a new protocol for your custom packets
my_protocol = Proto("MyProtocol", "My Custom Protocol")

-- Define the fields you want to display in Wireshark
my_protocol.fields = {}
my_protocol.fields.type = ProtoField.string("MyProtocol.type", "Type")
my_protocol.fields.payload = ProtoField.bytes("MyProtocol.payload", "Data")
my_protocol.fields.len = ProtoField.uint16("MyProtocol.len", "Len", base.HEX)

my_protocol.fields.m_type 		= ProtoField.uint8("MyProtocol.m_type", "Stream Type", base.HEX)
my_protocol.fields.m_stream_id 	= ProtoField.uint8("MyProtocol.m_stream_id", "Stream ID", base.HEX)
my_protocol.fields.elem_count	= ProtoField.uint16("MyProtocol.elem_count", "Elem count", base.DEC)

my_protocol.fields.cmd_payload_len = ProtoField.uint16("MyProtocol.cmd_payload_len", "CMD Payload Len", base.HEX)
my_protocol.fields.cmd = ProtoField.uint16("MyProtocol.cmd", "CMD", base.HEX)
my_protocol.fields.start = ProtoField.uint16("MyProtocol.start", "Start", base.HEX)
my_protocol.fields.cmd_dest = ProtoField.uint16("MyProtocol.cmd_dest", "Dest", base.HEX)
my_protocol.fields.cmd_payload = ProtoField.bytes("MyProtocol.payload", "Payload", base.DASH)

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
function my_protocol.dissector(buffer, pinfo, tree)
    local packet_length = buffer:len()

	local subtree = tree:add(my_protocol, buffer(), "My Custom Protocol Data")

	-- Add the entire packet as a field
	local packetname = lut[buffer(0, 2):uint()]
	subtree:add(my_protocol.fields.type, packetname)

	-- Set the protocol description in the packet list
	pinfo.cols.protocol:set("MyProtocol")
	if packetname == "DrwAck" then
		subtree:add(my_protocol.fields.len, buffer(2, 2))
		subtree:add(my_protocol.fields.m_type, buffer(4, 1))
		subtree:add(my_protocol.fields.m_stream_id, buffer(5, 1))
		subtree:add(my_protocol.fields.elem_count, buffer(6, 2))

	end
	if packetname == "Drw" then
		subtree:add(my_protocol.fields.len, buffer(2, 2))
		subtree:add(my_protocol.fields.m_type, buffer(4, 1))
		subtree:add(my_protocol.fields.m_stream_id, buffer(5, 1))
		subtree:add_le(my_protocol.fields.start, buffer(8, 2))
		subtree:add_le(my_protocol.fields.cmd, buffer(0xa, 2))
		local payload_len = buffer(0xc, 2):le_uint()
		subtree:add_le(my_protocol.fields.cmd_payload_len, buffer(0xc, 2))
		subtree:add_le(my_protocol.fields.cmd_dest, buffer(0xe, 2))
		subtree:add(my_protocol.fields.cmd_payload, buffer(0x10, payload_len))
		-- subtree:add(my_protocol.fields.cmd, buffer(0xc, 2))

	end
	--  AvcLIB = src/IpcSession.cpp, line 1113, CmdSndProc:BATC609531EXLVS[0:0:10] now CmdSend[start=a11,cmd=1032,len=4,dest=0]=12
    -- UDP PKT SEND Drw (0xf1d0)
    --            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    -- 00000000  f1 d0 00 10 d1 00 00 04 11 0a 32 10 04 00 00 00  ..........2.....
    -- 00000010  50 70 77 35                                      Ppw5

	subtree:add(my_protocol.fields.payload, buffer(2, packet_length-2))
end

udp_table = DissectorTable.get("udp.port"):add(49512, my_protocol)
