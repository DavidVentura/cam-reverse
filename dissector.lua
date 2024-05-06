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
ilnk_proto.fields.cmd_name 		= ProtoField.string("iLnkP2P.cmd_name", "Cmd Pkt")
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
	[0x0000] = "CFGID_VERSION",
	[0x0000] = "CMD_ACK_OK",
	[0x0001] = "CFGID_LANGUAGE",
	[0x0001] = "CMD_ACK_UNAUTH",
	[0x0002] = "CFGID_PRODUCTE",
	[0x0002] = "CMD_ACK_NO_PRIVILEGE",
	[0x0003] = "CFGID_UPGRADE",
	[0x0003] = "CMD_ACK_INVALID_PARAM",
	[0x0004] = "CFGID_P2P",
	[0x0004] = "CMD_ACK_CMDEXCUTE_FAILED",
	[0x0005] = "CFGID_TZ",
	[0x0005] = "CMD_ACK_NONE_RESULT",
	[0x0006] = "CFGID_USER",
	[0x0006] = "CMD_ACK_UNKNOWN",
	[0x0007] = "CFGID_OPR",
	[0x0008] = "CFGID_SERIAL",
	[0x0009] = "CFGID_WIRED",
	[0x000a] = "CFGID_WLAN",
	[0x000b] = "CFGID_OSD",
	[0x000c] = "CFGID_IMG",
	[0x000d] = "CFGID_CMOS",
	[0x000e] = "CFGID_PTZ",
	[0x000f] = "CFGID_AUDIO",
	[0x0010] = "CFGID_VIDEO",
	[0x0011] = "CFGID_RECPOLICY",
	[0x0012] = "CFGID_RESCH",
	[0x0013] = "CFGID_MDALARM",
	[0x0014] = "CFGID_ADCALARM",
	[0x0015] = "CFGID_INPUTALARM",
	[0x0016] = "CFGID_SMTP",
	[0x0017] = "CFGID_FTP",
	[0x0018] = "CFGID_PUSH",
	[0x0019] = "CFGID_WLANPMK",
	[0x00fe] = "CGICMD",
	[0x00ff] = "BINCMD",
	[0x03e8] = "CMD_ACK_ILLIGAL",
	[0x0eff] = "CMD_DEV_BROADCAST",
	[0x1000] = "CMD_SYSTEM_DFTCFG_IMPORT",
	[0x1001] = "CMD_SYSTEM_DFTCFG_EXPORT",
	[0x1002] = "CMD_SYSTEM_DFTCFG_RECOVERY",
	[0x1003] = "CMD_SYSTEM_ITEMDFTCFG_RECOVERY",
	[0x1004] = "CMD_SYSTEM_CRNCFG_EXPORT",
	[0x1005] = "CMD_SYSTEM_CRNCFG_IMPORT",
	[0x1006] = "CMD_SYSTEM_DFTCFG_CREATE",
	[0x1007] = "CMD_SYSTEM_UPGRAD_SET",
	[0x1008] = "CMD_SYSTEM_STATUS_GET",
	[0x1009] = "CMD_SYSTEM_UPGRAD_GET",
	[0x1010] = "CMD_SYSTEM_SHUTDOWN",
	[0x1011] = "CMD_SYSTEM_REBOOT",
	[0x1012] = "CMD_SYSTEM_INF_GET",
	[0x1013] = "CMD_SYSTEM_ALIAS_SET",
	[0x1020] = "CMD_SYSTEM_USER_CHK",
	[0x1021] = "CMD_SYSTEM_USER_SET",
	[0x1022] = "CMD_SYSTEM_USER_GET",
	[0x1023] = "CMD_SYSTEM_USER_CHG",
	[0x1030] = "CMD_SYSTEM_P2PPARAM_SET",
	[0x1031] = "CMD_SYSTEM_OPRPOLICY_SET",
	[0x1032] = "CMD_SYSTEM_OPRPOLICY_GET",
	[0x1033] = "CMD_SYSTEM_P2PPARAM_GET",
	[0x1040] = "CMD_SYSTEM_DATETIME_SET",
	[0x1041] = "CMD_SYSTEM_DATETIME_GET",
	[0x1051] = "CMD_NOTIFICATION",
	[0x1100] = "ACK_SYSTEM_DFTCFG_IMPORT",
	[0x1101] = "ACK_SYSTEM_DFTCFG_EXPORT",
	[0x1102] = "ACK_SYSTEM_DFTCFG_RECOVERY",
	[0x1103] = "ACK_SYSTEM_ITEMDFTCFG_RECOVERY",
	[0x1104] = "ACK_SYSTEM_CRNCFG_EXPORT",
	[0x1105] = "ACK_SYSTEM_CRNCFG_IMPORT",
	[0x1106] = "ACK_SYSTEM_DFTCFG_CREATE",
	[0x1107] = "ACK_SYSTEM_UPGRAD_SET",
	[0x1108] = "ACK_SYSTEM_STATUS_GET",
	[0x1109] = "ACK_SYSTEM_UPGRAD_GET",
	[0x1110] = "ACK_SYSTEM_SHUTDOWN",
	[0x1111] = "ACK_SYSTEM_REBOOT",
	[0x1112] = "ACK_SYSTEM_INF_GET",
	[0x1113] = "ACK_SYSTEM_ALIAS_SET",
	[0x1120] = "ACK_SYSTEM_USER_CHK",
	[0x1121] = "ACK_SYSTEM_USER_SET",
	[0x1122] = "ACK_SYSTEM_USER_GET",
	[0x1123] = "ACK_SYSTEM_USER_CHG",
	[0x1130] = "ACK_SYSTEM_P2PPARAM_SET",
	[0x1131] = "ACK_SYSTEM_OPRPOLICY_SET",
	[0x1132] = "ACK_SYSTEM_OPRPOLICY_GET",
	[0x1133] = "ACK_SYSTEM_P2PPARAM_GET",
	[0x1140] = "ACK_SYSTEM_DATETIME_SET",
	[0x1141] = "ACK_SYSTEM_DATETIME_GET",
	[0x1151] = "ACK_NOTIFICATION",
	[0x2000] = "CMD_SD_FORMAT",
	[0x2001] = "CMD_SD_RECPOLICY_SET",
	[0x2002] = "CMD_SD_RECPOLICY_GET",
	[0x2003] = "CMD_SD_RECORDING_NOW",
	[0x2004] = "CMD_SD_INFO_GET",
	[0x2005] = "CMD_SD_RECORDFILE_GET",
	[0x2006] = "CMD_SD_RECORDSCH_GET",
	[0x2007] = "CMD_SD_RECORDSCH_SET",
	[0x2008] = "CMD_SD_RETRIVEL",
	[0x2009] = "CMD_SD_PICFILE_GET",
	[0x200a] = "CMD_SD_PIC_CAPTURE",
	[0x200b] = "CMD_SD_REC_DEL",
	[0x200c] = "CMD_SD_PIC_DEL",
	[0x200d] = "CMD_SD_SPL_DEL",
	[0x2100] = "ACK_SD_FORMAT",
	[0x2101] = "ACK_SD_RECPOLICY_SET",
	[0x2102] = "ACK_SD_RECPOLICY_GET",
	[0x2103] = "ACK_SD_RECORDING_NOW",
	[0x2104] = "ACK_SD_INFO_GET",
	[0x2105] = "ACK_SD_RECORDFILE_GET",
	[0x2106] = "ACK_SD_RECORDSCH_GET",
	[0x2107] = "ACK_SD_RECORDSCH_SET",
	[0x2108] = "ACK_SD_RETRIVEL",
	[0x2109] = "ACK_SD_PICFILE_GET",
	[0x210a] = "ACK_SD_PIC_CAPTURE",
	[0x210b] = "ACK_SD_REC_DEL",
	[0x210c] = "ACK_SD_PIC_DEL",
	[0x210d] = "ACK_SD_SPL_DEL",
	[0x3000] = "CMD_PEER_LIVEAUDIO_START",
	[0x3001] = "CMD_PEER_LIVEAUDIO_STOP",
	[0x3002] = "CMD_LOCAL_LIVEAUDIO_START",
	[0x3003] = "CMD_LOCAL_LIVEAUDIO_STOP",
	[0x3004] = "CMD_PEER_AUDIOPARAM_SET",
	[0x3005] = "CMD_PEER_AUDIOPARAM_GET",
	[0x3006] = "CMD_PEER_AUDIOFILE_STARTPLAY",
	[0x3007] = "CMD_PEER_AUDIOFILE_STOPPLAY",
	[0x3008] = "CMD_PEER_AUDIOFILELIST_GET",
	[0x300a] = "CMD_PEER_IRCUT_ONOFF",
	[0x300b] = "CMD_PEER_LIGHTFILL_ONOFF",
	[0x3010] = "CMD_PEER_LIVEVIDEO_START",
	[0x3011] = "CMD_PEER_LIVEVIDEO_STOP",
	[0x3012] = "CMD_PEER_PLAYBACK_START",
	[0x3013] = "CMD_PEER_PLAYBACK_STOP",
	[0x3014] = "CMD_PEER_PLAYBACK_SEEK",
	[0x3015] = "CMD_PEER_PLAYBACK_SPEED",
	[0x3016] = "CMD_PEER_PLAYBACK_PAUSE",
	[0x3017] = "CMD_PEER_PLAYBACK_RESUME",
	[0x3018] = "CMD_PEER_VIDEOPARAM_SET",
	[0x3019] = "CMD_PEER_VIDEOPARAM_GET",
	[0x301a] = "CMD_SNAPSHOT_GET",
	[0x301b] = "CMD_PEER_PLAYBACK_END",
	[0x301c] = "CMD_PEER_PLAYBACK_STEP",
	[0x3020] = "CMD_DOORBELL_CALL_OPEN",
	[0x3021] = "CMD_DOORBELL_CALL_CLOSE",
	[0x3022] = "CMD_DOORBELL_CALL_ACCEPT",
	[0x3023] = "CMD_DOORBELL_CALL_REJECT",
	[0x3024] = "CMD_LOCAL_LIVEVIDIO_SEND_ON",
	[0x3025] = "CMD_LOCAL_LIVEVIDIO_SEND_OFF",
	[0x3026] = "CMD_LOCAL_AUDIO_STATUS_SET",
	[0x3027] = "CMD_LOCAL_AUDIO_STATUS_GET",
	[0x3028] = "CMD_LOCAL_AVREC_START",
	[0x3029] = "CMD_LOCAL_AVREC_STOP",
	[0x3030] = "CMD_LOCAL_PLAYBACK_START",
	[0x3031] = "CMD_LOCAL_PLAYBACK_STOP",
	[0x3032] = "CMD_LOCAL_PLAYBACK_SEEK",
	[0x3033] = "CMD_LOCAL_PLAYBACK_PAUSE",
	[0x3034] = "CMD_LOCAL_PLAYBACK_RESUME",
	[0x3035] = "CMD_LOCAL_PLAYBACK_START1",
	[0x3036] = "CMD_LOCAL_PLAYBACK_STEP",
	[0x3037] = "CMD_LOCAL_PLAYBACK_START2",
	[0x3040] = "CMD_LOCAL_MJREC_START",
	[0x3041] = "CMD_LOCAL_MJREC_STOP",
	[0x3100] = "ACK_PEER_LIVEAUDIO_START",
	[0x3101] = "ACK_PEER_LIVEAUDIO_STOP",
	[0x3102] = "ACK_LOCAL_LIVEAUDIO_START",
	[0x3103] = "ACK_LOCAL_LIVEAUDIO_STOP",
	[0x3104] = "ACK_PEER_AUDIOPARAM_SET",
	[0x3105] = "ACK_PEER_AUDIOPARAM_GET",
	[0x3106] = "ACK_PEER_AUDIOFILE_STARTPLAY",
	[0x3107] = "ACK_PEER_AUDIOFILE_STOPPLAY",
	[0x3108] = "ACK_PEER_AUDIOFILELIST_GET",
	[0x310a] = "ACK_PEER_IRCUT_ONOFF",
	[0x310b] = "ACK_PEER_LIGHTFILL_ONOFF",
	[0x3110] = "ACK_PEER_LIVEVIDEO_START",
	[0x3111] = "ACK_PEER_LIVEVIDEO_STOP",
	[0x3112] = "ACK_PEER_PLAYBACK_START",
	[0x3113] = "ACK_PEER_PLAYBACK_STOP",
	[0x3114] = "ACK_PEER_PLAYBACK_SEEK",
	[0x3115] = "ACK_PEER_PLAYBACK_SPEED",
	[0x3116] = "ACK_PEER_PLAYBACK_PAUSE",
	[0x3117] = "ACK_PEER_PLAYBACK_RESUME",
	[0x3118] = "ACK_PEER_VIDEOPARAM_SET",
	[0x3119] = "ACK_PEER_VIDEOPARAM_GET",
	[0x311a] = "ACK_SNAPSHOT_GET",
	[0x311b] = "ACK_PEER_PLAYBACK_END",
	[0x311c] = "ACK_PEER_PLAYBACK_STEP",
	[0x4000] = "CMD_FILE_CTRL",
	[0x4005] = "CMD_FILETRANSFER_FILELIST_GET",
	[0x4010] = "CMD_LOCALPATH",
	[0x4101] = "ACK_FILE_CREATE",
	[0x4102] = "ACK_FILE_RENAME",
	[0x4103] = "ACK_FILE_DELETE",
	[0x4104] = "ACK_FILE_MOVE",
	[0x4105] = "ACK_FILE_LIST",
	[0x4110] = "ACK_FILE_DOWNLOAD",
	[0x4111] = "ACK_FILE_DOWNLOAD_PAUSE",
	[0x4112] = "ACK_FILE_DOWNLOAD_RESUME",
	[0x4113] = "ACK_FILE_DOWNLOAD_CANCEL",
	[0x4120] = "ACK_FILE_UPLOAD",
	[0x4121] = "ACK_FILE_UPLOAD_PAUSE",
	[0x4122] = "ACK_FILE_UPLOAD_RESUME",
	[0x4123] = "ACK_FILE_UPLOAD_CANCEL",
	[0x50ff] = "CMD_PASSTHROUGH_STRING_PUT",
	[0x51ff] = "ACK_PASSTHROUGH_STRING_PUT",
	[0x55fe] = "CMD_SESSION_CHECK",
	[0x6001] = "CB_IEGET_STATUS",
	[0x6001] = "CMD_NET_WIFISETTING_SET",
	[0x6002] = "CB_IEGET_PARAM",
	[0x6002] = "CMD_NET_WIFISETTING_GET",
	[0x6003] = "CB_IEGET_CAM_PARAMS",
	[0x6003] = "CMD_NET_WIFI_SCAN",
	[0x6004] = "CB_IEGET_LOG",
	[0x6004] = "CMD_NET_WIREDSETTING_SET",
	[0x6005] = "CB_IEGET_MISC",
	[0x6005] = "CMD_NET_WIREDSETTING_GET",
	[0x6006] = "CB_IEGET_RECORD",
	[0x6007] = "CB_IEGET_RECORD_FILE",
	[0x6008] = "CB_IEGET_WIFI_SCAN",
	[0x6009] = "CB_IEGET_FACTORY",
	[0x600a] = "CB_IESET_IR",
	[0x600b] = "CB_IESET_UPNP",
	[0x600c] = "CB_IESET_ALARM",
	[0x600d] = "CB_IESET_LOG",
	[0x600e] = "CB_IESET_USER",
	[0x600f] = "CB_IESET_ALIAS",
	[0x6010] = "CB_IESET_MAIL",
	[0x6011] = "CB_IESET_WIFI",
	[0x6012] = "CB_CAM_CONTROL",
	[0x6013] = "CB_IESET_DATE",
	[0x6014] = "CB_IESET_MEDIA",
	[0x6015] = "CB_IESET_SNAPSHOT",
	[0x6016] = "CB_IESET_DDNS",
	[0x6017] = "CB_IESET_MISC",
	[0x6018] = "CB_IEGET_FTPTEST",
	[0x6019] = "CB_DECODER_CONTROL",
	[0x601a] = "CB_IESET_DEFAULT",
	[0x601b] = "CB_IESET_MOTO",
	[0x601c] = "CB_IEGET_MAILTEST",
	[0x601d] = "CB_IESET_MAILTEST",
	[0x601e] = "CB_IEDEL_FILE",
	[0x601f] = "CB_IELOGIN",
	[0x6020] = "CB_IESET_DEVICE",
	[0x6021] = "CB_IESET_NETWORK",
	[0x6022] = "CB_IESET_FTPTEST",
	[0x6023] = "CB_IESET_DNS",
	[0x6024] = "CB_IESET_OSD",
	[0x6025] = "CB_IESET_FACTORY",
	[0x6026] = "CB_IESET_PPPOE",
	[0x6027] = "CB_IEREBOOT",
	[0x6028] = "CB_IEFORMATSD",
	[0x6029] = "CB_IESET_RECORDSCH",
	[0x602a] = "CB_IESET_WIFISCAN",
	[0x602b] = "CB_IERESTORE",
	[0x602c] = "CB_IESET_FTP",
	[0x602d] = "CB_IESET_RTSP",
	[0x602e] = "CB_IEGET_VIDEOSTREAM",
	[0x602f] = "CB_UPGRADE_APP",
	[0x6030] = "CB_UPGRADE_SYS",
	[0x6031] = "CB_SET_IIC",
	[0x6032] = "CB_GET_IIC",
	[0x6033] = "CB_IEGET_ALARMLOG",
	[0x6034] = "CB_IESET_ALARMLOGCLR",
	[0x6035] = "CB_IEGET_SYSWIFI",
	[0x6036] = "CB_IESET_SYSWIFI",
	[0x6037] = "CB_IEGET_LIVESTREAM",
	[0x6040] = "CB_NOTIFICATION",
	[0x6053] = "CB_IEGET_BILL",
	[0x6054] = "CB_APP_VERSION",
	[0x60a0] = "CB_CHECK_USER",
	[0x60a1] = "CB_IESET_BILL",
	[0x6101] = "ACK_NET_WIFISETTING_SET",
	[0x6102] = "ACK_NET_WIFISETTING_GET",
	[0x6103] = "ACK_NET_WIFI_SCAN",
	[0x6104] = "ACK_NET_WIREDSETTING_SET",
	[0x6105] = "ACK_NET_WIREDSETTING_GET",
	[0x7000] = "CMD_FRIEND_MSG",
	[0x99f0] = "CB_SET_P2PPARAM",
	[0x99fe] = "CB_GET_SYSOPR",
	[0x99ff] = "CB_SET_SYSOPR",
	[0xf000] = "CMD_LOCAL_SESSION_INF",
	[0xf001] = "CMD_LOCAL_SESSION_CHECK",
	[0xf002] = "CMD_LOCAL_SESSION_GET",
	[0xf003] = "CMD_LOCAL_SESSION_CTRL",
	[0xf004] = "CMD_LOCAL_REC_START",
	[0xf005] = "CMD_LOCAL_REC_STOP",
	[0xf006] = "CMD_LOCAL_REC_MERGECTRL",
	[0xf007] = "CMD_LOCAL_P2P_START",
	[0xf008] = "CMD_LOCAL_P2P_STOP",
	[0xf00f] = "CMD_SESSION_CLOSE",
	[0xf010] = "CMD_LOCAL_PUSH_STRING",
	[0xf011] = "CMD_LOCAL_PUSH_CFG",
	[0xf012] = "CMD_LOCAL_RCVVID_DEC",
	[0xf021] = "CMD_LOCAL_LAPSED",
	[0xff01] = "CB_SET_SINGLE_SETTING_DEFAULT",
	[0xff10] = "CB_GET_FILE",
	[0xff11] = "CB_PUT_FILE",
	[0xff12] = "CB_SET_FILE",
	[0xff13] = "CB_GET_FILELIST",
	[0xff14] = "CB_SET_GPIO",
	[0xff15] = "CB_GET_GPIO",
	[0xff16] = "CB_GET_ADC",
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
		local b_payload_len = buffer(0xc, 2)
		local payload_len = buffer(0xc, 2):le_uint()

		if not is_data_packet then
			subtree:add_le(ilnk_proto.fields.start, buffer(8, 2))
			subtree:add_le(ilnk_proto.fields.cmd, buffer(0xa, 2))
			local cmdname = control_lut[buffer(0xa, 2):le_uint()] or "UNK"
			pinfo.cols.info:set(cmdname)
			subtree:add(ilnk_proto.fields.cmd_name,  cmdname):set_generated()
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
