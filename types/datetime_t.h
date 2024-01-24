struct datetime_t {
	uint32_t now; // the code to _write_ these uses long ))
	uint32_t tz;
	uint32_t ntp_enable;
	uint32_t daylight;
	char ntp_ser[64];
};
