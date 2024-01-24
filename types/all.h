struct avparamset_t {
	uint32_t paramType;
	uint32_t paramValue;
};
struct datetime_t {
	uint32_t now; // the code to _write_ these uses long ))
	uint32_t tz;
	uint32_t ntp_enable;
	uint32_t daylight;
	char ntp_ser[64];
};
struct devuser_t {
	char account[0x20];
	char password[0x80];
};

struct fileinfo_t {
	uint32_t offset;
	char filename[0x100];
};
struct opr_t {
	uint8_t wakeupFixMin;
    uint8_t wakeupFixSec;
    uint8_t timedSleepEnable;
    uint8_t timedWakeUpEnable;
    uint8_t sleepRegularity;
    uint8_t sleepHour;
    uint8_t sleepMinute;
    uint8_t sleepSecond;
    uint8_t wakeupRegularity;
    uint8_t wakeupHour;
    uint8_t wakeupMinute;
    uint8_t wakeupSecond;
    uint8_t rcdPicEnable;
    uint8_t rcdPicEvent;
    uint8_t rcdPicSize;
    uint8_t rcdPicInterval;
    uint8_t rcdAvEnable;
    uint8_t rcdAvEvent;
    uint8_t rcdAvSize;
    uint8_t rcdAvTime;
    uint8_t pirLevel;
    uint8_t language;
    uint8_t pushEnable;
    uint8_t vidScale;
    uint8_t sleepEnable;
    uint8_t wakeupEnable;
    uint8_t apSleepEnable;
    uint8_t waitConnTime;
    uint8_t mcuFun;
    uint8_t pushInterval;
    uint8_t vidScaleCX;
    uint8_t vidScaleCY;
};

struct sysopr_t {
    uint8_t adcChkInterval;
    uint8_t gpioChkInterval;
    uint8_t sleepEnable;
    uint8_t wakeupEnable;
    uint8_t sleepRegularity;
    uint8_t sleepHour;
    uint8_t sleepMinute;
    uint8_t sleepSecond;
    uint8_t wakeupRegularity;
    uint8_t wakeupHour;
    uint8_t wakeupMinute;
    uint8_t wakeupSecond;
    uint8_t rcdPicEnable;
    uint8_t rcdPicEvent;
    uint8_t rcdPicSize;
    uint8_t rcdPicInterval;
    uint8_t rcdAvEnable;
    uint8_t rcdAvEvent;
    uint8_t rcdAvSize;
    uint8_t rcdAvTime;
    uint8_t pushEnable;
    uint8_t alarmEnable;
    uint8_t wifiEnable;
    uint8_t ircut;
};
