#include "config.h" 
#include "szarp_base_common/time.h" 

time_t
szb_move_time(time_t t, int count, SZARP_PROBE_TYPE probe_type, int custom_length)
{
	struct tm tm;
#ifndef HAVE_LOCALTIME_R
	struct tm *ptm;
#endif
	if (t <= 0)
		return -1;
	if ( (probe_type == PT_CUSTOM) && (custom_length <= 0) )
		return -1;
	
	switch (probe_type) {
		case PT_CUSTOM :
			return (t + custom_length * count);
		case PT_MIN10 :
			return (t + (count * 600 ));
		case PT_SEC10 :
			return (t + (count * 10 ));
		case PT_HOUR :
			return (t + (count * 3600));
		case PT_HOUR8 :
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof(struct tm));
#else
			localtime_r(&t, &tm);
#endif
			tm.tm_hour += count * 8;
			tm.tm_isdst = -1;
			return mktime(&tm);
		case PT_DAY :
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof(struct tm));
#else
			localtime_r(&t, &tm);
#endif
			tm.tm_mday += count;
			tm.tm_isdst = -1;
			return mktime(&tm);
		case PT_WEEK :
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof(struct tm));
#else
			localtime_r(&t, &tm);
#endif
			tm.tm_mday += count * 7;
			tm.tm_isdst = -1;
			return mktime(&tm);
		case PT_MONTH :
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof(struct tm));
#else
			localtime_r(&t, &tm);
#endif
			tm.tm_mon += count;
			tm.tm_isdst = -1;
			return mktime(&tm);
		case PT_YEAR :
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof(struct tm));
#else
			localtime_r(&t, &tm);
#endif
			tm.tm_year += count;
			tm.tm_isdst = -1;
			return mktime(&tm);
	}
	return -1;
}

