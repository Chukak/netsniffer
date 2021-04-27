#include "testing.h"
#include "structures.h"

#ifdef __linux__
#include <time.h>
#elif _WIN32
#include <Windows.h>
#endif
#include <stdlib.h>

TEST_CASE(TestStructures, GetTimeInfoNow)
{
  TimeInfo_t ti;
  char* error = NULL;

#ifdef __linux__
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

  struct tm buf;
  localtime_r(&now.tv_sec, &buf);

  TEST_ASSERT(GetTimeInfoNow(&ti, &error) == 0, "GetTimeInfoNow(..) < 0.");
  TEST_ASSERT(ti.Hours == buf.tm_hour, "TimeInfo_t: invalid hours.");
  TEST_ASSERT(ti.Minutes == buf.tm_min, "TimeInfo_t: invalid minutes.");
  TEST_ASSERT(ti.Seconds == buf.tm_sec, "TimeInfo_t: invalid seconds.");

#elif _WIN32
  SYSTEMTIME st;
  GetLocalTime(&st);

  TEST_ASSERT(GetTimeInfoNow(&ti, &error) == 0, "GetTimeInfoNow(..) < 0.");
  TEST_ASSERT(ti.Hours == st.wHour, "TimeInfo_t: invalid hours.");
  TEST_ASSERT(ti.Minutes == st.wMinute, "TimeInfo_t: invalid minutes.");
  TEST_ASSERT(ti.Seconds == st.wSecond, "TimeInfo_t: invalid seconds.");

#endif

  free(error);
}
