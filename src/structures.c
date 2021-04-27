#include "structures.h"
#include "utils.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#endif

#define TIME_INFO_BUFFER_MAX_SIZE 14
static const char* TIME_INFO_FORMAT = "%02d:%02d:%02d.%d";

#ifndef _WIN32
ETHHeader_t* GetETHHeader(Buffer_t buf)
{
  return (ETHHeader_t*) buf;
}

size_t GetETHHeaderLength()
{
  return sizeof(ETHHeader_t);
}
#endif

IPHeader_t* GetIPHeader(Buffer_t buf)
{
  return (IPHeader_t*) buf;
}

size_t GetIPHeaderLength(IPHeader_t* hdr)
{
  return (size_t)(hdr->HeaderLength * 4);
}

ICMPHeader_t* GetICMPHeader(Buffer_t buf)
{
  return (ICMPHeader_t*) (buf + GetIPHeaderLength(GetIPHeader(buf)));
}

TCPV4Header_t* GetTCPV4Header(Buffer_t buf)
{
  return (TCPV4Header_t*) (buf + GetIPHeaderLength(GetIPHeader(buf)));
}

UDPHeader_t* GetUDPHeader(Buffer_t buf)
{
  return (UDPHeader_t*) (buf + GetIPHeaderLength(GetIPHeader(buf)));
}

Buffer_t GetPacketData(Buffer_t buf, size_t* offset)
{
  IPHeader_t* iphdr = GetIPHeader(buf);
  *offset = GetIPHeaderLength(iphdr);
  switch (iphdr->Protocol) {
  case Protocol_ICMP:
    *offset += sizeof(ICMPHeader_t);
    break;
  case Protocol_TCP:
    *offset += sizeof(TCPV4Header_t);
    break;
  case Protocol_UDP:
    *offset += sizeof(UDPHeader_t);
    break;
  default:
    *offset = 0;
    break;
  }

  return buf + *offset;
}

void FilterInitDefaults(Filter_t* f)
{
  if (f == NULL)
    return;

  f->Direction = Direction_ANY;
  f->Protocol = Protocol_ANY;
}

int GetTimeInfoNow(TimeInfo_t* ti, char** error)
{
  if (ti == NULL)
    return -1;

#ifdef __linux__
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
    FormatStringBuffer(error, "Cannot get time: %s", GetLastErrorMessage());
    return -1;
  }

  ti->TimestampSec = now.tv_sec;
  ti->TimestampNanosec = (uint32_t) now.tv_nsec;

  struct tm buf;
  localtime_r(&now.tv_sec, &buf);

  ti->Hours = buf.tm_hour;
  ti->Minutes = buf.tm_min;
  ti->Seconds = buf.tm_sec;

  static const long l1e6 = 1000000;
  ti->Milliseconds = (int) (now.tv_nsec / l1e6);

#elif _WIN32
  static ULARGE_INTEGER unixtime;
  if (unixtime.QuadPart == 0) {
    FILETIME ft;
    SYSTEMTIME st = {1970, 1, 0, 1, 0, 0, 0, 0};
    SystemTimeToFileTime(&st, &ft);

    unixtime.LowPart = ft.dwLowDateTime;
    unixtime.HighPart = ft.dwHighDateTime;
  }

  FILETIME fileTimeNow;
  {
    FILETIME fileTimeNowUtc;
    GetSystemTimeAsFileTime(&fileTimeNowUtc);
    if (FileTimeToLocalFileTime(&fileTimeNowUtc, &fileTimeNow) == 0) {
      FormatStringBuffer(error, "Cannot get a local time: %s", GetLastErrorMessage());
      return -1;
    }
  }

  ULARGE_INTEGER now;
  {
    now.LowPart = fileTimeNow.dwLowDateTime;
    now.HighPart = fileTimeNow.dwHighDateTime;

    now.QuadPart -= unixtime.QuadPart;
  }

  static const uint32_t ul1e7 = 10000000;
  ti->TimestampSec = (time_t)(now.QuadPart / ul1e7);
  ti->TimestampNanosec = (uint32_t)(now.QuadPart % ul1e7);

  SYSTEMTIME systemTimeNow;
  if (FileTimeToSystemTime(&fileTimeNow, &systemTimeNow) == 0) {
    FormatStringBuffer(error, "Cannot get a system time: %s", GetLastErrorMessage());
    return -1;
  }

  ti->Hours = systemTimeNow.wHour;
  ti->Minutes = systemTimeNow.wMinute;
  ti->Seconds = systemTimeNow.wSecond;
  ti->Milliseconds = systemTimeNow.wMilliseconds;
#endif

  return 0;
}

void TimeInfoToString(TimeInfo_t* ti, char** buffer)
{
  *buffer = malloc(sizeof(char) * TIME_INFO_BUFFER_MAX_SIZE);
  ASSERT("Cannot initialize a new string: realloc returned 'NULL'.", *buffer != NULL);

  snprintf(*buffer, TIME_INFO_BUFFER_MAX_SIZE, TIME_INFO_FORMAT, ti->Hours, ti->Minutes, ti->Seconds, ti->Milliseconds);
}
