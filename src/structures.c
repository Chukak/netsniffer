#include "structures.h"

#include <string.h>

static const char* ProtocolStringICMP = "ICMP";
static const char* ProtocolStringTCPV4 = "TCP";
static const char* ProtocolStringUDP = "UDP";

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

Protocol_t GetProtocolFromString(const char* s)
{
  if (strcmp(s, ProtocolStringICMP) == 0)
    return Protocol_ICMP;
  if (strcmp(s, ProtocolStringTCPV4) == 0)
    return Protocol_TCP;
  if (strcmp(s, ProtocolStringUDP) == 0)
    return Protocol_UDP;

  return Protocol_ANY;
}
