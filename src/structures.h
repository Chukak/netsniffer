#ifndef __STRUCTURES_H
#define __STRUCTURES_H

#include <stdint.h>

#ifdef __linux__
#include <netinet/ip.h>
#elif _WIN32
#include <winsock2.h>
#endif

#ifndef NETSNIFFER_STRUCTURES_VERBOSE
#define __HIDE_FIELD(f) __##f
#else
#define __HIDE_FIELD(f) f
#endif

#define IFACE_MAX_SIZE 24
#define IP_MAX_SIZE 16
#define ETH_MAX_PACKET_SIZE 65536
#define ADDRESS_MAX_SIZE IP_MAX_SIZE + 1 /*:*/ + 4 /* port */

/**
 * @brief Protocol_t
 * Implements a protocol number values.
 */
typedef enum
{
  Protocol_ANY = 0,
  Protocol_ICMP = IPPROTO_ICMP,
  Protocol_TCP = IPPROTO_TCP,
  Protocol_UDP = IPPROTO_UDP
} Protocol_t;

#ifndef _WIN32
/**
 * @brief ETHHeader_t
 * Ethernet header structure.
 */
typedef struct
{
  uint8_t DestinationAddressMac[6];
  uint8_t SourceAddressMac[6];
  uint16_t Protocol;
} ETHHeader_t;
#endif

/**
 * @brief IPHeader_t
 * IP header structure.
 */
typedef struct
{
  uint8_t HeaderLength : 4 /* 4 bits */;
  uint8_t Version : 4 /* 4 bits */;
  uint8_t __HIDE_FIELD(TOS);
  uint16_t TotalLength;
  uint16_t __HIDE_FIELD(ID);
  uint16_t __HIDE_FIELD(FragmentOffset);
  uint8_t TTL;
  uint8_t Protocol;
  uint16_t Checksum;
  uint32_t SourceAddress;
  uint32_t DestinationAddress;
} IPHeader_t;
/**
 * @brief ICMPHeader_t
 * ICMP header structure.
 */
typedef struct
{
  uint8_t Type;
  uint8_t Code;
  uint16_t Checksum;
  uint32_t RestOfHeader;
} ICMPHeader_t;
/**
 * @brief TCPHeader_t
 * TCP header structure.
 */
typedef struct
{
  uint16_t SourcePort;
  uint16_t DestinationPort;
  uint32_t SequenceNumber;
  uint32_t AckNumber;
  uint16_t __HIDE_FIELD(DataOffset);
  uint16_t __reserved1Part : 3 /* reserved 3 bits */;
  uint8_t __HIDE_FIELD(FlagNS) : 1;  /* 1 bit */
  uint8_t FlagFinish : 1;            /* 1 bit */
  uint8_t FlagSync : 1;              /* 1 bit */
  uint8_t FlagReset : 1;             /* 1 bit */
  uint8_t FlagAck : 1;               /* 1 bit */
  uint8_t FlagUrgent : 1;            /* 1 bit */
  uint8_t __HIDE_FIELD(FlagECE) : 1; /* 1 bit */
  uint8_t __HIDE_FIELD(FlagCWR) : 1; /* 1 bit */
  uint16_t WindowSize;
  uint16_t Checksum;
  uint16_t UrgentPoint;
} TCPV4Header_t;
/**
 * @brief UDPHeader_t
 * UDP header structure.
 */
typedef struct
{
  uint16_t SourcePort;
  uint16_t DestinationPort;
  uint16_t Length;
  uint16_t Checksum;
} UDPHeader_t;
/**
 * @brief Buffer_t
 */
typedef int8_t* Buffer_t;

#ifdef __linux__
/**
 * @brief GetETHHeader
 * This function is only available on linux.
 * @param buf The pointer to the network packet
 * @return A pointer to the ETH header structure.
 */
ETHHeader_t* GetETHHeader(Buffer_t);
/**
 * @brief GetETHHeaderLength
 * This function is only available on linux.
 * @return  A length of this ETH header.
 */
size_t GetETHHeaderLength();
#endif
/**
 * @brief GetIPHeader
 * @param buf The pointer to the network packet without the ETH header
 * @returns A pointer to the IP header structure.
 */
IPHeader_t* GetIPHeader(Buffer_t buf);
/**
 * @brief GetIPHeaderLength
 * @param hdr The pointer to the IP header object.
 * @returns A length of this IP header.
 */
size_t GetIPHeaderLength(IPHeader_t* hdr);
/**
 * @brief GetICMPHeader
 * @param buf The pointer to the network packet without the ETH header
 * @returns A pointer to the ICMP header structure.
 */
ICMPHeader_t* GetICMPHeader(Buffer_t buf);
/**
 * @brief GetTCPV4Header
 * @param buf The pointer to the network packet without the ETH header
 * @returns A pointer to the TCP header structure.
 */
TCPV4Header_t* GetTCPV4Header(Buffer_t buf);
/**
 * @brief GetUDPHeader
 * @param buf The pointer to the network packet without the ETH header
 * @returns A pointer to the UDP header structure.
 */
UDPHeader_t* GetUDPHeader(Buffer_t buf);
/**
 * @brief GetPacketData
 * Sets a pointer to the packet data. Stores an offset (IP header length + Protocol header length) to the second
 * argument.
 * @param buf The pointer to the network packet without the ETH header
 * @param offset The pointer to the offset variable
 * @returns The pointer to the packet data.
 */
Buffer_t GetPacketData(Buffer_t buf, size_t* offset);

/**
 * @brief Direction_t
 * Implements a network packet direction.
 */
typedef enum
{
  Direction_ANY = 0,
  Direction_SOURCE = 1,
  Direction_DESTINATION = 2
} Direction_t;

/**
 * @brief Address_t
 * Network address.
 */
typedef struct
{
  char IP[IP_MAX_SIZE];
  uint16_t Port;
} Address_t;

#define ADDRESSES_MAX_COUNT 20

/**
 * @brief Filter_t
 * Network filter.
 */
typedef struct
{
  Direction_t Direction;
  Protocol_t Protocol;
} Filter_t;
/**
 * @brief FilterInitDefaults
 * Initializes a Filter_t structure with default values.
 * @param f The pointer to the Filter_t structure.
 */
void FilterInitDefaults(Filter_t* f);

/**
 * @brief Timestamp_t
 * Stores information about time.
 */
typedef struct
{
  int Hours;
  int Minutes;
  int Seconds;
  int Milliseconds;
  time_t TimestampSec;
  uint32_t TimestampNanosec;
} TimeInfo_t;
/**
 * @brief GetTimeInfoNow
 * Gets the current time and stores it in the first argument (TimeInfo_t structure).
 * @param ti The pointer to the TimeInfo_t structure
 * @param error The error message (if occurred)
 * @return -1 if an error occurred, otherwise 0.
 */
int GetTimeInfoNow(TimeInfo_t* ti, char** error);
/**
 * @brief TimeInfoToString
 * Convert TimeInfo_t to a string.
 * @param ti The pointer to the TimeInfo_t structure
 * @param buffer The pointer to the result.
 */
void TimeInfoToString(TimeInfo_t* ti, char** buffer);

#endif // __STRUCTURES_H
