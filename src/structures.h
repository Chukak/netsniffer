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

#define IP_MAX_SIZE 15
#define ETH_MAX_PACKET_SIZE 65536

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

#ifndef _WIN32
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
 * @brief GetProtocolFromString
 * @return A Protocol_t value.
 */
Protocol_t GetProtocolFromString(const char* s);

#endif // __STRUCTURES_H