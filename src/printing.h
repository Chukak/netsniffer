#ifndef __PRINTING_H
#define __PRINTING_H

#include "structures.h"

#ifndef _WIN32
#define ETH_HEADER_BUFFER_SUFFICIENT_SIZE 256
#endif
#define IP_HEADER_BUFFER_SUFFICIENT_SIZE 512
#define PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE 512
#define DATA_BUFFER_SUFFICIENT_SIZE (65536 - 512) * 2 /* brackets */ + ((65536 - 512) / 3) /* spaces and breaks */

/**
 * @brief PacketBuffers_t
 * Implemets buffers to store formatted output from network packets.
 */
typedef struct
{
  char* IPHeaderBuffer;
  char* ProtocolHeaderBuffer;
  char* DataBuffer;
} PacketBuffers_t;

/**
 * @brief PacketBuffersInit
 * Initializes values for the new buffers object.
 * @param p
 */
void PacketBuffersInit(PacketBuffers_t* p);
/**
 * @brief PacketBuffersDelete
 * Clear the passed buffers object.
 * @param p
 */
void PacketBuffersDelete(PacketBuffers_t* p);

/**
 * @brief PrintPacketToBuffers
 * Prints the received network packet to the buffer. It the third argument is NULL, the result will not contain the time
 * in the IP header.
 * @param packetBuffer The network packet without the ETH header
 * @param size Packet size
 * @param buffers The pointer to buffers (PacketBuffers_t*)
 * @param t The pointer to the TimeInfo_t
 */
void PrintPacketToBuffers(Buffer_t packetBuffer, size_t size, PacketBuffers_t* buffers, TimeInfo_t* t);
#ifndef _WIN32
/**
 * @brief PrintPacketETHHeader
 * Prints the ETH header of this packet. But, useful to use the PrintPacketBuffers() function instead of it.
 * This function is only available on linux.
 * @param packetBuffer The network packet
 * @param ethHeaderBuffer The pointer to the buffer for the ETH header part of this packet
 * @param ethHeaderBufferSize The size of ETH header buffer
 */
void PrintPacketETHHeader(Buffer_t packetBuffer, char** ethHeaderBuffer, size_t ethHeaderBufferSize);
#endif
/**
 * @brief PrintPacketIPHeader
 * Prints the IP header of this packet. But, useful to use the PrintPacketBuffers() function instead of it. It the third
 * argument is NULL, the result will not contain the time in the IP header.
 * @param packetBuffer The network packet without the ETH header
 * @param ipHeaderBuffer The pointer to the buffer for the IP header part of this packet
 * @param ipHeaderBufferSize The size of IP header buffer
 * @param t The pointer to the TimeInfo_t
 */
void PrintPacketIPHeader(Buffer_t packetBuffer, char** ipHeaderBuffer, size_t ipHeaderBufferSize, TimeInfo_t* t);
/**
 * @brief PrintPacketICMPHeader
 * Prints the ICMP header of this packet. But, useful to use the PrintPacketBuffers() function instead of it.
 * @param packetBuffer The network packet without the ETH header
 * @param headerBuffer The pointer to the buffer for the ICMP header part of this packet
 * @param headerBufferSize The size of the protocol header buffer
 */
void PrintPacketICMPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize);
/**
 * @brief PrintPacketTCPHeader
 * Prints the TCP header of this packet. But, useful to use the PrintPacketBuffers() function instead of it.
 * @param packetBuffer The network packet without the ETH header
 * @param headerBuffer The pointer to the buffer for the TCP header part of this packet
 * @param headerBufferSize The size of the protocol header buffer
 */
void PrintPacketTCPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize);
/**
 * @brief PrintPacketUDPHeader
 * Prints the UDP header of this packet. But, useful to use the PrintPacketBuffers() function instead of it.
 * @param packetBuffer The network packet without the ETH header
 * @param headerBuffer The pointer to the buffer for the UDP header part of this packet
 * @param headerBufferSize The size of the protocol header buffer
 */
void PrintPacketUDPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize);
/**
 * @brief PrintPacketData
 * Prints the data of this packet. But, useful to use the PrintPacketBuffers() function instead of it.
 * @param packetBuffer The network packet without the ETH header
 * @param size Size of the data part of this packet
 * @param dataBuffer The pointer to the buffer for the data of this packet
 * @param dataBufferSize The size of the data buffer
 */
void PrintPacketData(Buffer_t packetBuffer, size_t size, char** dataBuffer, size_t dataBufferSize);

#endif // __PRINTING_H
