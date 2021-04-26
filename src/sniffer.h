#ifndef __SNIFFER_H
#define __SNIFFER_H

#include "structures.h"

#define SOCKET_WAITING_TIMEOUT_MS 1000

typedef void* HandlerArgs_t;
typedef void (*ProcessingPacketHandler_t)(void*, Buffer_t, size_t, HandlerArgs_t);
/**
 * @brief Sniffer_t
 * Implements a sniffer object on specified address.
 */
typedef struct
{
  uint64_t SniffStart;                      //! Sniffer start timestamp (not used, always non-initialized)
  uint64_t SniffEnd;                        //! Sniffer end timestamp (not used, always non-initialized)
  Address_t Addresses[ADDRESSES_MAX_COUNT]; //! Addresses in the format 'IP:PORT'
  uint16_t AddressesCount;                  //! Addresses count
  char Interface[IFACE_MAX_SIZE];           //! Interface name (On Windows this field is interface index )
  Protocol_t Protocol;                      //! Protocol number value
  uint32_t RecvCount;                       //! Number of received packets
  uint32_t SentCount;                       //! NUmber of sent packets
  char* ErrorMessage;                       //! Error messages
#ifdef __linux__
  int __sock;
#elif _WIN32
  SOCKET __sock;
  WSADATA __wsadata;
#endif
  int __ifindex;
  char __bindIP[IP_MAX_SIZE];
  Buffer_t __buf;
  ProcessingPacketHandler_t __handler;
  HandlerArgs_t __args;
  int8_t __running;
} Sniffer_t;

/**
 * @brief SnifferInit
 * Initializates values for the new sniffer object.
 * @param s The pointer to the sniffer object
 * @param p Protocol number value
 * @param iface Interface (on Windows this parameter is interface index as string)
 * @param handler Handler to processing network packets
 * @param args Handler arguments.
 * @returns -1 if an error occurred, otherwise 0.
 */
int SnifferInit(Sniffer_t* s, Protocol_t p, const char* iface, ProcessingPacketHandler_t handler, HandlerArgs_t args);
/**
 * @brief SnifferAddAddress
 * Adds the new address for sniffing network packets. The address must be in the format "IP\:PORT".
 * @param s The pointer to the sniffer object
 * @param addr The new address in the format "IP\:PORT"
 * @returns -1 if an error occurred, otherwise 0.
 */
int SnifferAddAddress(Sniffer_t*, const char* addr);
/**
 * @brief SnifferStart
 * Starts sniffing network packets. This function will be block the current thread on SOCKET_WAITING_TIMEOUT_MS.
 * @param s The pointer to the sniffer object
 * @return -1 if an error occurred, otherwise 0.
 */
int SnifferStart(Sniffer_t* s);
/**
 * @brief SnifferProcessNextPacket
 * Processes the next intercepted packet from socket. Calls the user-defined handler with this packet.
 * Also, all packets will be filtered in this function by the address (IP, port).
 * @param s The pointer to the sniffer object
 * @return -1 if an error occurred, otherwise 0.
 */
int SnifferProcessNextPacket(Sniffer_t* s);
/**
 * @brief SnifferStop
 * Stops sniffing network packets.
 * @param s The pointer to the sniffer object
 * @return -1 if an error occurred, otherwise 0.
 */
int SnifferStop(Sniffer_t* s);
/**
 * @brief SnifferClear
 * Clears the passed sniffer object.
 * @param s The pointer to the sniffer object
 */
void SnifferClear(Sniffer_t* s);

#endif // __SNIFFER_H
