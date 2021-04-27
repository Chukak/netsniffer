#include "sniffer.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_packet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <unistd.h>
#include <errno.h>
#elif _WIN32
#include <ws2def.h>
#include <mstcpip.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

#ifdef __linux__
#define SOCKET_ERROR_CODE -1
static bool PromiscModeEnabled = false;
#elif _WIN32
#define SOCKET_ERROR_CODE SOCKET_ERROR
static int WSAIoctlEnableMode = 1;
static unsigned long WSAIoctlSupperss;
#endif

#define LOOPBACK_ADDRESS "127.0.0.1"

int SnifferInit(Sniffer_t* s, const char* iface, ProcessingPacketHandler_t handler, HandlerArgs_t args)
{
  if (s == NULL)
    return -1;

  for (int i = 0; i < ADDRESSES_MAX_COUNT; ++i) {
    s->Addresses[i].Address.IP[0] = '\0';
    s->Addresses[i].Address.Port = 0;
    FilterInitDefaults(&s->Addresses[i].Filter);
  }

  s->AddressesCount = 0;
  strncpy(s->Interface, iface, IFACE_MAX_SIZE);

  s->ErrorMessage = NULL;

#ifdef _WIN32
  if (WSAStartup(MAKEWORD(2, 2), &s->__wsadata) != NO_ERROR) {
    FormatStringBuffer(&s->ErrorMessage, "Failed to startup WinSock: %s", GetLastErrorMessage());
    return -1;
  }
#endif

#ifdef __linux__
  s->__sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s->__sock == -1) {
#elif _WIN32
  s->__sock = socket(AF_INET, SOCK_RAW, htons(IPPROTO_IP));
  if (s->__sock == INVALID_SOCKET) {
#endif
    FormatStringBuffer(&s->ErrorMessage, "Cannot create a socket: %s", GetLastErrorMessage());
    return -1;
  }

#ifdef __linux__
  {
    int flags;
    if ((flags = fcntl(s->__sock, F_GETFL, 0)) < 0) {
      FormatStringBuffer(&s->ErrorMessage, "Cannot get socket flags: %s", GetLastErrorMessage());
      return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s->__sock, F_SETFL, 0) < 0) {
      FormatStringBuffer(&s->ErrorMessage, "Cannot set socket flags: %s", GetLastErrorMessage());
      return -1;
    }
  }
  s->__promiscEnabled = false;
  s->ETHHeaderIncluded = false;
#elif _WIN32
  if (WSAIoctl(s->__sock,
               (DWORD) FIONBIO,
               &WSAIoctlEnableMode,
               sizeof(WSAIoctlEnableMode),
               NULL,
               0,
               &WSAIoctlSupperss,
               NULL,
               NULL) < 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot set socket flags: %s", GetLastErrorMessage());
    return -1;
  }
#endif

  s->__ifindex = 0;
  s->__bindIP[0] = '\0';

  s->__buf = malloc(ETH_MAX_PACKET_SIZE);
  ASSERT("Cannot initialize a new network buffer: malloc returned size '0'.", s->__buf != NULL);

  s->__handler = handler;
  s->__args = args;
  s->__running = 0;
  return 0;
}

int SnifferAddAddress(Sniffer_t* s, const char* addr, const Filter_t* filter)
{
  if (s == NULL)
    return -1;

  if (s->AddressesCount >= ADDRESSES_MAX_COUNT) {
    FormatStringBuffer(&s->ErrorMessage,
                       "Max addresses count %d (max value: %d).",
                       s->AddressesCount,
                       ADDRESSES_MAX_COUNT);
    return -1;
  }

  char* ip;
  int port;
  if (ParseAddressString(addr, &ip, &port, &s->ErrorMessage) < 0)
    return -1;

  int currentIndex = s->AddressesCount++;
  strncpy(s->Addresses[currentIndex].Address.IP, ip, IP_MAX_SIZE);
  s->Addresses[currentIndex].Address.Port = (uint16_t) port;
  if (filter != NULL)
    memcpy(&s->Addresses[currentIndex].Filter, filter, sizeof(Filter_t));

  free(ip);
  return 0;
}

int SnifferStart(Sniffer_t* s)
{
  if (s == NULL)
    return -1;

  void* sockAddress = NULL;
  socklen_t szSockAddress = 0;
#ifdef __linux__
  struct ifreq sockSettings = {0};

  if ((s->__ifindex = (int) if_nametoindex(s->Interface)) == 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot get interface (%s) index: %s", s->Interface, GetLastErrorMessage());
    return -1;
  }

  strncpy(sockSettings.ifr_name, s->Interface, IFNAMSIZ);
  sockSettings.ifr_ifindex = s->__ifindex;
  if (ioctl(s->__sock, SIOCGIFADDR, &sockSettings) < 0) {
    FormatStringBuffer(&s->ErrorMessage,
                       "Cannot get IP address of the interface (%s): %s",
                       s->Interface,
                       GetLastErrorMessage());
    return -1;
  }
  strncpy(s->__bindIP, inet_ntoa(((struct sockaddr_in*) &sockSettings.ifr_addr)->sin_addr), IP_MAX_SIZE);

  struct sockaddr_ll* ll = malloc(sizeof(struct sockaddr_ll));
  memset(ll, 0, sizeof(struct sockaddr_ll));
  ll->sll_family = AF_PACKET;
  ll->sll_protocol = htons(ETH_P_ALL);
  ll->sll_ifindex = s->__ifindex;

  sockAddress = ll;
  szSockAddress = sizeof(struct sockaddr_ll);
#elif _WIN32
  s->__ifindex = strtol(s->Interface, NULL, 10);
  if (s->__ifindex < 0) {
    FormatStringBuffer(&s->ErrorMessage, "Invalid interface index: %s.", s->Interface);
    return -1;
  }

  if (s->__ifindex == 0) {
    strncpy(s->__bindIP, LOOPBACK_ADDRESS, IP_MAX_SIZE);
  } else {
    PIP_ADAPTER_INFO adaptlist = malloc(sizeof(IP_ADAPTER_INFO)), adaptlistNext = NULL;
    ASSERT(("Cannot initialize a new network adapter information: malloc returned size '0'.", adaptlist != NULL));
    ULONG adaptlistBytes = sizeof(IP_ADAPTER_INFO);
    ULONG getAdaptListRetCode = NO_ERROR;
    do {
      getAdaptListRetCode = GetAdaptersInfo(adaptlist, &adaptlistBytes);

      switch (getAdaptListRetCode) {
      case ERROR_BUFFER_OVERFLOW: {
        FormatStringBuffer(&s->ErrorMessage, "GetInfoAdapters(..): Error allocating memore needed to call.");
        adaptlist = realloc(adaptlist, adaptlistBytes);
        ASSERT(("Cannot reinitialize a new network adapter information: malloc returned size '0'.", adaptlist != NULL));
        break;
      }
      case NO_ERROR:
        break;
      default: {
        FormatStringBuffer(&s->ErrorMessage, "GetInfoAdapters(..): %s.", GetLastErrorMessage());
        free(adaptlist);
        return -1;
      }
      }
    } while (getAdaptListRetCode != NO_ERROR);

    bool ifaceIpAddressFound = false;
    for (adaptlistNext = adaptlist; adaptlistNext != NULL; adaptlistNext = adaptlist->Next) {
      if ((DWORD) s->__ifindex == adaptlistNext->Index) {
        ifaceIpAddressFound = true;
        strncpy(s->__bindIP, adaptlistNext->IpAddressList.IpAddress.String, IP_MAX_SIZE);
        break;
      }
    }

    free(adaptlist);
    if (!ifaceIpAddressFound) {
      FormatStringBuffer(&s->ErrorMessage, "IP address for the interface index %s not found.", s->Interface);
      return -1;
    }
  }

  struct sockaddr_in* in = malloc(sizeof(struct sockaddr_in));
  memset(in, 0, sizeof(struct sockaddr_in));
  in->sin_family = AF_INET;
  in->sin_addr.s_addr = inet_addr(s->__bindIP);
  in->sin_port = 0;

  sockAddress = in;
  szSockAddress = sizeof(struct sockaddr_in);
#endif

  if (bind(s->__sock, (struct sockaddr*) sockAddress, szSockAddress) == SOCKET_ERROR_CODE) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot bind socket: %s", GetLastErrorMessage());
    free(sockAddress);
    return -1;
  }
  free(sockAddress);

#ifdef __linux__
  if (PromiscModeEnabled && !s->__promiscEnabled) {
    memset(&sockSettings, 0, sizeof(sockSettings));
    strncpy(sockSettings.ifr_name, s->Interface, IFNAMSIZ);
    sockSettings.ifr_ifindex = s->__ifindex;
    if (ioctl(s->__sock, SIOCGIFFLAGS, (char*) &sockSettings) < 0) {
      FormatStringBuffer(&s->ErrorMessage, "Cannot get socket mode: %s", GetLastErrorMessage());
      return -1;
    }

    if (!(sockSettings.ifr_flags & IFF_PROMISC)) {
      sockSettings.ifr_flags |= IFF_PROMISC;
      if (ioctl(s->__sock, SIOCSIFFLAGS, (char*) &sockSettings) < 0) {
        FormatStringBuffer(&s->ErrorMessage, "Cannot set socket mode: %s", GetLastErrorMessage());
        return -1;
      }
    }

    s->__promiscEnabled = true;
  }
#elif _WIN32
  if (WSAIoctl(s->__sock,
               SIO_RCVALL,
               &WSAIoctlEnableMode,
               sizeof(WSAIoctlEnableMode),
               NULL,
               0,
               &WSAIoctlSupperss,
               NULL,
               NULL) == SOCKET_ERROR) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot set socket mode: %s", GetLastErrorMessage());
    return -1;
  }
#endif
  s->__running = 1;

  return 0;
}

int SnifferProcessNextPacket(Sniffer_t* s)
{
  if (s == NULL)
    return -1;

  if (!s->__running) {
    FormatStringBuffer(&s->ErrorMessage, "This sniffer not started.");
    return -1;
  }

  memset(s->__buf, 0, ETH_MAX_PACKET_SIZE);

  fd_set input;
  FD_SET(s->__sock, &input);
  struct timeval timeout = {0, SOCKET_WAITING_TIMEOUT_MS};
  switch (select((int) s->__sock + 1, &input, NULL, NULL, &timeout)) {
  case -1: {
    FormatStringBuffer(&s->ErrorMessage, "select (..): %s", GetLastErrorMessage());
    return -1;
  }
  case 0:
    return 0;
  default: {
    if (FD_ISSET(s->__sock, &input) == 0)
      return 0;
  }
  }
#ifdef __linux__
  struct sockaddr_ll from;
#elif _WIN32
  struct sockaddr_in from;
  (void) from;
#endif
  socklen_t fromBytes = sizeof(from);

  int64_t recvBytes;
  if ((recvBytes =
           recvfrom(s->__sock, (char*) s->__buf, ETH_MAX_PACKET_SIZE, 0, (struct sockaddr*) &from, &fromBytes)) > 0) {
    do {
      Buffer_t buffer;
#ifdef __linux__
      buffer = s->__buf + GetETHHeaderLength(); // ETH_P_ALL
#elif _WIN32
      buffer = s->__buf
#endif
      IPHeader_t* iphdr = GetIPHeader(buffer);

      if (iphdr) {
        char sourceIP[IP_MAX_SIZE] = "\0", destIP[IP_MAX_SIZE] = "\0";
        {
          static struct sockaddr_in src, dst;
          memset(&src, 0, sizeof(src));
          memset(&dst, 0, sizeof(dst));
          src.sin_addr.s_addr = iphdr->SourceAddress;
          dst.sin_addr.s_addr = iphdr->DestinationAddress;

          strncpy(sourceIP, inet_ntoa(src.sin_addr), IP_MAX_SIZE);
          strncpy(destIP, inet_ntoa(dst.sin_addr), IP_MAX_SIZE);
        }

#ifdef __linux__
        // duplicate packets
        if (strcmp(sourceIP, destIP) == 0 && from.sll_pkttype == PACKET_OUTGOING)
          /*
           * It is the same packet.
           */
          break;

        if (from.sll_pkttype == PACKET_OUTGOING && strcmp(s->__bindIP, sourceIP) != 0)
          /*
           * If this packet has type == PACKET_OUTGOING, the bind IP should be equals to source IP! Otherwise, may be it
           * is duplicate (from localhost to localhost, 127.0.0.2 -> 127.0.0.1).
           */
          break;

        if (from.sll_pkttype == PACKET_HOST && strcmp(s->__bindIP, destIP) != 0)
          /*
           * If this packet has type == PACKET_HOST, the bind IP shoul be equals to destination IP!
           */
          break;
#endif

        int sourcePort = 0, destPort = 0;
        {
          switch (iphdr->Protocol) {
          case Protocol_TCP: {
            TCPV4Header_t* tcphdr = GetTCPV4Header(buffer);
            sourcePort = ntohs(tcphdr->SourcePort);
            destPort = ntohs(tcphdr->DestinationPort);
            break;
          }
          case Protocol_UDP: {
            UDPHeader_t* udphdr = GetUDPHeader(buffer);
            sourcePort = htons(udphdr->SourcePort);
            destPort = htons(udphdr->DestinationPort);
            break;
          }
          default:
            break;
          }
        }

        bool addrFound = false;
        for (int i = 0; i < s->AddressesCount; ++i) {
          if (s->Addresses[i].Filter.Protocol != iphdr->Protocol && s->Addresses[i].Filter.Protocol != Protocol_ANY)
            continue;

          if (s->Addresses[i].Filter.Direction == Direction_ANY ||
              s->Addresses[i].Filter.Direction == Direction_SOURCE) {
            if (( // if specified any address, ip was found. We received any packet with any direction
                    (strcmp(s->Addresses[i].Address.IP, "any") == 0) //
                    || // compare source ip with the specified ip, find direction
                    (strcmp(s->Addresses[i].Address.IP, sourceIP) == 0))
                // compare the source port and the specified port
                && (s->Addresses[i].Address.Port == 0 || s->Addresses[i].Address.Port == sourcePort)) //
            {
              addrFound = true;
              break;
            }
          }

          if (s->Addresses[i].Filter.Direction == Direction_ANY ||
              s->Addresses[i].Filter.Direction == Direction_DESTINATION) {
            if (( // if specified any address, ip was found. We received any packet with any direction
                    (strcmp(s->Addresses[i].Address.IP, "any") == 0) //
                    || // compare dest ip with the specified ip, find direction
                    (strcmp(s->Addresses[i].Address.IP, destIP) == 0))
                // compare the destination port and the specified port
                && (s->Addresses[i].Address.Port == 0 || s->Addresses[i].Address.Port == destPort)) //
            {
              addrFound = true;
              break;
            }
          }
        }

        if (!addrFound)
          break;

        if (s->__handler) {
          TimeInfo_t tinfo;
          GetTimeInfoNow(&tinfo, &s->ErrorMessage);

#ifdef __linux__
          if (s->ETHHeaderIncluded)
            buffer = s->__buf;
#endif
          s->__handler(s, buffer, (size_t) recvBytes, tinfo, s->__args);
        } else {
          FormatStringBuffer(&s->ErrorMessage, "Handler to processing network packets == 'NULL'.");
          return -1;
        }

        memset(s->__buf, 0, ETH_MAX_PACKET_SIZE);
      }
    } while (0);
  }

  if (s->__running && recvBytes < 0 && errno != EAGAIN /* finish timeout */
      && errno != EWOULDBLOCK) {
    FormatStringBuffer(&s->ErrorMessage, "recvfrom(..): %s", GetLastErrorMessage());
    return -1;
  }
  return 0;
}

int SnifferIncludeETHHeader(Sniffer_t* s, bool inc)
{
  if (s == NULL)
    return -1;

  if (!s->__running)
    s->ETHHeaderIncluded = inc;
  else {
    FormatStringBuffer(&s->ErrorMessage, "This sniffer was already started.");
    return -1;
  }

  return 0;
}

int SnifferStop(Sniffer_t* s)
{
  if (s == NULL)
    return -1;

  if (!s->__running) {
    FormatStringBuffer(&s->ErrorMessage, "This sniffer not started.");
    return -1;
  }

#ifdef __linux__
  if (PromiscModeEnabled && s->__promiscEnabled) {
    struct ifreq sockSettings = {0};
    strncpy(sockSettings.ifr_name, s->Interface, IFNAMSIZ);
    sockSettings.ifr_ifindex = s->__ifindex;
    if (ioctl(s->__sock, SIOCGIFFLAGS, (char*) &sockSettings) < 0) {
      FormatStringBuffer(&s->ErrorMessage, "Cannot get socket mode: %s", GetLastErrorMessage());
      return -1;
    }

    if (sockSettings.ifr_flags & IFF_PROMISC) {
      sockSettings.ifr_flags &= ~IFF_PROMISC;
      if (ioctl(s->__sock, SIOCSIFFLAGS, (char*) &sockSettings) < 0) {
        FormatStringBuffer(&s->ErrorMessage, "Cannot set socket mode: %s", GetLastErrorMessage());
        return -1;
      }
    }

    s->__promiscEnabled = false;
  }
#endif

#ifdef __linux__
  close(s->__sock);
#elif _WIN32
  closesocket(s->__sock);
#endif

#ifdef _WIN32
  WSACleanup();
#endif

  s->__running = 0;

  return 0;
}

void SnifferClear(Sniffer_t* s)
{
  if (s == NULL)
    return;

  free(s->__buf);

  free(s->ErrorMessage);
}

#ifdef __linux__
void SetPromiscMode(bool enable)
{
  PromiscModeEnabled = enable;
}
#endif
