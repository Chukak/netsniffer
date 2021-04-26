#include "sniffer.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#ifdef __linux__
#include <arpa/inet.h>
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
#elif _WIN32
#define SOCKET_ERROR_CODE SOCKET_ERROR
static int WSAIoctlEnableMode = 1;
static unsigned long WSAIoctlSupperss;
#endif

int SnifferInit(Sniffer_t* s, Protocol_t p, const char* addr, ProcessingPacketHandler_t handler, HandlerArgs_t args)
{
  assert(("Cannot init sniffer ('Sniffer_t'): s == NULL.", s != NULL));

  s->SniffStart = 0;
  s->SniffEnd = 0;

  ParseAddressString(addr, &s->Interface, &s->IP, &s->Port, &s->ErrorMessage);

  s->Protocol = p;
  s->RecvCount = 0;
  s->SentCount = 0;
  s->ErrorMessage = NULL;

#ifdef _WIN32
  if (WSAStartup(MAKEWORD(2, 2), &s->__wsadata) != NO_ERROR) {
    FormatStringBuffer(&s->ErrorMessage, "Failed to startup WinSock: %s", GetLastErrorMessage());
    return -1;
  }
#endif

#ifdef __linux__
  if (s->Protocol == Protocol_ANY) // TODO: duplicates
    s->__sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  else
    s->__sock = socket(AF_INET, SOCK_RAW, s->Protocol);
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

  s->__sockAddr = NULL;
  s->__buf = malloc(ETH_MAX_PACKET_SIZE);
  assert(("Cannot initialize a new network buffer: malloc returned size '0'.", s->__buf != NULL));

  s->__handler = handler;
  s->__args = args;
  s->__running = 0;
  return 0;
}

int SnifferStart(Sniffer_t* s)
{
  if (s == NULL)
    return -1;

#ifdef __linux__
  memset(&(s->__ifr), 0, sizeof(s->__ifr));
  strncpy(s->__ifr.ifr_name, s->Interface, IFNAMSIZ);
  if ((s->__ifr.ifr_ifindex = (int) if_nametoindex(s->Interface)) == 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot get interface (%s) index: %s", s->Interface, GetLastErrorMessage());
    return -1;
  }

  if (ioctl(s->__sock, SIOCGIFADDR, &s->__ifr) < 0) {
    FormatStringBuffer(&s->ErrorMessage,
                       "Cannot get IP address of the interface (%s): %s",
                       s->Interface,
                       GetLastErrorMessage());
    return -1;
  }
#endif

  socklen_t szSockAddress = 0;
#ifdef __linux__
  if (s->Protocol == Protocol_ANY) {
    struct sockaddr_ll* ll = malloc(sizeof(struct sockaddr_ll));
    memset(ll, 0, sizeof(struct sockaddr_ll));
    ll->sll_family = AF_PACKET;
    ll->sll_protocol = htons(ETH_P_ALL);
    ll->sll_ifindex = s->__ifr.ifr_ifindex;

    s->__sockAddr = ll;
    szSockAddress = sizeof(struct sockaddr_ll);
  } else {
#elif _WIN32
  PIP_ADAPTER_INFO adaptlist = malloc(sizeof(IP_ADAPTER_INFO)), adaptlistNext = NULL;
  assert(("Cannot initialize a new network adapter information: malloc returned size '0'.", adaptlist != NULL));
  ULONG adaptlistBytes = sizeof(IP_ADAPTER_INFO);
  ULONG getAdaptListRetCode = NO_ERROR;
  do {
    getAdaptListRetCode = GetAdaptersInfo(adaptlist, &adaptlistBytes);

    switch (getAdaptListRetCode) {
    case ERROR_BUFFER_OVERFLOW: {
      FormatStringBuffer(&s->ErrorMessage, "GetInfoAdapters(..): Error allocating memore needed to call.");
      adaptlist = realloc(adaptlist, adaptlistBytes);
      assert(("Cannot reinitialize a new network adapter information: malloc returned size '0'.", adaptlist != NULL));
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

  char ifaceIpAddress[IP_MAX_SIZE];
  DWORD ifaceIndex = (DWORD) atoi(s->Interface);
  BOOL ifaceIpAddressFound = FALSE;
  for (adaptlistNext = adaptlist; adaptlistNext != NULL; adaptlistNext = adaptlist->Next) {
    if (ifaceIndex == adaptlistNext->Index) {
      ifaceIpAddressFound = TRUE;
      strncpy(ifaceIpAddress, adaptlistNext->IpAddressList.IpAddress.String, IP_MAX_SIZE);
      break;
    }
  }
  free(adaptlist);

  if (!ifaceIpAddressFound) {
    FormatStringBuffer(&s->ErrorMessage, "IP address for the interface index %s not found.", s->Interface);
    return -1;
  }
#endif
    // clang-format off
    struct sockaddr_in* in = malloc(sizeof(struct sockaddr_in));
    memset(in, 0, sizeof(struct sockaddr_in));
    in->sin_family = AF_INET;
#ifdef __linux__
    in->sin_addr = ((struct sockaddr_in*) &s->__ifr.ifr_addr)->sin_addr;
#elif _WIN32
    in->sin_addr.s_addr = inet_addr(ifaceIpAddress); 
#endif
    in->sin_port = htons((u_short) s->Port);

    s->__sockAddr = in;
    szSockAddress = sizeof(struct sockaddr_in);
    // clang-format on
#ifdef __linux__
  }
#endif

  if (bind(s->__sock, (struct sockaddr*) s->__sockAddr, szSockAddress) == SOCKET_ERROR_CODE) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot bind socket: %s", GetLastErrorMessage());
    return -1;
  }

#ifdef __linux__
  if (ioctl(s->__sock, SIOCGIFFLAGS, (char*) &s->__ifr) < 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot get socket mode: %s", GetLastErrorMessage());
    return -1;
  }

  s->__ifr.ifr_flags |= IFF_PROMISC;
  if (ioctl(s->__sock, SIOCSIFFLAGS, (char*) &s->__ifr) < 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot set socket mode: %s", GetLastErrorMessage());
    return -1;
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
  struct timeval timeout = {0, SOCKET_WAITING_TIMEOUT_MS * 1000};
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

  int64_t recvBytes;
  if ((recvBytes = recvfrom(s->__sock, (char*) s->__buf, ETH_MAX_PACKET_SIZE, 0, NULL, 0)) > 0) {
    do {
      Buffer_t buffer = s->__buf;
#ifdef __linux__
      if (s->Protocol == Protocol_ANY)
        buffer = s->__buf + GetETHHeaderLength();
#endif
      IPHeader_t* iphdr = GetIPHeader(buffer);

      if (iphdr) {
        if (s->Protocol != Protocol_ANY && iphdr->Protocol != s->Protocol)
          break;

        char sourceIP[IP_MAX_SIZE], destIP[IP_MAX_SIZE];
        {
          static struct sockaddr_in src, dst;
          memset(&src, 0, sizeof(src));
          memset(&dst, 0, sizeof(dst));
          src.sin_addr.s_addr = iphdr->SourceAddress;
          dst.sin_addr.s_addr = iphdr->DestinationAddress;

          strncpy(sourceIP, inet_ntoa(src.sin_addr), IP_MAX_SIZE);
          strncpy(destIP, inet_ntoa(dst.sin_addr), IP_MAX_SIZE);
        }

        // TODO: Direction
        if (s->IP[0] != '\0' && strcmp(sourceIP, s->IP) != 0 && strcmp(destIP, s->IP) != 0)
          break;

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

        if (s->Port != 0 && s->Port != sourcePort && s->Port != destPort)
          break;

        if (s->__handler) {
          s->__handler(s, s->__buf, (size_t) recvBytes, s->__args);
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

int SnifferStop(Sniffer_t* s)
{
  if (s == NULL)
    return -1;

  if (!s->__running) {
    FormatStringBuffer(&s->ErrorMessage, "This sniffer not started.");
    return -1;
  }

#ifdef __linux__
  s->__ifr.ifr_flags &= ~IFF_PROMISC;
  if (ioctl(s->__sock, SIOCSIFFLAGS, (char*) &s->__ifr) < 0) {
    FormatStringBuffer(&s->ErrorMessage, "Cannot set socket mode: %s", GetLastErrorMessage());
    return -1;
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

  free(s->__sockAddr);
  free(s->__buf);

  free(s->IP);
  free(s->Interface);
  free(s->ErrorMessage);
}
