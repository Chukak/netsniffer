#include "printing.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include <arpa/inet.h>
#elif _WIN32
#include <winsock2.h>
#endif

void PacketBuffersInit(PacketBuffers_t* p)
{
  assert(("Cannot init buffers ('PacketBuffers_t'): p == NULL.", p != NULL));

  p->IPHeaderBuffer = malloc(sizeof(char) * IP_HEADER_BUFFER_SUFFICIENT_SIZE + 1);
  assert(("Cannot initialize a new buffer: malloc returned size '0'.", p->IPHeaderBuffer != NULL));

  p->ProtocolHeaderBuffer = malloc(sizeof(char) * PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE + 1);
  assert(("Cannot initialize a new buffer: malloc returned size '0'.", p->ProtocolHeaderBuffer != NULL));

  p->DataBuffer = malloc(sizeof(char) * DATA_BUFFER_SUFFICIENT_SIZE + 1);
  assert(("Cannot initialize a new buffer: malloc returned size '0'.", p->DataBuffer != NULL));
}

void PacketBuffersDelete(PacketBuffers_t* p)
{
  if (p == NULL)
    return;

  free(p->DataBuffer);
  free(p->ProtocolHeaderBuffer);
  free(p->IPHeaderBuffer);
}

void PrintPacketToBuffers(Buffer_t packetBuffer, size_t size, PacketBuffers_t* buffers, TimeInfo_t* t)
{
  memset(buffers->IPHeaderBuffer, 0, IP_HEADER_BUFFER_SUFFICIENT_SIZE);
  memset(buffers->ProtocolHeaderBuffer, 0, PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE);
  memset(buffers->DataBuffer, 0, DATA_BUFFER_SUFFICIENT_SIZE);

  IPHeader_t* iphdr = GetIPHeader(packetBuffer);
  PrintPacketIPHeader(packetBuffer, &buffers->IPHeaderBuffer, IP_HEADER_BUFFER_SUFFICIENT_SIZE, t);
  switch (iphdr->Protocol) {
  case Protocol_ICMP: {
    PrintPacketICMPHeader(packetBuffer, &buffers->ProtocolHeaderBuffer, PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE);
    break;
  }
  case Protocol_TCP: {
    PrintPacketTCPHeader(packetBuffer, &buffers->ProtocolHeaderBuffer, PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE);
    break;
  }
  case Protocol_UDP: {
    PrintPacketUDPHeader(packetBuffer, &buffers->ProtocolHeaderBuffer, PROTOCOL_HEADER_BUFFER_SUFFICIENT_SIZE);
    break;
  }
  default:
    break;
  }

  size_t offset = 0;
  Buffer_t packetDataBuffer = GetPacketData(packetBuffer, &offset);
  if (size >= offset)
    PrintPacketData(packetDataBuffer, size - offset, &buffers->DataBuffer, DATA_BUFFER_SUFFICIENT_SIZE);
}

#ifndef _WIN32
void PrintPacketETHHeader(Buffer_t packetBuffer, char** ethHeaderBuffer, size_t ethHeaderBufferSize)
{
  ETHHeader_t* ethhdr = GetETHHeader(packetBuffer);

  int length = 0;
  length += snprintf(*ethHeaderBuffer + length, ethHeaderBufferSize, "\n        ETH Header\n");
  length += snprintf(*ethHeaderBuffer + length,
                     ethHeaderBufferSize,
                     "| Destination Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                     ethhdr->DestinationAddressMac[0],
                     ethhdr->DestinationAddressMac[1],
                     ethhdr->DestinationAddressMac[2],
                     ethhdr->DestinationAddressMac[3],
                     ethhdr->DestinationAddressMac[4],
                     ethhdr->DestinationAddressMac[5]);
  length += snprintf(*ethHeaderBuffer + length,
                     ethHeaderBufferSize,
                     "| Source Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                     ethhdr->SourceAddressMac[0],
                     ethhdr->SourceAddressMac[1],
                     ethhdr->SourceAddressMac[2],
                     ethhdr->SourceAddressMac[3],
                     ethhdr->SourceAddressMac[4],
                     ethhdr->SourceAddressMac[5]);
  length += snprintf(*ethHeaderBuffer + length, ethHeaderBufferSize, "| Protocol: %d\n", ntohs(ethhdr->Protocol));
  snprintf(*ethHeaderBuffer + length, ethHeaderBufferSize, "\n");
}
#endif

void PrintPacketIPHeader(Buffer_t packetBuffer, char** ipHeaderBuffer, size_t ipHeaderBufferSize, TimeInfo_t* t)
{
  IPHeader_t* iphdr = GetIPHeader(packetBuffer);

  struct sockaddr_in source, dest;
  memset(&source, 0, sizeof(source));
  memset(&dest, 0, sizeof(dest));

  source.sin_addr.s_addr = iphdr->SourceAddress;
  dest.sin_addr.s_addr = iphdr->DestinationAddress;

  int length = 0;
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "\n        IP Header\n");
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Version: %d\n", iphdr->Version);
  length += snprintf(*ipHeaderBuffer + length,
                     ipHeaderBufferSize,
                     "| Header Length: %lu bytes\n",
                     (unsigned long) GetIPHeaderLength(iphdr));
#ifdef NET_STRUCTS_VERBOSE
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Type Of Service: %d\n", iphdr->TOS);
#endif
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Total Length: %d bytes\n", iphdr->TotalLength);
#ifdef NET_STRUCTS_VERBOSE
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Identification: %d\n", iphdr->ID);
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Fragment offset: %d\n", iphdr->FragmentOffset);
#endif
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| TTL (Time To Live): %d\n", iphdr->TTL);
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Protocol number value: %d\n", iphdr->Protocol);
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Checksum: %u\n", ntohs(iphdr->Checksum));
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Source IP: %s\n", inet_ntoa(source.sin_addr));
  length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Destination IP: %s\n", inet_ntoa(dest.sin_addr));
  if (t != NULL) {
    char* time;
    TimeInfoToString(t, &time);
    length += snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "| Time: %s\n", time);
    free(time);
  }
  snprintf(*ipHeaderBuffer + length, ipHeaderBufferSize, "\n");
}

void PrintPacketICMPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize)
{
  ICMPHeader_t* icmphdr = GetICMPHeader(packetBuffer);

  int length = 0;
  length += snprintf(*headerBuffer + length, headerBufferSize, "\n        ICMP Header\n");
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Type: %d\n", icmphdr->Type);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Code: %d\n", icmphdr->Code);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Checksum: %u\n", ntohs(icmphdr->Checksum));
  snprintf(*headerBuffer + length, headerBufferSize, "\n");
}

void PrintPacketTCPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize)
{
  TCPV4Header_t* tcphdr = GetTCPV4Header(packetBuffer);

  int length = 0;
  length += snprintf(*headerBuffer + length, headerBufferSize, "\n        TCP Header\n");
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Source Port: %u\n", ntohs(tcphdr->SourcePort));
  length +=
      snprintf(*headerBuffer + length, headerBufferSize, "| Destination Port: %u\n", ntohs(tcphdr->DestinationPort));
  length += snprintf(*headerBuffer + length,
                     headerBufferSize,
                     "| Sequence Number: %lu\n",
                     (unsigned long) ntohl(tcphdr->SequenceNumber));
  length += snprintf(*headerBuffer + length,
                     headerBufferSize,
                     "| Acknowledge Number: %lu\n",
                     (unsigned long) ntohl(tcphdr->AckNumber));
#ifdef NET_STRUCTS_VERBOSE
  length += snprintf(*headerBuffer + length, headerBufferSize, "| DataOffset: %d Bytes\n", tcphdr->DataOffset * 4);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| NS (Flag): %d\n", tcphdr->FlagNS);
#endif
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Finish (Flag): %d\n", tcphdr->FlagFinish);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Sync (Flag): %d\n", tcphdr->FlagSync);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Reset (Flag): %d\n", tcphdr->FlagReset);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Acknowledge (Flag): %d\n", tcphdr->FlagAck);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Urgent (Flag): %d\n", tcphdr->FlagUrgent);
#ifdef NET_STRUCTS_VERBOSE
  length += snprintf(*headerBuffer + length, headerBufferSize, "| ECE (Flag): %d\n", tcphdr->FlagECE);
  length += snprintf(*headerBuffer + length, headerBufferSize, "| CWR (Flag): %d\n", tcphdr->FlagCWR);
#endif
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Window Size: %u\n", ntohs(tcphdr->WindowSize));
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Checksum: %u\n", ntohs(tcphdr->Checksum));
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Urgent Point: %d\n", tcphdr->UrgentPoint);
  snprintf(*headerBuffer + length, headerBufferSize, "\n");
}

void PrintPacketUDPHeader(Buffer_t packetBuffer, char** headerBuffer, size_t headerBufferSize)
{
  UDPHeader_t* udphdr = GetUDPHeader(packetBuffer);

  int length = 0;
  length += snprintf(*headerBuffer + length, headerBufferSize, "\n        UDP Header\n");
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Source Port: %u\n", ntohs(udphdr->SourcePort));
  length +=
      snprintf(*headerBuffer + length, headerBufferSize, "| Destination Port: %u\n", ntohs(udphdr->DestinationPort));
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Length: %u\n", ntohs(udphdr->Length));
  length += snprintf(*headerBuffer + length, headerBufferSize, "| Checksum: %u\n", ntohs(udphdr->Checksum));
  snprintf(*headerBuffer + length, headerBufferSize, "\n");
}

void PrintPacketData(Buffer_t packetBuffer, size_t size, char** dataBuffer, size_t dataBufferSize)
{
  static const size_t lineSize = 32;
  int length = 0;

  length += snprintf(*dataBuffer + length, dataBufferSize, "\n      Data\n");
  for (size_t i = 0; i < size && i < dataBufferSize; ++i) {
    length += snprintf(*dataBuffer + length, dataBufferSize, "[%02X]", (uint8_t) packetBuffer[i]);
    if (i % lineSize == 0)
      length += snprintf(*dataBuffer + length, dataBufferSize, "\n");
    else
      length += snprintf(*dataBuffer + length, dataBufferSize, " ");
  }
  snprintf(*dataBuffer + length, dataBufferSize, "\n");
}
