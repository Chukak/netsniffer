#include "sniffer.h"
#include "cmdargs.h"
#include "printing.h"

#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <stdatomic.h>

#ifdef __linux__
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

typedef void* ThreadArgs_t;
typedef void* ThreadReturnValue_t;
#elif _WIN32
#include <windows.h>

typedef LPVOID ThreadArgs_t;
typedef DWORD ThreadReturnValue_t;
#endif

static void PrintPacket(void* owner, Buffer_t buffer, size_t size, HandlerArgs_t args);
static ThreadReturnValue_t StartSniffingPackets(ThreadArgs_t args);

static atomic_int IsRunning = 0;
static void SignalHandler(int sig);

int main(int argc, char** argv)
{
  if (argc == 1) {
    PrintHelp();
    return 1;
  }

  CmdArgs_t args;
  char* errorMsg = NULL;
  switch (ParseCommandLineArgs(argc, argv, &args, &errorMsg)) {
  case CmdArgs_PRINT_HELP:
    PrintHelp();
    return 0;
  case CmdArgs_ERROR:
    printf("%s\n", errorMsg);
    return 1;
  default:
    break;
  }

  signal(SIGINT, SignalHandler);
  signal(SIGTERM, SignalHandler);

  PacketBuffers_t buffers;
  PacketBuffersInit(&buffers);

  Sniffer_t sniffer;
  if (SnifferInit(&sniffer, args.Protocol, args.Interface, PrintPacket, &buffers) < 0) {
    printf("%s\n", sniffer.ErrorMessage);
    SnifferClear(&sniffer);
    return 1;
  }

  for (int i = 0; i < args.AddressesCount; ++i) {
    if (SnifferAddAddress(&sniffer, args.Addresses[i]) < 0) {
      printf("%s\n", sniffer.ErrorMessage);
      SnifferClear(&sniffer);
      return 1;
    }
  }

  if (SnifferStart(&sniffer) < 0) {
    printf("%s\n", sniffer.ErrorMessage);
    SnifferClear(&sniffer);
    return 1;
  }

#ifdef __linux__
  pthread_t snifferThread;

  pthread_create(&snifferThread, NULL, StartSniffingPackets, &sniffer);
#elif _WIN32
  HANDLE snifferThread = CreateThread(
      NULL, 0, (LPTHREAD_START_ROUTINE) StartSniffingPackets, &sniffer, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
#endif

  IsRunning = 1;
  while (IsRunning) {
#ifdef __linux__
    usleep(500 * 1000 /* 500 ms */);
#elif _WIN32
    Sleep(500);
#endif
  }

  // TODO: mutex
  if (SnifferStop(&sniffer) < 0) {
    printf("%s\n", sniffer.ErrorMessage);
  }

#ifdef __linux__
  pthread_join(snifferThread, NULL);
#elif _WIN32
  WaitForSingleObject(snifferThread, INFINITE);
#endif

  SnifferClear(&sniffer);
  PacketBuffersDelete(&buffers);

  return 0;
}

void PrintPacket(void* owner, Buffer_t buffer, size_t size, HandlerArgs_t args)
{
  if (args == NULL)
    return;

  Sniffer_t* sniffer = (Sniffer_t*) owner;
  assert(("Cannot convert 'void*' to 'Sniffer_t*'.", sniffer != NULL));
  (void) sniffer;

  PacketBuffers_t* buffers = (PacketBuffers_t*) args;
  assert(("Cannot convert 'handlerArgs_t' to 'PacketBuffers_t*'.", buffer != NULL));

  size_t hdroffset = 0;
#ifdef __linux__
  if (sniffer->Protocol == Protocol_ANY) {
    char* ethHeaderBuffer = malloc(ETH_HEADER_BUFFER_SUFFICIENT_SIZE);
    assert(("Cannot initialize a new buffer: malloc returned size '0'.", ethHeaderBuffer != NULL));

    PrintPacketETHHeader(buffer, &ethHeaderBuffer, ETH_HEADER_BUFFER_SUFFICIENT_SIZE);
    printf("%s ", ethHeaderBuffer);

    free(ethHeaderBuffer);

    hdroffset = GetETHHeaderLength();
  }
#endif

  PrintPacketToBuffers(buffer + hdroffset, size, buffers);

  printf("%s %s %s", buffers->IPHeaderBuffer, buffers->ProtocolHeaderBuffer, buffers->DataBuffer);
}

ThreadReturnValue_t StartSniffingPackets(ThreadArgs_t args)
{
  if (args == NULL)
#ifdef __linux__
    return (void*) -1;
#elif _WIN32
    return FALSE;
#endif

  Sniffer_t* sniffer = (Sniffer_t*) args;
  assert(("Cannot convert 'ThreadArgs_t' to 'Sniffer_t*'.", sniffer != NULL));

  while (IsRunning) {
    if (SnifferProcessNextPacket(sniffer) < 0) {
      printf("%s\n", sniffer->ErrorMessage);
#ifdef __linux__
      return (void*) -1;
#elif _WIN32
      return FALSE;
#endif
    }
  }

#ifdef __linux__
  return (void*) 0;
#elif _WIN32
  return TRUE;
#endif
}

void SignalHandler(int sig)
{
  (void) sig;
  IsRunning = 0;
}
