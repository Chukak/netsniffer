#include "cmdargs.h"

#include "utils.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

ParseArgsReturnCode_t ParseCommandLineArgs(int argc, char** argv, CmdArgs_t* args, char** error)
{
  if (args == NULL) {
    FormatStringBuffer(error, "The pointer to CmdArgs_t == NULL.");
    return CmdArgs_ERROR;
  }

  args->PromiscMode = false;
  args->IncludeETHHeader = false;
  args->Protocol = Protocol_ANY;
  args->Interface[0] = '\0';

  args->AddressesCount = 0;
  for (int i = 1; i < argc; ++i) {
    char* arg = argv[i];
    if (strcmp(arg, "-protocol") == 0) {
      if (i + 1 >= argc) {
        FormatStringBuffer(error, "No the protocol value after '-protocol' option.");
        return CmdArgs_ERROR;
      }
      args->Protocol = GetProtocolFromString(argv[++i]);
#ifdef __linux__
    } else if (strcmp(arg, "-enable-promisc-mode") == 0) {
      args->PromiscMode = true;
    } else if (strcmp(arg, "-include-eth-header") == 0) {
      args->IncludeETHHeader = true;
#endif
    } else if (strcmp(arg, "-help") == 0 || strcmp(arg, "--help") == 0 /* compatibility */) {
      return CmdArgs_PRINT_HELP;
    } else {
      if (strlen(args->Interface) == 0)
        strncpy(args->Interface, arg, IFACE_MAX_SIZE);
      else {
        if (args->AddressesCount >= ADDRESSES_MAX_COUNT) {
          FormatStringBuffer(error,
                             "Max addresses count %d (max value: %d)",
                             args->AddressesCount,
                             ADDRESSES_MAX_COUNT);
          return CmdArgs_ERROR;
        }

        strncpy(args->Addresses[args->AddressesCount++], arg, ADDRESS_MAX_SIZE);
      }
    }
  }

  if (strlen(args->Interface) == 0) {
    FormatStringBuffer(error, "No network interface specified.");
    return CmdArgs_ERROR;
  }

  if (args->AddressesCount == 0) {
    FormatStringBuffer(error, "No addresses specified.");
    return CmdArgs_ERROR;
  }
  return CmdArgs_SUCCESS;
}

void PrintHelp()
{
  const char* message = "Usage: " EXE_BINARY_NAME " OPTIONS... "
#ifdef __linux__
                        "INTERFACE"
#elif _WIN32
                        "INTERFACE-INDEX"
#endif
                        " IP:PORT... \n"
                        "Sniffs network traffic at the specified address. \n"
                        "Arguments: \n"
                        "\t-protocol [ICMP, TCP, UDP]\t\tNetwork protocol. \n"
#ifdef __linux__
                        "\t-enable-promisc-mode      \t\tEnable the promiscious mode on the interface. \n"
                        "\t-include-eth-header       \t\tShow the Ethernet header of each packet. \n"
#endif
                        "\n"
                        "To sniffing from any IP and port, use address: any:0.\n"
#ifdef _WIN32
                        "On Windows to sniff from localhost set the interface index as 0.\n"
#endif
                        "\n"
                        "Example: \n"
#ifdef __linux__
                        "\t" EXE_BINARY_NAME " eth0"
#elif _WIN32
                        "\t" EXE_BINARY_NAME ".exe 6"
#endif
                        " 192.168.0.1:8000 192.168.0.2:8000\n"
                        "\n";
  printf("%s", message);
}
