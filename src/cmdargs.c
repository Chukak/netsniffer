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
#ifdef __linux__
  args->PromiscMode = false;
  args->IncludeETHHeader = false;
#endif
  args->Interface[0] = '\0';

  for (int i = 0; i < ADDRESSES_MAX_COUNT; ++i)
    FilterInitDefaults(&args->Filters[i]);

  args->AddressesCount = 0;
  for (int i = 1; i < argc; ++i) {
    char* arg = argv[i];
    if (strcmp(arg, "-help") == 0 || strcmp(arg, "--help") == 0 /* compatibility */) {
      return CmdArgs_PRINT_HELP;
#ifdef __linux__
    } else if (strcmp(arg, "-enable-promisc-mode") == 0) {
      args->PromiscMode = true;
    } else if (strcmp(arg, "-include-eth-header") == 0) {
      args->IncludeETHHeader = true;
#endif
    } else {
      if ((char*) strstr(arg, ":") == NULL) {
        if (strlen(args->Interface) == 0)
          strncpy(args->Interface, arg, IFACE_MAX_SIZE);
        else {
          if (strcmp(arg, "src") == 0)
            args->Filters[args->AddressesCount].Direction = Direction_SOURCE;
          else if (strcmp(arg, "dst") == 0)
            args->Filters[args->AddressesCount].Direction = Direction_DESTINATION;
          else if (strcmp(arg, "tcp") == 0)
            args->Filters[args->AddressesCount].Protocol = Protocol_TCP;
          else if (strcmp(arg, "udp") == 0)
            args->Filters[args->AddressesCount].Protocol = Protocol_UDP;
          else if (strcmp(arg, "icmp") == 0)
            args->Filters[args->AddressesCount].Protocol = Protocol_ICMP;
          else {
            FormatStringBuffer(error, "Invalid filter option: %s", arg);
            return CmdArgs_ERROR;
          }
        }
        continue;
      }

      if (args->AddressesCount >= ADDRESSES_MAX_COUNT) {
        FormatStringBuffer(error, "Max addresses count %d (max value: %d)", args->AddressesCount, ADDRESSES_MAX_COUNT);
        return CmdArgs_ERROR;
      }

      strncpy(args->Addresses[args->AddressesCount++], arg, ADDRESS_MAX_SIZE);
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
                        " FILTERS-OPTIONS... IP:PORT... \n"
                        "Sniffs network traffic at the specified address. \n"
                        "Options: \n"
#ifdef __linux__
                        "\t-enable-promisc-mode      \t\tEnable the promiscious mode on the interface. \n"
                        "\t-include-eth-header       \t\tShow the Ethernet header of each packet. \n"
#endif
                        "\n"
                        "To sniffing from any IP and port, use address: any:0.\n"
                        "\n"
                        "Available filters: \n"
                        "\tProtocols: [tcp (TCP), udp (UDP), icmp (ICMP)].\n"
                        "\tDirection: [src (Source), dst (Destination)].\n"
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
                        " src tcp 192.168.0.1:8000 udp dst 192.168.0.2:8000 192.168.0.3:0\n"
#ifdef __linux__
                        "\t" EXE_BINARY_NAME " lo"
#elif _WIN32
                        "\t" EXE_BINARY_NAME ".exe 0"
#endif
                        " any:0\n"
                        "\n";
  printf("%s", message);
}
