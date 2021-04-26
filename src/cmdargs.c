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

  args->Address = "";
  args->Protocol = Protocol_ANY;

  for (int i = 1; i < argc; ++i) {
    char* arg = argv[i];
    if (strcmp(arg, "-protocol") == 0) {
      if (i + 1 >= argc) {
        FormatStringBuffer(error, "No the protocol value after '-protocol' option.");
        return CmdArgs_ERROR;
      }
      args->Protocol = GetProtocolFromString(argv[++i]);
    } else if (strcmp(arg, "-help") == 0) {
      return CmdArgs_PRINT_HELP;
    } else {
      char *ip = NULL, *iface = NULL;
      int port;
      int rc = ParseAddressString(arg, &iface, &ip, &port, error);
      free(ip);
      free(iface);
      if (rc != 0) {
        return CmdArgs_ERROR;
      }
      args->Address = arg;
    }
  }

  if (strlen(args->Address) == 0) {
    FormatStringBuffer(error, "No address specified.");
    return CmdArgs_ERROR;
  }
  return CmdArgs_SUCCESS;
}

void PrintHelp()
{
  const char* message = "Usage: " EXE_BINARY_NAME " OPTIONS... "
#ifdef __linux__
                        "INTERFACE:IP:PORT"
#elif _WIN32
                        "INTERFACE-INDEX:IP:PORT"
#endif
                        " \n"
                        "Sniffs network traffic at the specified address. \n"
                        "Arguments: \n"
                        "\t-protocol [ICMP, TCP, UDP]\t\tNetwork protocol. \n"
                        "\n"
                        "Example: \n"
#ifdef __linux__
                        "\t" EXE_BINARY_NAME " lo:127.0.0.1:8000 \n"
#elif _WIN32
                        "\t" EXE_BINARY_NAME ".exe 127.0.0.1:8000 \n"
#endif
                        "\n";
  printf("%s", message);
}
