#ifndef __CMDARGS_H
#define __CMDARGS_H

#include "structures.h"
#include <stdbool.h>

/**
 * @brief ParseArgsReturnCode_t
 * Result codes of parsing command line arguments.
 */
typedef enum
{
  CmdArgs_ERROR = -1,
  CmdArgs_SUCCESS = 0,
  CmdArgs_PRINT_HELP = 1
} ParseArgsReturnCode_t;
/**
 * @brief CmdArgs_t
 * Stores arguments from command line.
 */
typedef struct
{
#ifdef __linux__
  bool PromiscMode;
  bool IncludeETHHeader;
#endif
  Protocol_t Protocol;
  char Interface[IFACE_MAX_SIZE];
  char Addresses[ADDRESSES_MAX_COUNT][ADDRESS_MAX_SIZE];
  int AddressesCount;
} CmdArgs_t;
/**
 * @brief ParseCommandLineArgs
 * Parses command line arguments. Stores these arguments to the passed CmdArgs_t object.
 * @param argc Arguments size
 * @param argv Arguments array
 * @param error Error message (if occurred)
 * @return CmdArgs_ERROR if an error occurred, otherwise CmdArgs_SUCCESS or other codes.
 */
ParseArgsReturnCode_t ParseCommandLineArgs(int argc, char** argv, CmdArgs_t* args, char** error);
/**
 * @brief PrintHelp
 * Print the help information.
 */
void PrintHelp();

#endif // __CMDARGS_H
