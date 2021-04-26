#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <errno.h>
#elif _WIN32
#include <Windows.h>
#endif

#define ERROR_MESSAGE_BUFFER_CAPACITY 1024

static char ErrorMessageBuffer[ERROR_MESSAGE_BUFFER_CAPACITY];
static
#ifdef __linux__
    size_t
#elif _WIN32
    DWORD
#endif
        ErrorMessageBufferSize = 0;

void FormatStringBuffer(char** buffer, const char* msg, ...)
{
  va_list args, argsCopy;
  va_start(args, msg);
  va_start(argsCopy, msg);
  long msgSize = vsnprintf(NULL, 0, msg, args);
  va_end(args);

  if (msgSize < 0) // TODO:
    return;

  *buffer = realloc(*buffer, sizeof(char) * (size_t) msgSize + 1);
  assert(("Cannot initialize a new string: realloc returned 'NULL'.", *buffer != NULL));

  vsnprintf(*buffer, (size_t) msgSize + 1, msg, argsCopy);
  (*buffer)[msgSize] = '\0';
}

const char* GetLastErrorMessage()
{
  ErrorMessageBuffer[0] = '\0';

#ifdef __linux__
  strcpy(ErrorMessageBuffer, strerror(errno));
  ErrorMessageBufferSize = strlen(ErrorMessageBuffer);
#elif _WIN32
  ErrorMessageBufferSize = (size_t) FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                                                  NULL,
                                                  (DWORD) GetLastError(),
                                                  MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                                                  ErrorMessageBuffer,
                                                  ERROR_MESSAGE_BUFFER_CAPACITY,
                                                  NULL);
#endif
  return ErrorMessageBuffer;
}

int ParseAddressString(const char* address, char** ip, int* port, char** error)
{
  size_t addrSize = strlen(address);
  char* source = malloc(sizeof(char) * addrSize + 1);
  strncpy(source, address, addrSize);
  source[addrSize] = '\0';

  char* delimeter = strstr(source, ":");
  if (delimeter == NULL) {
    FormatStringBuffer(error,
                       "Invalid address: %s. Address must be in the format \"IP:PORT\". Invalid part: %s",
                       address,
                       source);
    free(source);
    return -1;
  }

  int ipSize = (int) (delimeter - source);
  if (ipSize <= 0) {
    FormatStringBuffer(error, "Invalid address '%s'.", address);
    free(source);
    return -1;
  }

  *ip = malloc(sizeof(char) * (size_t) ipSize + 1);
  assert(("Cannot initialize a new string: realloc returned 'NULL'.", *ip != NULL));
  strncpy(*ip, source, (size_t) ipSize);
  (*ip)[ipSize] = '\0';

  *port = (int) strtol(source + ipSize + 1, NULL, 10);
  if (*port < 0) {
    FormatStringBuffer(error, "Invalid port '%d'.", port);
    free(source);
    return -1;
  }

  free(source);
  return 0;
}
