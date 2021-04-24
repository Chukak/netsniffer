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

int ParseAddressString(const char* address, char** iface, char** ip, int* port, char** error)
{
  size_t addrSize = strlen(address);
  char *source = malloc(sizeof(char) * addrSize + 1), *sourceOrig = source;
  strncpy(source, address, addrSize);
#ifdef __linux__
  char** args[] = {iface, ip};
  int countArgs = 2;
#elif _WIN32
  char** args[] = {ip};
  int countArgs = 1;
#endif
  for (int i = 0; i < countArgs; ++i) {
    char* delimeter = strstr(source, ":");
    if (delimeter == NULL) {
      FormatStringBuffer(error,
                         "Invalid address: %s. Address must be in the format "
#ifdef __linux__
                         "\"INTERFACE:IP:PORT\""
#elif _WIN32
                         "\"IP:PORT\""
#endif
                         ". Invalid part: %s",
                         address,
                         source);
      free(sourceOrig);
      return -1;
    }

    int size = (int) (delimeter - source);
    if (size <= 0) {
      FormatStringBuffer(error, "Invalid interface in the address '%s'.", address);
      free(source);
      return -1;
    }

    char** arg = args[i];
    *arg = malloc(sizeof(char) * (size_t) size + 1);
    assert(("Cannot initialize a new string: realloc returned 'NULL'.", *arg != NULL));
    strncpy(*arg, source, (size_t) size);
    (*arg)[size] = '\0';

    source = delimeter + 1;
  }

  *port = (int) strtol(source, NULL, 10);
  if (*port < 0) {
    FormatStringBuffer(error, "Invalid port '%d'.", port);
    free(sourceOrig);
    return -1;
  }
#ifdef _WIN32
  *iface = malloc(sizeof(char) * 1);
  assert(("Cannot initialize a new string: realloc returned 'NULL'.", *iface != NULL));
  iface[0] = '\0';
#endif

  free(sourceOrig);
  return 0;
}
