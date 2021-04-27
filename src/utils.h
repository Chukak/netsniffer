#ifndef __UTILS_H
#define __UTILS_H

#include <assert.h>

/**
 * @brief GetLastErrorMessage
 * @return The last system error message.
 */
const char* GetLastErrorMessage();
/**
 * @brief FormatStringBuffer
 * Formats the buffer using the passed arguments.
 * @param buffer The string buffer
 * @param msg A message with formatting symbols (or without them).
 */
void FormatStringBuffer(char** buffer, const char* msg, ...);
/**
 * @brief ParseAddressString
 * Parses an address string in the format 'IP\:PORT' and sets the IP and port to the passed arguments.
 * @param address An address string in the format 'IP\:PORT'
 * @param ip IP
 * @param port Port
 * @param error The error message (if occurred)
 * @return -1 if an error occurred, otherwise 0.
 */
int ParseAddressString(const char* address, char** ip, int* port, char** error);

#define ASSERT(msg, cond) assert(((void) msg, cond));
#endif // __UTILS_H
