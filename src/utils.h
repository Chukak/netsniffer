#ifndef __UTILS_H
#define __UTILS_H

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
 * Parses an address string in the format 'INTERFACE:IP\:PORT' on linux or 'IP:PORT' on Windows and sets the interface,
 * IP and port to the passed arguments. On Windows the interface is an empty string.
 * @param address An address string
 * @param iface Interface name
 * @param ip IP
 * @param port Port
 * @param error The error message (if occurred)
 * @return -1 if an error occurred, otherwise 0.
 */
int ParseAddressString(const char* address, char** iface, char** ip, int* port, char** error);

#endif // __UTILS_H
