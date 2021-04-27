#include "testing.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

TEST_CASE(TestUtils, ParseAddressString)
{
  char *ip, *error = NULL;
  int port = 0;
  (void) port;

  TEST_ASSERT(ParseAddressString("127.0.0.1:8000", &ip, &port, &error) == 0, "ParseAddressString(..) < 0.");
  TEST_ASSERT(strcmp(ip, "127.0.0.1") == 0, "Invalid IP.");
  TEST_ASSERT(port == 8000, "Invalid port.");

  free(ip);
  free(error);
}

TEST_CASE(TestUtils, FormatStringBuffer)
{
  char *buffer = NULL;

  FormatStringBuffer(&buffer, "%s, %d, %s", "abc", 1, "def");
  TEST_ASSERT(buffer != NULL, "FormatStringBuffer(..) retutns NULL.");
  TEST_ASSERT(strcmp(buffer, "abc, 1, def") == 0, "Invalid buffer.");

  free(buffer);
}
