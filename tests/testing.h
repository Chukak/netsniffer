#ifndef __TESTING_H
#define __TESTING_H

#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef __GNUC__
#define attribute(at) __attribute__((at))
#elif __MINGW32__
#define attribute(at) __attribute((at))
#endif

#define TEST_CASE(TestName, TestCaseName)                                                                              \
  void TestName##_##TestCaseName() attribute(constructor(10000));                                                      \
  void TestName##_##TestCaseName()

#define TEST_ASSERT(cond, msg)                                                                                         \
  {                                                                                                                    \
    int __ret = (cond);                                                                                                \
    if (!__ret) {                                                                                                      \
      fprintf(stderr,                                                                                                  \
              "assetrion failed %s:%d.\n",                                                                             \
              strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__,                                          \
              __LINE__);                                                                                               \
      fflush(stderr);                                                                                                  \
    }                                                                                                                  \
    assert(((void) msg, __ret));                                                                                       \
  }

#endif // __TESTING_H
