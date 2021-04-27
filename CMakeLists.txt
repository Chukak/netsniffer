cmake_minimum_required(VERSION 2.8)

project(netsniffer LANGUAGES C)

if (UNIX)
    find_library(PTHREAD_LIBRARIES NAMES pthread REQUIRED)
endif()

set(SOURCE_FILES
    src/main.c
    src/structures.c
    src/printing.c
    src/utils.c
    src/sniffer.c
    src/cmdargs.c
)
set(PRIVATE_HEADER_FILES
    src/structures.h
    src/printing.h
    src/utils.h
    src/sniffer.h
    src/cmdargs.h
)
set(PUBLIC_HEADER_FILES
)

set(C_PROJECT_COMPILE_FLAGS
)
set(C_PROJECT_LINK_FLAGS
)
set(C_PROJECT_COMPILE_DEFINITIONS -DEXE_BINARY_NAME=\"${PROJECT_NAME}\"
)

if (${CMAKE_BUILD_TYPE} MATCHES Debug)
    list(APPEND C_PROJECT_COMPILE_FLAGS -g)
    if (UNIX)
        list(APPEND C_PROJECT_COMPILE_FLAGS -fno-omit-frame-pointer -fsanitize=address)
        list(APPEND C_PROJECT_LINK_FLAGS -lasan)
    endif()
else()
    list(APPEND C_PROJECT_COMPILE_DEFINITIONS -DNDEBUG)
endif()

if (UNIX)
    list(APPEND C_PROJECT_LINK_FLAGS ${PTHREAD_LIBRARIES})
elseif (WIN32)
    list(APPEND C_PROJECT_COMPILE_DEFINITIONS -D_WIN32_WINNT=0x0601)
    list(APPEND C_PROJECT_LINK_FLAGS -lws2_32 -liphlpapi)
endif()

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND C_PROJECT_COMPILE_FLAGS 
        -Wextra -Wall -Wshadow -Wcast-align -Wwrite-strings -Wuninitialized -std=gnu11 -Wundef -Wconversion
        -Wunreachable-code -Wno-unknown-pragmas)
endif()

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${PRIVATE_HEADER_FILES} ${PUBLIC_HEADER_FILES})
target_compile_options(${PROJECT_NAME} PUBLIC ${C_PROJECT_COMPILE_FLAGS})
target_link_libraries(${PROJECT_NAME} PUBLIC ${C_PROJECT_LINK_FLAGS})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${C_PROJECT_COMPILE_DEFINITIONS})
target_include_directories(${PROJECT_NAME} PRIVATE src)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin COMPONENT binary)

if (TESTS_ENABLED)
    set(PROJECT_TEST_NAME ${PROJECT_NAME}-test)
    enable_testing()

    set(TEST_SOURCE_FILES
        tests/main.c
        tests/test-utils.c
        tests/test-structures.c
    )
    set(TEST_HEADER_FILES
        tests/testing.h
    )
    
    list(REMOVE_ITEM SOURCE_FILES src/main.c)
    add_executable(${PROJECT_TEST_NAME} ${SOURCE_FILES} ${PRIVATE_HEADER_FILES} ${PUBLIC_HEADER_FILES}
        ${TEST_SOURCE_FILES} ${TEST_HEADER_FILES})
    target_compile_options(${PROJECT_TEST_NAME} PRIVATE ${C_PROJECT_COMPILE_FLAGS})
    target_link_libraries(${PROJECT_TEST_NAME} PRIVATE ${C_PROJECT_LINK_FLAGS})
    target_compile_definitions(${PROJECT_TEST_NAME} PUBLIC ${C_PROJECT_COMPILE_DEFINITIONS})
    target_include_directories(${PROJECT_TEST_NAME} PRIVATE src)

    add_test(NAME "${PROJECT_TEST_NAME}" COMMAND ${PROJECT_TEST_NAME})
endif()
