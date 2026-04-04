cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

option(CNOISE_PROTOBUFS "Compile source of protobufs." OFF)
option(CNOISE_EXAMPLES "Compile examples." OFF)
option(CNOISE_TESTS "Compile tests." ON)
option(CNOISE_VECTOR_TESTS "Compile vector tests." OFF)

set(NAME_PROJECT_CNOISE cnoise)

set(CMAKE_EXPORT_COMPILE_COMMANDS YES)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/portable;${CMAKE_MODULE_PATH}")

file(GLOB_RECURSE CRYPTO_SOURCE_FILES src/crypto/*.c)
file(GLOB_RECURSE PROTOCOL_SOURCE_FILES src/protocol/*.c)
file(
    GLOB
    MLKEM1024_AMD64_AVX2
    thirdparty/mlkem-libjade/src/mlkem1024_amd64_avx2/mlkem1024_amd64_avx2.s
)

set(CNOISE_SOURCE_FILES ${CRYPTO_SOURCE_FILES} ${PROTOCOL_SOURCE_FILES} ${MLKEM1024_AMD64_AVX2})
set(CNOISE_INCLUDE_DIR include/)

project(${NAME_PROJECT_CNOISE} LANGUAGES C ASM)

# Builds LibreSSL
add_custom_target(
    LibreSSL_lib
    WORKING_DIRECTORY thirdparty/portable
    COMMAND ./autogen
    COMMAND ./configure
    COMMAND make check
    COMMAND make 
    VERBATIM
)
find_package(LibreSSL REQUIRED)

# Builds BLAKE2
file(GLOB_RECURSE BLAKE2_SOURCE_FILES thirdparty/BLAKE2/ref/*.c)
add_library(BLAKE2 STATIC ${BLAKE2_SOURCE_FILES})

add_library(${NAME_PROJECT_CNOISE} STATIC ${CNOISE_SOURCE_FILES})

target_link_libraries(${NAME_PROJECT_CNOISE} LibreSSL::Crypto BLAKE2)
target_include_directories(
    ${NAME_PROJECT_CNOISE}
    PRIVATE
    src/ 
    PUBLIC
    ${CNOISE_INCLUDE_DIR}
    thirdparty/portable/include
    thirdparty/BLAKE2/ref
    thirdparty/mlkem-libjade/src
)

if(CNOISE_EXAMPLES)
    set(NAME_ECHO_CLIENT echo_client)
    set(NAME_ECHO_SERVER echo_server)
    set(NAME_ECHO_KEYGEN echo_keygen)
    
    file(GLOB_RECURSE ECHO_CLIENT_SOURCE_FILES examples/echo/echo-client/*.c)
    file(GLOB_RECURSE ECHO_SERVER_SOURCE_FILES examples/echo/echo-server/*.c)
    file(GLOB_RECURSE ECHO_KEYGEN_SOURCE_FILES examples/echo/echo-keygen/*.c)

    add_executable(${NAME_ECHO_CLIENT} ${ECHO_CLIENT_SOURCE_FILES})
    add_executable(${NAME_ECHO_SERVER} ${ECHO_SERVER_SOURCE_FILES})
    add_executable(${NAME_ECHO_KEYGEN} ${ECHO_KEYGEN_SOURCE_FILES})
    
    target_link_libraries(${NAME_ECHO_CLIENT} ${NAME_PROJECT_CNOISE})
    target_link_libraries(${NAME_ECHO_SERVER} ${NAME_PROJECT_CNOISE})
    target_link_libraries(${NAME_ECHO_KEYGEN} ${NAME_PROJECT_CNOISE})
endif()

if(CNOISE_TESTS)
    set(NAME_TEST_UNITS_CNOISE test_units_cnoise)
    set(NAME_TEST_PERFORMANCE_CNOISE test_performance_cnoise)
    file(GLOB_RECURSE TEST_UNITS_SOURCE_FILES tests/unit/*.c)
    file(GLOB_RECURSE TEST_PERFORMANCE_SOURCE_FILES tests/performance/*.c)
    
    add_executable(${NAME_TEST_UNITS_CNOISE} ${TEST_UNITS_SOURCE_FILES})
    add_executable(${NAME_TEST_PERFORMANCE_CNOISE} ${TEST_PERFORMANCE_SOURCE_FILES})
    
    target_link_libraries(${NAME_TEST_UNITS_CNOISE} ${NAME_PROJECT_CNOISE})
    target_include_directories(
        ${NAME_TEST_UNITS_CNOISE}
        PRIVATE
        src/
    )
    target_link_libraries(${NAME_TEST_PERFORMANCE_CNOISE} ${NAME_PROJECT_CNOISE})
    target_include_directories(
        ${NAME_TEST_PERFORMANCE_CNOISE}
        PRIVATE
        src/
    )
    
    add_test(NAME TEST_UNITS_CNOISE COMMAND ${NAME_TEST_UNITS_CNOISE})
    add_test(NAME TEST_PERFORMANCE_CNOISE COMMAND ${NAME_TEST_PERFORMANCE_CNOISE})
endif()
if(CNOISE_VECTOR_TESTS)
    set(NAME_TEST_VECTOR_CNOISE test_vector_cnoise)
    set(NAME_TEST_VECTOR_GEN_CNOISE test_vector_gen_cnoise)
    
    file(GLOB_RECURSE TEST_VECTOR_SOURCE_FILES tests/vector/*.c)
    file(GLOB_RECURSE TEST_VECTOR_GEN_SOURCE_FILES tests/vector-gen/*.c)
    
    add_executable(${NAME_TEST_VECTOR_CNOISE} ${TEST_VECTOR_SOURCE_FILES})
    add_executable(${NAME_TEST_VECTOR_GEN_CNOISE} ${TEST_VECTOR_GEN_SOURCE_FILES})

    target_link_libraries(${NAME_TEST_VECTOR_CNOISE} ${NAME_PROJECT_CNOISE})
    target_include_directories(
        ${NAME_TEST_VECTOR_CNOISE}
        PRIVATE
        src/
    )
    
    target_link_libraries(${NAME_TEST_VECTOR_GEN_CNOISE} ${NAME_PROJECT_CNOISE})
    target_include_directories(
        ${NAME_TEST_VECTOR_GEN_CNOISE}
        PRIVATE
        src/
    )
endif()
