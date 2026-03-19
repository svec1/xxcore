set(NOISE_C noise_c)
set(NOISE_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/noise-c)

file(GLOB_RECURSE NOISE_C_SOURCE_FILES ${NOISE_C_DIR}/src/*)
set(NOISE_C_INCLUDE_DIR ${NOISE_C_DIR}/include ${NOISE_C_DIR}/src/crypto)
set(
    NOISE_C_CONFIGURE_OUTPUT
    ${NOISE_C_DIR}/src/Makefile
    ${NOISE_C_DIR}/src/protocol/Makefile
    ${NOISE_C_DIR}/src/keys/Makefile
)

set(
    NOISE_C_LIBS
    ${NOISE_C_DIR}/src/protocol/libnoiseprotocol.a
    ${NOISE_C_DIR}/src/keys/libnoisekeys.a
)

add_custom_command(
    OUTPUT ${NOISE_C_DIR}/configure
    WORKING_DIRECTORY ${NOISE_C_DIR}
    COMMAND ${NOISE_C_DIR}/autogen.sh > /dev/null
    VERBATIM
)

add_custom_command(
    OUTPUT ${NOISE_C_CONFIGURE_OUTPUT}
    WORKING_DIRECTORY ${NOISE_C_DIR}
    COMMAND ${NOISE_C_DIR}/configure > /dev/null
    DEPENDS ${NOISE_C_DIR}/configure
    VERBATIM
)

add_custom_target(
    ${NOISE_C}
    WORKING_DIRECTORY ${NOISE_C_DIR}
    COMMAND make > /dev/null
    DEPENDS ${NOISE_C_CONFIGURE_OUTPUT}
    VERBATIM
)
