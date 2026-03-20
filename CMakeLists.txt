cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

option(SNDIO "Use sndio audio interface." OFF)

set(XXCORE xxcore)

set(CMAKE_EXPORT_COMPILE_COMMANDS YES)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_COMPILER clang++)
file(GLOB_RECURSE SRC_FILES src/*.cpp)

project(${XXCORE})
add_executable(${XXCORE} ${SRC_FILES})
        
set(OPUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/opus)
set(OPUS_INCLUDE_DIR ${OPUS_DIR}/include)
set(OPUS_BUILD_SHARED_LIBRARY ON)
set(OPUS_VAR_ARRAYS ON)
set(OPUS_NONTHREADSAFE_PSEUDOSTACK OFF)
set(OPUS_USE_ALLOCA OFF)
add_subdirectory(${OPUS_DIR})	

include(cmake/noise_c_target.cmake)
add_dependencies(${XXCORE} ${NOISE_C})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -g")

target_include_directories(
    ${XXCORE}
    PUBLIC 
    src/
    ${LIBBOOST_INCLUDE_DIR}
    ${OPUS_INCLUDE_DIR}
	${NOISE_C_INCLUDE_DIR}
)
target_link_libraries(
    ${XXCORE}
    PRIVATE
    Opus::opus
    ${NOISE_C_LIBS}
)

if(SNDIO AND (LINUX OR BSD))
	find_library(LIBSNDIO NAMES sndio)
        if("${LIBSNDIO}" STREQUAL "LIBSNDIO-NOTFOUND")	
		message(FATAL_ERROR "[sndio] lib was not found.")
	endif()
	
	message(STATUS "Building with sndio.")
	target_link_libraries(${XXCORE} PRIVATE ${LIBSNDIO})
	target_compile_options(${XXCORE} PRIVATE "-DSNDIO")
elseif(LINUX)
	find_package(ALSA)
	
    set(AUDIO_SYSTEM "ALSA")
    target_link_libraries(${XXCORE} PRIVATE ALSA::ALSA)
	target_compile_options(${XXCORE} PRIVATE "-DALSA")
elseif(BSD)
	message(STATUS "Building with ${CMAKE_SYSTEM_NAME} audio.")
	if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		target_compile_options(${XXCORE} PRIVATE "-DFREEBSD_AUDIO")
	elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
		target_compile_options(${XXCORE} PRIVATE "-DOPENBSD_AUDIO")
	elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
		target_compile_options(${XXCORE} PRIVATE "-DNETBSD_AUDIO")
	endif()
endif()
