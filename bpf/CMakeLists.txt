cmake_minimum_required(VERSION 3.10)
project(bpflet)

# Set the default build type to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Add the include directory
set(INCLUDE ${CMAKE_SOURCE_DIR})

include_directories(${INCLUDE})

# Add the bpf directories
add_subdirectory(syscall)
add_subdirectory(generic)
add_library(dummy_lib_global EXCLUDE_FROM_ALL oomkill/bpf/oomkill.bpf.c bpf_tracing.h)