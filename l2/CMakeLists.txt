cmake_minimum_required(VERSION 3.10)

project(cpp-network-lesson-2 C CXX)

if (UNIX)
    add_subdirectory("linux_call_intercepter")
endif()

add_subdirectory("pcappp")
