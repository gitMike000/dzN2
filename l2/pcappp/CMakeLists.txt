cmake_minimum_required(VERSION 3.10)

project(pcappp C CXX)

set(${PROJECT_NAME}_SRC main.cpp)

source_group(source FILES ${${PROJECT_NAME}_SRC}})

add_executable("${PROJECT_NAME}" "${${PROJECT_NAME}_SRC}")

#target_include_directories("${PROJECT_NAME}" PRIVATE /home/mike/git/dzN2/libpcap++/include/pcapplusplus/)
#target_link_directories("${PROJECT_NAME}" PRIVATE /home/mike/git/dzN2/libpcap++/lib)

target_include_directories("${PROJECT_NAME}" PRIVATE ../../libpcap++/include/pcapplusplus/)
target_link_directories("${PROJECT_NAME}" PRIVATE ../../libpcap++/lib)
target_link_libraries("${PROJECT_NAME}" PRIVATE Pcap++ Packet++ Common++ pcap pthread)


