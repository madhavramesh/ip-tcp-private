cmake_minimum_required(VERSION 3.0)
project(ip-tcp)

# set c++ version
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# debugging message
message(STATUS "*** root cmake ***")

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)

# anytime new cpp file used in main, need to add here
set(SOURCES src/main.cpp src/IP/Node.cpp src/repl/REPL.cpp src/IP/IPCommands.cpp
    src/Link/UDPLink.cpp)

# add subdirectories
add_subdirectory(utils)
add_subdirectory(third_party)

add_executable(node ${SOURCES})
target_link_libraries(node pthread third_party utilities ${Boost_LIBRARIES})
target_include_directories(node PRIVATE ${CMAKE_SOURCE_DIR})

# debugging: prints out include directories for node
# get_property(dirs TARGET node PROPERTY INCLUDE_DIRECTORIES)
# foreach(dir ${dirs})
#   message(STATUS "dir='${dir}'")
# endforeach()
