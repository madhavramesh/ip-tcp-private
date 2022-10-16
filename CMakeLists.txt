cmake_minimum_required(VERSION 3.0)

project(ip-tcp)

# debugging message
message(STATUS "*** root cmake ***")

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)

set(SOURCES src/main.cpp)

# add subdirectories
add_subdirectory(utils)

add_executable(node ${SOURCES})
target_link_libraries(node pthread utilities ${Boost_LIBRARIES})
target_include_directories(node PRIVATE ${CMAKE_SOURCE_DIR})

# debugging: prints out include directories for node
# get_property(dirs TARGET node PROPERTY INCLUDE_DIRECTORIES)
# foreach(dir ${dirs})
#   message(STATUS "dir='${dir}'")
# endforeach()
