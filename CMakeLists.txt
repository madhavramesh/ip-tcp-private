cmake_minimum_required(VERSION 3.0)

# debugging message
message(STATUS "*** root cmake ***")

project(ip)
set(SOURCES src/main.cpp)

# add subdirectories
add_subdirectory(utils)

add_executable(node ${SOURCES})
target_link_libraries(node utilities)
target_include_directories(node PRIVATE ${CMAKE_SOURCE_DIR})

# debugging: prints out include directories for node
# get_property(dirs TARGET node PROPERTY INCLUDE_DIRECTORIES)
# foreach(dir ${dirs})
#   message(STATUS "dir='${dir}'")
# endforeach()
