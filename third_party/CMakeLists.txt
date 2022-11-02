message(STATUS "*** third_party cmake ***")

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

add_library(third_party bonsai.c)
target_link_libraries(third_party ${CURSES_LIBRARIES})
