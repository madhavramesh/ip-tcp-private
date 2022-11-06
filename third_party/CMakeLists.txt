message(STATUS "*** third_party cmake ***")

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

add_executable(bonsai bonsai.c)
target_link_libraries(bonsai PUBLIC ncursesw tinfo panelw)
target_include_directories(bonsai PUBLIC ${CMAKE_SOURCE_DIR})
