cmake_minimum_required(VERSION 3.10)
project(ROPWeaver)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(USE_GUI "Build with Qt GUI" OFF)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/ui
    ${CMAKE_SOURCE_DIR}/firebase
    ${CMAKE_SOURCE_DIR}/include
)

# Gather core source files
file(GLOB_RECURSE CORE_SRC
    core/*.cpp
    firebase/*.cpp
    include/*.h
)

# CLI build
if(NOT USE_GUI)
    add_executable(ropweaver main.cpp ${CORE_SRC} ui/cli.cpp)
else()
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_executable(ropweaver main_qt.cpp ${CORE_SRC} ui/qt_gui.cpp)
    target_link_libraries(ropweaver Qt5::Widgets)
endif()

# Optional: install rules
install(TARGETS ropweaver DESTINATION bin)

# Makefile fallback
# Run: make cli or make gui
# > To build CLI:
# cmake -DUSE_GUI=OFF .
# make

# > To build GUI (Qt required):
# cmake -DUSE_GUI=ON .
# make
if(DEFINED ENV{USE_GUI})
    message("[MAKE] Building GUI version")
else()
    message("[MAKE] Building CLI version")
endif()
