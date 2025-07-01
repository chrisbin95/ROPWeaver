cmake_minimum_required(VERSION 3.10)
project(ROPWeaver)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(USE_GUI "Build with Qt GUI" OFF)

# Adjusted relative paths since CMakeLists.txt is inside Makefile/
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

include_directories(${PROJECT_ROOT})

# Gather source files
file(GLOB_RECURSE CORE_SRC
    ${PROJECT_ROOT}/core/*.cpp
    ${PROJECT_ROOT}/firebase/*.cpp
    ${PROJECT_ROOT}/include/*.h
)

# CLI build
if(NOT USE_GUI)
    add_executable(ropweaver ${PROJECT_ROOT}/main.cpp ${CORE_SRC} ${PROJECT_ROOT}/ui/cli.cpp)
else()
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_executable(ropweaver ${PROJECT_ROOT}/main_qt.cpp ${CORE_SRC} ${PROJECT_ROOT}/ui/qt_gui.cpp)
    target_link_libraries(ropweaver Qt5::Widgets)
endif()

install(TARGETS ropweaver DESTINATION bin)

if(DEFINED ENV{USE_GUI})
    message("[MAKE] Building GUI version")
else()
    message("[MAKE] Building CLI version")
endif()

# Makefile fallback
# Run: make cli or make gui
# > To build CLI:
# cmake -DUSE_GUI=OFF .
# make

# > To build GUI (Qt required):
# cmake -DUSE_GUI=ON .
# make
