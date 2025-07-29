cmake_minimum_required(VERSION 3.10)
project(ROPWeaver)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(USE_GUI "Build with Qt GUI" OFF)

# Define project root
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Include all necessary folders
include_directories(
    ${PROJECT_ROOT}
    ${PROJECT_ROOT}/core
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/firebase
)

# Find required packages
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

include_directories(${CAPSTONE_INCLUDE_DIRS})
link_directories(${CAPSTONE_LIBRARY_DIRS})

# Gather source files
file(GLOB_RECURSE CORE_SRC
    ${PROJECT_ROOT}/core/*.cpp
    ${PROJECT_ROOT}/firebase/*.cpp
    ${PROJECT_ROOT}/include/*.h
)

# Build CLI or GUI based on flag
if(NOT USE_GUI)
    add_executable(ropweaver
        ${PROJECT_ROOT}/main.cpp
        ${CORE_SRC}
        ${PROJECT_ROOT}/ui/cli.cpp
    )
    target_link_libraries(ropweaver
        PRIVATE
            ${CAPSTONE_LIBRARIES}
            CURL::libcurl
    )
else()
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_executable(ropweaver
        ${PROJECT_ROOT}/main_qt.cpp
        ${CORE_SRC}
        ${PROJECT_ROOT}/ui/qt_gui.cpp
    )
    target_link_libraries(ropweaver
        PRIVATE
            ${CAPSTONE_LIBRARIES}
            CURL::libcurl
            Qt5::Widgets
    )
endif()

# Install and messages
install(TARGETS ropweaver DESTINATION bin)

if(USE_GUI)
    message("[MAKE] Building GUI version")
else()
    message("[MAKE] Building CLI version")
endif()

message(STATUS "To build CLI: cmake -DUSE_GUI=OFF . && make")
message(STATUS "To build GUI: cmake -DUSE_GUI=ON . && make")
