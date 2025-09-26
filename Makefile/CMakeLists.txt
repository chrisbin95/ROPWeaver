cmake_minimum_required(VERSION 3.10)
project(ROPWeaver)

set(CMAKE_CXX_STANDARD 17)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Qt automation (only used if USE_GUI)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(USE_GUI "Build with Qt GUI" OFF)
option(BUILD_TESTS "Build test executables" ON)

# --- REQUIRED PACKAGES ---
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
# PkgConfig for Capstone (Standard method for libraries without a modern CMake find module)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# --- CORE SOURCE FILES (RECOMMENDED TO LIST EXPLICITLY) ---
# Listing files explicitly is preferred over GLOB_RECURSE
set(CORE_SRC
    # Core
    ${PROJECT_ROOT}/core/arch_detector.cpp
    ${PROJECT_ROOT}/core/chain_builder.cpp
    ${PROJECT_ROOT}/core/gadget.cpp
    ${PROJECT_ROOT}/core/gadget_finder.cpp
    ${PROJECT_ROOT}/core/payload_gen.cpp
    ${PROJECT_ROOT}/core/rop_chain.cpp
    ${PROJECT_ROOT}/core/utils.cpp
    
    # Parsers
    ${PROJECT_ROOT}/core/parsers/aarch64_parser.cpp
    ${PROJECT_ROOT}/core/parsers/armv7_parser.cpp
    ${PROJECT_ROOT}/core/parsers/elf_parser.cpp
    ${PROJECT_ROOT}/core/parsers/macho_parser.cpp
    ${PROJECT_ROOT}/core/parsers/pe_parser.cpp
    ${PROJECT_ROOT}/core/parsers/riscv32_parser.cpp
    ${PROJECT_ROOT}/core/parsers/riscv64_parser.cpp

    # Firebase
    ${PROJECT_ROOT}/firebase/firebase_uploader.cpp
)

# --- CORE STATIC LIBRARY ---
add_library(ropweaver_core STATIC ${CORE_SRC})

# Target-specific properties for include paths
target_include_directories(ropweaver_core PUBLIC
    # Public includes for consumers of the library (like execve_chain_test)
    ${PROJECT_ROOT}/include
    
    # Internal includes (Private)
    PRIVATE
    ${PROJECT_ROOT}/core
    ${PROJECT_ROOT}/core/parsers
    ${PROJECT_ROOT}/firebase
    ${CAPSTONE_INCLUDE_DIRS} # Capstone includes
)

# Link dependencies to the library
target_link_libraries(ropweaver_core PUBLIC 
    ${CAPSTONE_LIBRARIES} 
    CURL::libcurl
)

# --- BUILD EXECUTABLES ---

# Test executable
if(BUILD_TESTS)
    add_executable(execve_chain_test
        ${PROJECT_ROOT}/execve_chain_test/execve_chain_test.cpp
    )
    # Link to the static core library
    target_link_libraries(execve_chain_test PRIVATE ropweaver_core)
    install(TARGETS execve_chain_test DESTINATION bin)
endif()

# Main executable (CLI or GUI)
if(NOT USE_GUI)
    add_executable(ropweaver
        ${PROJECT_ROOT}/main.cpp
        ${PROJECT_ROOT}/ui/cli.cpp
    )
    target_link_libraries(ropweaver PRIVATE ropweaver_core)
else()
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_executable(ropweaver
        ${PROJECT_ROOT}/main_qt.cpp
        ${PROJECT_ROOT}/ui/qt_gui.cpp
    )
    target_link_libraries(ropweaver PRIVATE ropweaver_core Qt5::Widgets)
endif()

# Install main executable
install(TARGETS ropweaver DESTINATION bin)

# Build messages
if(USE_GUI)
    message("[MAKE] Building GUI version")
else()
    message("[MAKE] Building CLI version")
endif()

message(STATUS "To build CLI: cmake -DUSE_GUI=OFF . && make")
message(STATUS "To build GUI: cmake -DUSE_GUI=ON . && make")