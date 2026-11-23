cmake_minimum_required(VERSION 3.10)
project(ROPWeaver)

set(CMAKE_CXX_STANDARD 17)
set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

option(BUILD_TESTS "Build test executables" ON)

# Backward compatibility / safe deprecation for legacy USE_GUI
if(DEFINED USE_GUI)
    message(DEPRECATION "USE_GUI is deprecated; please use BUILD_GUI instead. BUILD_GUI creates an independent 'ropweaver-gui' target without replacing the CLI.")
    if(USE_GUI AND NOT DEFINED BUILD_GUI)
        set(BUILD_GUI ON CACHE BOOL "Build native Qt GUI application" FORCE)
    endif()
endif()

option(BUILD_GUI "Build native Qt GUI application" OFF)

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
    ${PROJECT_ROOT}/firebase/firebase_auth.cpp
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

# CLI executable (always built)
add_executable(ropweaver
    ${PROJECT_ROOT}/main.cpp
    ${PROJECT_ROOT}/ui/cli.cpp
)
target_link_libraries(ropweaver PRIVATE ropweaver_core)
install(TARGETS ropweaver DESTINATION bin)

# Optional Qt GUI executable (independent target)
if(BUILD_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTORCC ON)

    # Discover Qt 6 Widgets with Qt 5 fallback
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
    find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

    add_executable(ropweaver-gui
        ${PROJECT_ROOT}/main_qt.cpp
        ${PROJECT_ROOT}/ui/qt_gui.cpp
        ${PROJECT_ROOT}/ui/qt_gui.h
    )
    target_include_directories(ropweaver-gui PRIVATE
        ${PROJECT_ROOT}
        ${PROJECT_ROOT}/ui
    )
    target_link_libraries(ropweaver-gui PRIVATE
        ropweaver_core
        Qt${QT_VERSION_MAJOR}::Widgets
    )
    install(TARGETS ropweaver-gui DESTINATION bin)
endif()

# Build status message
if(BUILD_GUI)
    message(STATUS "[BUILD] Building CLI (ropweaver) and GUI (ropweaver-gui)")
else()
    message(STATUS "[BUILD] Building CLI (ropweaver) only")
endif()