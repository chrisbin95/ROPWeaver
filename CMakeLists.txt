cmake_minimum_required(VERSION 3.16)
project(ROPWeaver VERSION 1.6.3 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optional components
option(BUILD_TESTS "Build test executables" ON)
option(USE_GUI "Build with experimental Qt GUI (Developer prototype)" OFF)

# Platform-specific dependency discovery: macOS Homebrew
if(APPLE)
    if(EXISTS "/opt/homebrew")
        set(HOMEBREW_PREFIX "/opt/homebrew")
    elseif(EXISTS "/usr/local")
        set(HOMEBREW_PREFIX "/usr/local")
    endif()

    if(HOMEBREW_PREFIX)
        list(APPEND CMAKE_PREFIX_PATH "${HOMEBREW_PREFIX}")
        set(ENV{PKG_CONFIG_PATH} "${HOMEBREW_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        include_directories("${HOMEBREW_PREFIX}/include")
        link_directories("${HOMEBREW_PREFIX}/lib")
    endif()
endif()

# Required packages
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# Core library source files
set(CORE_SRC
    core/arch_detector.cpp
    core/chain_builder.cpp
    core/gadget.cpp
    core/gadget_finder.cpp
    core/payload_gen.cpp
    core/rop_chain.cpp
    core/utils.cpp
    core/parsers/aarch64_parser.cpp
    core/parsers/armv7_parser.cpp
    core/parsers/elf_parser.cpp
    core/parsers/macho_parser.cpp
    core/parsers/pe_parser.cpp
    core/parsers/riscv32_parser.cpp
    core/parsers/riscv64_parser.cpp
    firebase/firebase_uploader.cpp
)

# Core static library
add_library(ropweaver_core STATIC ${CORE_SRC})

target_include_directories(ropweaver_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/core/parsers
    ${CMAKE_CURRENT_SOURCE_DIR}/firebase
    ${CAPSTONE_INCLUDE_DIRS}
)

target_link_directories(ropweaver_core PUBLIC
    ${CAPSTONE_LIBRARY_DIRS}
)

target_link_libraries(ropweaver_core PUBLIC
    ${CAPSTONE_LIBRARIES}
    CURL::libcurl
)

# Test executable (execve_chain_test)
if(BUILD_TESTS)
    add_executable(execve_chain_test
        execve_chain_test/execve_chain_test.cpp
    )
    target_link_libraries(execve_chain_test PRIVATE ropweaver_core)
endif()

# Main executable (CLI or experimental GUI)
if(NOT USE_GUI)
    add_executable(ropweaver
        main.cpp
        ui/cli.cpp
    )
    target_link_libraries(ropweaver PRIVATE ropweaver_core)
else()
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTORCC ON)
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_executable(ropweaver
        main_qt.cpp
        ui/qt_gui.cpp
    )
    target_link_libraries(ropweaver PRIVATE ropweaver_core Qt5::Widgets)
endif()

# Set RPATH for macOS
if(APPLE AND HOMEBREW_PREFIX)
    set_target_properties(ropweaver PROPERTIES
        INSTALL_RPATH "@executable_path/../lib;${HOMEBREW_PREFIX}/lib"
    )
endif()

install(TARGETS ropweaver DESTINATION bin)
if(BUILD_TESTS)
    install(TARGETS execve_chain_test DESTINATION bin)
endif()
