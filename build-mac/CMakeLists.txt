cmake_minimum_required(VERSION 3.16)
project(ROPWeaver_macOS VERSION 1.6.4 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Backward compatibility / safe deprecation for legacy USE_GUI
if(DEFINED USE_GUI)
    message(DEPRECATION "USE_GUI is deprecated; please use BUILD_GUI instead. BUILD_GUI creates an independent 'ropweaver-gui' target without replacing the CLI.")
    if(USE_GUI AND NOT DEFINED BUILD_GUI)
        set(BUILD_GUI ON CACHE BOOL "Build native Qt GUI application" FORCE)
    endif()
endif()

option(BUILD_GUI "Build native Qt GUI application" OFF)

set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Detect Homebrew prefix for Apple Silicon vs Intel
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

# Find required libraries
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# Core sources
set(CORE_SRC
    ${PROJECT_ROOT}/core/arch_detector.cpp
    ${PROJECT_ROOT}/core/chain_builder.cpp
    ${PROJECT_ROOT}/core/gadget.cpp
    ${PROJECT_ROOT}/core/gadget_finder.cpp
    ${PROJECT_ROOT}/core/payload_gen.cpp
    ${PROJECT_ROOT}/core/rop_chain.cpp
    ${PROJECT_ROOT}/core/utils.cpp
    ${PROJECT_ROOT}/core/parsers/aarch64_parser.cpp
    ${PROJECT_ROOT}/core/parsers/armv7_parser.cpp
    ${PROJECT_ROOT}/core/parsers/elf_parser.cpp
    ${PROJECT_ROOT}/core/parsers/macho_parser.cpp
    ${PROJECT_ROOT}/core/parsers/pe_parser.cpp
    ${PROJECT_ROOT}/core/parsers/riscv32_parser.cpp
    ${PROJECT_ROOT}/core/parsers/riscv64_parser.cpp
    ${PROJECT_ROOT}/firebase/firebase_auth.cpp
    ${PROJECT_ROOT}/firebase/firebase_uploader.cpp
)

add_library(ropweaver_core STATIC ${CORE_SRC})

target_include_directories(ropweaver_core PUBLIC
    ${PROJECT_ROOT}
    ${PROJECT_ROOT}/include
    PRIVATE
    ${PROJECT_ROOT}/core
    ${PROJECT_ROOT}/core/parsers
    ${PROJECT_ROOT}/firebase
    ${CAPSTONE_INCLUDE_DIRS}
)

target_link_libraries(ropweaver_core PUBLIC
    ${CAPSTONE_LIBRARIES}
    CURL::libcurl
)

# CLI Executable
add_executable(ropweaver
    ${PROJECT_ROOT}/main.cpp
    ${PROJECT_ROOT}/ui/cli.cpp
)

target_link_libraries(ropweaver PRIVATE ropweaver_core)

# Set rpath for macOS
set_target_properties(ropweaver PROPERTIES
    INSTALL_RPATH "@executable_path/../lib;${HOMEBREW_PREFIX}/lib"
)

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
    set_target_properties(ropweaver-gui PROPERTIES
        INSTALL_RPATH "@executable_path/../lib;${HOMEBREW_PREFIX}/lib"
    )
    install(TARGETS ropweaver-gui DESTINATION bin)
endif()
