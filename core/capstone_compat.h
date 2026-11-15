#pragma once

#include <capstone/capstone.h>

// Capstone compatibility definitions for RISC-V compressed (RVC) mode.
//
// Architectural Note:
// CS_MODE_RISCVC is an enumerator declared inside 'enum cs_mode' in capstone.h,
// NOT a preprocessor #define macro. Direct usage of '#ifdef CS_MODE_RISCVC'
// is invalid C/C++ preprocessor logic and silently evaluates to false.
//
// We establish a valid compile-time compatibility strategy using Capstone's
// official API version macros: CS_API_MAJOR and CS_API_MINOR.

#if defined(CS_API_MAJOR) && (CS_API_MAJOR >= 5)
// Capstone 5.0+ natively provides CS_MODE_RISCVC in cs_mode
constexpr cs_mode ROPW_CS_MODE_RISCVC = CS_MODE_RISCVC;
constexpr bool ROPW_CAPSTONE_HAS_RVC = true;
#elif defined(CS_API_MAJOR) && (CS_API_MAJOR == 4 && CS_API_MINOR >= 0)
// Capstone 4.x supports RISC-V C extension via mode bit 2 (1 << 2)
constexpr cs_mode ROPW_CS_MODE_RISCVC = static_cast<cs_mode>(1 << 2);
constexpr bool ROPW_CAPSTONE_HAS_RVC = true;
#else
// Legacy Capstone without RISC-V compressed mode support
constexpr cs_mode ROPW_CS_MODE_RISCVC = static_cast<cs_mode>(0);
constexpr bool ROPW_CAPSTONE_HAS_RVC = false;
#endif

