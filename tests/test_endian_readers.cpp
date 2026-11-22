#include <cstddef>
#include <cstdint>
#include <iostream>
#include "../core/parsers/elf_defs.h"

using namespace ropweaver;

int main() {
    int failures = 0;

    auto check32 = [&](const char* name, int32_t got, int32_t expected) {
        if (got != expected) {
            std::cerr << "FAIL [32-bit]: " << name << " got " << got << " expected " << expected << "\n";
            failures++;
        } else {
            std::cout << "PASS [32-bit]: " << name << " = " << got << "\n";
        }
    };

    auto check64 = [&](const char* name, int64_t got, int64_t expected) {
        if (got != expected) {
            std::cerr << "FAIL [64-bit]: " << name << " got " << got << " expected " << expected << "\n";
            failures++;
        } else {
            std::cout << "PASS [64-bit]: " << name << " = " << got << "\n";
        }
    };

    // 1. Zero
    uint8_t zero32[4] = {0x00, 0x00, 0x00, 0x00};
    check32("Zero LE", read_i32(zero32, false), 0);
    check32("Zero BE", read_i32(zero32, true), 0);

    uint8_t zero64[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    check64("Zero LE", read_i64(zero64, false), 0);
    check64("Zero BE", read_i64(zero64, true), 0);

    // 2. Positive values
    uint8_t pos32_le[4] = {0x78, 0x56, 0x34, 0x12};
    uint8_t pos32_be[4] = {0x12, 0x34, 0x56, 0x78};
    check32("Positive 305419896 LE", read_i32(pos32_le, false), 305419896);
    check32("Positive 305419896 BE", read_i32(pos32_be, true), 305419896);

    uint8_t pos64_le[8] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t pos64_be[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    check64("Positive 81985529216486895 LE", read_i64(pos64_le, false), 81985529216486895LL);
    check64("Positive 81985529216486895 BE", read_i64(pos64_be, true), 81985529216486895LL);

    // 3. -1
    uint8_t neg1_32[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    check32("-1 LE", read_i32(neg1_32, false), -1);
    check32("-1 BE", read_i32(neg1_32, true), -1);

    uint8_t neg1_64[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    check64("-1 LE", read_i64(neg1_64, false), -1LL);
    check64("-1 BE", read_i64(neg1_64, true), -1LL);

    // 4. INT32_MIN (-2147483648 = 0x80000000) and INT32_MAX (2147483647 = 0x7FFFFFFF)
    uint8_t int32_min_le[4] = {0x00, 0x00, 0x00, 0x80};
    uint8_t int32_min_be[4] = {0x80, 0x00, 0x00, 0x00};
    check32("INT32_MIN LE", read_i32(int32_min_le, false), INT32_MIN);
    check32("INT32_MIN BE", read_i32(int32_min_be, true), INT32_MIN);

    uint8_t int32_max_le[4] = {0xFF, 0xFF, 0xFF, 0x7F};
    uint8_t int32_max_be[4] = {0x7F, 0xFF, 0xFF, 0xFF};
    check32("INT32_MAX LE", read_i32(int32_max_le, false), INT32_MAX);
    check32("INT32_MAX BE", read_i32(int32_max_be, true), INT32_MAX);

    // 5. INT64_MIN (-9223372036854775808LL = 0x8000000000000000ULL) and INT64_MAX (9223372036854775807LL = 0x7FFFFFFFFFFFFFFFULL)
    uint8_t int64_min_le[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
    uint8_t int64_min_be[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    check64("INT64_MIN LE", read_i64(int64_min_le, false), INT64_MIN);
    check64("INT64_MIN BE", read_i64(int64_min_be, true), INT64_MIN);

    uint8_t int64_max_le[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    uint8_t int64_max_be[8] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    check64("INT64_MAX LE", read_i64(int64_max_le, false), INT64_MAX);
    check64("INT64_MAX BE", read_i64(int64_max_be, true), INT64_MAX);

    // 6. ELF Dynamic tags
    uint8_t dt_flags1_le[8] = {0xFB, 0xFF, 0xFF, 0x6F, 0x00, 0x00, 0x00, 0x00};
    uint8_t dt_flags1_be[8] = {0x00, 0x00, 0x00, 0x00, 0x6F, 0xFF, 0xFF, 0xFB};
    check64("DT_FLAGS_1 LE", read_i64(dt_flags1_le, false), 0x6ffffffbLL);
    check64("DT_FLAGS_1 BE", read_i64(dt_flags1_be, true), 0x6ffffffbLL);

    return failures == 0 ? 0 : 1;
}

