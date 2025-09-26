#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include "gadget.h"

inline std::string GadgetToString(const Gadget& g) {
    return g.toString(); // use the Gadget's toString() method
}

class Utils {
public:
    static std::vector<uint8_t> readBinaryFile(const std::string& path);
    static void writeToFile(const std::string& path, const std::string& content);
};
