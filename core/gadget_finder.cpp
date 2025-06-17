// gadget_finder.cpp
#include "gadget_finder.h"
#include <iostream>

GadgetFinder::GadgetFinder(const std::vector<uint8_t>& code, const std::string& arch)
    : binary_code(code), architecture(arch), handle(0) {}

void GadgetFinder::findGadgets() {
    // Capstone disassembly to find ROP gadgets
    // Populate gadgets vector
}

std::vector<std::string> GadgetFinder::getGadgets() const {
    return gadgets;
}