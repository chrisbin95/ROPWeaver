// gadget_finder.h
#pragma once
#include "gadget.h"
#include <vector>
#include <string>
#include <capstone/capstone.h>

class GadgetFinder {
public:
    GadgetFinder(const std::vector<uint8_t>& code, const std::string& arch);
    void findGadgets();
    std::vector<Gadget> getGadgets() const;
private:
    std::vector<uint8_t> binary_code;
    //std::vector<std::string> gadgets;
    std::string architecture;
    std::vector<Gadget> gadgets;
    csh handle;
};