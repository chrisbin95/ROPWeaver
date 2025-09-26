#ifndef GADGET_FINDER_H
#define GADGET_FINDER_H

#include <capstone/capstone.h>
#include <vector>
#include <string>
#include <map>
#include "gadget.h"

class GadgetFinder {
public:
    GadgetFinder(const std::vector<unsigned char>& code,
                 uint64_t base,
                 const std::string& arch,
                 const std::string& binary_path,
                 size_t maxSize = 10);

    ~GadgetFinder();

    void findGadgets();
    std::vector<Gadget> getGadgets() const { return m_gadgets; }

    std::map<std::string, std::vector<Gadget>> categorizeGadgets() const;

private:
    std::vector<unsigned char> m_code;
    uint64_t m_baseAddress;
    std::string m_arch;
    // FIX: Add m_binaryPath to the private members
    std::string m_binaryPath; 
    size_t m_maxSize;

    csh handle;
    cs_arch arch_id;
    cs_mode mode;

    std::vector<Gadget> m_gadgets;

};

#endif // GADGET_FINDER_H