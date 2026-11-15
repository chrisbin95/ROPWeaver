#ifndef GADGET_FINDER_H
#define GADGET_FINDER_H

#include <capstone/capstone.h>
#include <vector>
#include <string>
#include <map>
#include "gadget.h"
#include "parsers/file_parser.h"

class GadgetFinder {
public:
    GadgetFinder(const std::vector<unsigned char>& code,
                 uint64_t base,
                 const std::string& arch,
                 const std::string& binary_path,
                 size_t maxSize = 10,
                 Endianness instruction_endianness = Endianness::Little,
                 bool rvc_enabled = false,
                 const std::vector<ArmCodeRegion>& arm_regions = {});

    GadgetFinder(const std::vector<unsigned char>& code,
                 uint64_t base,
                 const std::string& arch,
                 const std::string& binary_path,
                 const std::vector<ExecBufferMapping>& mappings,
                 size_t maxSize = 10,
                 Endianness instruction_endianness = Endianness::Little,
                 bool rvc_enabled = false,
                 const std::vector<ArmCodeRegion>& arm_regions = {});

    ~GadgetFinder();

    void findGadgets();
    std::vector<Gadget>& getGadgets() { return m_gadgets; }
    const std::vector<Gadget>& getGadgets() const { return m_gadgets; }

    Endianness getInstructionEndianness() const { return m_instruction_endianness; }
    bool isRvcEnabled() const { return m_rvc_enabled; }
    const std::vector<ArmCodeRegion>& getArmCodeRegions() const { return m_arm_regions; }

    std::string determineCategory(const Gadget& g) const;
    std::map<std::string, std::vector<Gadget>> categorizeGadgets();
    std::map<std::string, std::vector<Gadget>> categorizeGadgets() const;

private:
    std::vector<unsigned char> m_code;
    uint64_t m_baseAddress;
    std::string m_arch;
    // FIX: Add m_binaryPath to the private members
    std::string m_binaryPath; 
    size_t m_maxSize;
    std::vector<ExecBufferMapping> m_mappings;
    Endianness m_instruction_endianness;
    bool m_rvc_enabled = false;
    std::vector<ArmCodeRegion> m_arm_regions;

    csh handle;
    csh thumb_handle = 0;
    cs_arch arch_id;
    cs_mode mode;

    std::vector<Gadget> m_gadgets;

};

#endif // GADGET_FINDER_H