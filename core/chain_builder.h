#pragma once
#include "rop_chain.h"
#include "gadget.h"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#if __has_include("parsers/file_parser.h")
#include "parsers/file_parser.h"
#elif __has_include("file_parser.h")
#include "file_parser.h"
#elif __has_include("core/parsers/file_parser.h")
#include "core/parsers/file_parser.h"
#else
class FileParser;
#endif

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string path;
};

class ChainBuilder {
public:
    /**
     * @brief Construct a ChainBuilder for ROP chain synthesis.
     *
     * @param gadgets Available ROP gadgets.
     * @param arch Target architecture string (e.g. "x86_64", "armv7", "riscv64").
     * @param fileType Binary container format ("ELF", "PE", or "Mach-O").
     * @param parser Optional pointer to FileParser providing container and ABI metadata.
     *
     * @note When parser is nullptr (such as legacy or unit test calls via the 3-argument signature),
     *       container-level ABI metadata (e.g. ARM EABI version, RISC-V RVE/OSABI) cannot be inspected
     *       and is left UNVERIFIED. A chain synthesized without parser metadata must NOT be treated
     *       or described as ABI-validated. The production path in main.cpp always supplies parser.get().
     */
    ChainBuilder(const std::vector<Gadget>& gadgets, const std::string& arch,
                 const std::string& fileType = "ELF", const FileParser* parser = nullptr);

    std::optional<Gadget> findOptimalPopGadget(const std::string& reg);
    std::optional<Gadget> findSpecificGadget(const std::string& instruction);

    ROPChain buildExecveChain(const std::vector<MemoryRegion>& memoryRegions);
    ROPChain buildExecveChain(uint64_t binsh_addr, uint64_t argv_addr = 0, uint64_t envp_addr = 0);
    uint64_t findBinShAddress(const std::vector<MemoryRegion>& memoryRegions);
    uint64_t findDarwinArgvAddress(uint64_t binsh_addr);
    uint64_t findDarwinEnvpAddress();

private:
    std::vector<Gadget> rop_gadgets;
    std::string m_arch;
    std::string m_fileType;
    const FileParser* m_parser = nullptr;
    
    ROPChain buildExecveChainInternal(uint64_t binsh_addr, uint64_t argv_addr = 0, uint64_t envp_addr = 0);
};
