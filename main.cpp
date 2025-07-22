// main.cpp
#include <iostream>
#include <vector>
#include "include/ropweaver.h"
#include "core/elf_parser.h"
#include "core/arch_detector.h"
#include "core/gadget_finder.h"
#include "core/chain_builder.h"
#include "core/utils.h"
#include "core/gadget.h"
#include "core/rop_chain.h"

#include "ui/cli.h"
#include "firebase/firebase_uploader.h"

int main(int argc, char* argv[]) {
    std::cout << "=== ROPWeaver: ROP Exploit Generator ===" << std::endl;

    CLI cli;
    CLIOptions options = cli.parseArguments(argc, argv);

    if (!options.valid) {
        cli.printUsage();
        return 1;
    }

    ELFParser elf(options.filename);
    if (!elf.parse() || !elf.isValidELF()) {
        std::cerr << "[Error] Invalid ELF binary: " << options.filename << std::endl;
        return 1;
    }

    ArchDetector detector;
    std::string arch = detector.detectArchitecture(elf);
    std::cout << "[*] Detected architecture: " << arch << std::endl;

    std::vector<uint8_t> binaryCode = elf.getTextSection();
    GadgetFinder finder(binaryCode, arch);

    finder.findGadgets();
    std::vector<Gadget> gadgets = finder.getGadgets();

    std::cout << "[*] Found " << gadgets.size() << " gadgets." << std::endl;

    if (options.listGadgets) {
        for (const auto& g : gadgets) {
            std::cout << "  0x" << std::hex << g.address << ": " << g.instruction << std::endl;
        }
        return 0;
    }

    if (options.autoChain) {
        ChainBuilder builder(gadgets);
        std::string chain = builder.buildExecveChain("/bin/sh").toString();
        
         if (chain.empty() || chain.find("Unable") != std::string::npos) {
            std::cerr << "[!] Failed to build ROP chain." << std::endl;
            return 1;
        }

        std::cout << "[+] ROP chain created successfully:\n" << chain << std::endl;
        std::cout << chain << std::endl;

        if (options.uploadReport) {
            FirebaseUploader uploader("config/firebase_config.json");
            if (uploader.uploadReport("reports/output.json")) {
                std::cout << "[+] Report uploaded to Firebase." << std::endl;
            } else {
                std::cerr << "[!] Firebase upload failed." << std::endl;
            }
        }
    }

    return 0;
}
