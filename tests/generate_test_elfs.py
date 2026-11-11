#!/usr/bin/env python3
"""
generate_test_elfs.py
Generates valid minimal ELF32 and ELF64 test binaries for ROPWeaver regression testing.
Architectures generated:
- x86 (ELF32, EM_386)
- ARMv7 (ELF32, EM_ARM)
- AArch64 (ELF64, EM_AARCH64)
- RISC-V 32 (ELF32, EM_RISCV)
- RISC-V 64 (ELF64, EM_RISCV)
"""
import struct
import os

def create_elf32(filename, machine, code_bytes, base_va=0x08048000, has_gnu_stack=True, nx=True):
    # ELF Header: 52 bytes
    # e_ident: 16 bytes
    # EI_MAG: \x7fELF
    # EI_CLASS: 1 (ELFCLASS32)
    # EI_DATA: 1 (ELFDATA2LSB)
    # EI_VERSION: 1
    # EI_OSABI: 0
    # EI_ABIVERSION: 0
    # Pad to 16
    e_ident = b"\x7fELF\x01\x01\x01\x00\x00" + b"\x00" * 7
    e_type = 2 # ET_EXEC
    e_machine = machine
    e_version = 1
    
    ehdr_size = 52
    phdr_size = 32
    shdr_size = 40
    
    # 2 Program Headers:
    # 0: PT_LOAD
    # 1: PT_GNU_STACK (optional)
    num_phdrs = 2 if has_gnu_stack else 1
    phoff = ehdr_size
    
    # Section layout:
    # After phdrs: .text section
    code_off = phoff + (num_phdrs * phdr_size)
    # Align code to 16 bytes
    if code_off % 16 != 0:
        code_off += (16 - (code_off % 16))
    
    code_va = base_va + (code_off % 0x1000)
    e_entry = code_va
    code_size = len(code_bytes)
    
    # After code: .shstrtab
    shstrtab_off = code_off + code_size
    if shstrtab_off % 4 != 0:
        shstrtab_off += (4 - (shstrtab_off % 4))
    
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab)
    
    # Section Header Table:
    # 0: NULL
    # 1: .text (SHF_ALLOC | SHF_EXECINSTR = 6)
    # 2: .shstrtab (SHT_STRTAB = 3)
    shoff = shstrtab_off + shstrtab_size
    if shoff % 4 != 0:
        shoff += (4 - (shoff % 4))
    num_shdrs = 3
    shstrndx = 2
    
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry,
        phoff, shoff, 0, ehdr_size, phdr_size, num_phdrs,
        shdr_size, num_shdrs, shstrndx
    )
    
    # Program Headers:
    # PT_LOAD = 1
    pt_load_filesz = (code_off + code_size)
    pt_load_memsz = pt_load_filesz
    phdr_load = struct.pack(
        "<IIIIIIII",
        1, 0, base_va, base_va, pt_load_filesz, pt_load_memsz, 7, 0x1000 # PF_R|PF_W|PF_X = 7
    )
    
    phdrs = phdr_load
    if has_gnu_stack:
        # PT_GNU_STACK = 0x6474e551
        flags = 6 if nx else 7 # PF_R|PF_W (no PF_X = NX enabled)
        phdr_stack = struct.pack(
            "<IIIIIIII",
            0x6474e551, 0, 0, 0, 0, 0, flags, 0x10
        )
        phdrs += phdr_stack
        
    # Build complete file
    file_bytes = bytearray(ehdr)
    file_bytes += phdrs
    # Pad to code_off
    if len(file_bytes) < code_off:
        file_bytes += b"\x00" * (code_off - len(file_bytes))
    file_bytes += code_bytes
    
    # Pad to shstrtab_off
    if len(file_bytes) < shstrtab_off:
        file_bytes += b"\x00" * (shstrtab_off - len(file_bytes))
    file_bytes += shstrtab
    
    # Pad to shoff
    if len(file_bytes) < shoff:
        file_bytes += b"\x00" * (shoff - len(file_bytes))
        
    # Section Header 0: NULL
    sh0 = b"\x00" * shdr_size
    # Section Header 1: .text
    # sh_name = 1 (".text"), sh_type = 1 (SHT_PROGBITS), sh_flags = 6 (SHF_ALLOC|SHF_EXECINSTR)
    sh1 = struct.pack(
        "<IIIIIIIIII",
        1, 1, 6, code_va, code_off, code_size, 0, 0, 16, 0
    )
    # Section Header 2: .shstrtab
    # sh_name = 7 (".shstrtab"), sh_type = 3 (SHT_STRTAB), sh_flags = 0
    sh2 = struct.pack(
        "<IIIIIIIIII",
        7, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0
    )
    file_bytes += sh0 + sh1 + sh2
    
    with open(filename, "wb") as f:
        f.write(file_bytes)

def create_elf64(filename, machine, code_bytes, base_va=0x400000, has_gnu_stack=True, nx=True):
    # ELF Header: 64 bytes
    e_ident = b"\x7fELF\x02\x01\x01\x00\x00" + b"\x00" * 7
    e_type = 2 # ET_EXEC
    e_machine = machine
    e_version = 1
    
    ehdr_size = 64
    phdr_size = 56
    shdr_size = 64
    
    num_phdrs = 2 if has_gnu_stack else 1
    phoff = ehdr_size
    
    code_off = phoff + (num_phdrs * phdr_size)
    if code_off % 16 != 0:
        code_off += (16 - (code_off % 16))
    
    code_va = base_va + (code_off % 0x1000)
    e_entry = code_va
    code_size = len(code_bytes)
    
    shstrtab_off = code_off + code_size
    if shstrtab_off % 8 != 0:
        shstrtab_off += (8 - (shstrtab_off % 8))
    
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab)
    
    shoff = shstrtab_off + shstrtab_size
    if shoff % 8 != 0:
        shoff += (8 - (shoff % 8))
    num_shdrs = 3
    shstrndx = 2
    
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry,
        phoff, shoff, 0, ehdr_size, phdr_size, num_phdrs,
        shdr_size, num_shdrs, shstrndx
    )
    
    # PT_LOAD = 1
    pt_load_filesz = (code_off + code_size)
    pt_load_memsz = pt_load_filesz
    # Elf64_Phdr: p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
    phdr_load = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, base_va, base_va, pt_load_filesz, pt_load_memsz, 0x1000
    )
    
    phdrs = phdr_load
    if has_gnu_stack:
        flags = 6 if nx else 7
        phdr_stack = struct.pack(
            "<IIQQQQQQ",
            0x6474e551, flags, 0, 0, 0, 0, 0, 0x10
        )
        phdrs += phdr_stack
        
    file_bytes = bytearray(ehdr)
    file_bytes += phdrs
    if len(file_bytes) < code_off:
        file_bytes += b"\x00" * (code_off - len(file_bytes))
    file_bytes += code_bytes
    
    if len(file_bytes) < shstrtab_off:
        file_bytes += b"\x00" * (shstrtab_off - len(file_bytes))
    file_bytes += shstrtab
    
    if len(file_bytes) < shoff:
        file_bytes += b"\x00" * (shoff - len(file_bytes))
        
    sh0 = b"\x00" * shdr_size
    # Elf64_Shdr: sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8), sh_size(8), sh_link(4), sh_info(4), sh_addralign(8), sh_entsize(8)
    sh1 = struct.pack(
        "<IIQQQQIIQQ",
        1, 1, 6, code_va, code_off, code_size, 0, 0, 16, 0
    )
    sh2 = struct.pack(
        "<IIQQQQIIQQ",
        7, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0
    )
    file_bytes += sh0 + sh1 + sh2
    
    with open(filename, "wb") as f:
        f.write(file_bytes)

def main():
    target_dir = os.path.join(os.path.dirname(__file__), "..", "test_binaries")
    os.makedirs(target_dir, exist_ok=True)
    
    # 1. x86 32-bit (EM_386 = 3): pop eax ; ret (0x58 0xc3)
    create_elf32(os.path.join(target_dir, "elf32_x86"), 3, b"\x90\x58\xc3\x90", base_va=0x08048000)
    print("[+] Generated elf32_x86")
    
    # 2. ARMv7 32-bit (EM_ARM = 40): bx lr (0x1e 0xff 0x2f 0xe1)
    create_elf32(os.path.join(target_dir, "elf32_arm"), 40, b"\x00\x00\xa0\xe1\x1e\xff\x2f\xe1", base_va=0x00010000)
    print("[+] Generated elf32_arm")
    
    # 3. AArch64 64-bit (EM_AARCH64 = 183): ret (0xc0 0x03 0x5f 0xd6)
    create_elf64(os.path.join(target_dir, "elf64_aarch64"), 183, b"\x1f\x20\x03\xd5\xc0\x03\x5f\xd6", base_va=0x400000)
    print("[+] Generated elf64_aarch64")
    
    # 4. RISC-V 32-bit (EM_RISCV = 243): ret / jalr x0, x1, 0 (0x67 0x80 0x00 0x00)
    create_elf32(os.path.join(target_dir, "elf32_riscv"), 243, b"\x13\x00\x00\x00\x67\x80\x00\x00", base_va=0x00010000)
    print("[+] Generated elf32_riscv")
    
    # 5. RISC-V 64-bit (EM_RISCV = 243): ret / jalr x0, x1, 0 (0x67 0x80 0x00 0x00)
    create_elf64(os.path.join(target_dir, "elf64_riscv"), 243, b"\x13\x00\x00\x00\x67\x80\x00\x00", base_va=0x400000)
    print("[+] Generated elf64_riscv")

    # 6. x86_64 Multi-section ELF: .init (0x401000) and .text (0x402000)
    create_elf64_multisection(os.path.join(target_dir, "elf64_multisection"))
    print("[+] Generated elf64_multisection")

def create_elf64_multisection(filename):
    # Two executable sections separated by a 4096-byte gap:
    # .init: VA 0x401000, file offset 0x1000, size 16 bytes: nop; nop; ret
    # .text: VA 0x402000, file offset 0x2000, size 16 bytes: pop rax; ret
    e_ident = b"\x7fELF\x02\x01\x01\x00\x00" + b"\x00" * 7
    e_type = 2
    e_machine = 62 # EM_X86_64
    e_version = 1
    
    ehdr_size = 64
    phdr_size = 56
    shdr_size = 64
    
    num_phdrs = 1
    phoff = ehdr_size
    
    sec1_off = 0x1000
    sec1_va  = 0x401000
    sec1_data = b"\x90\x90\xc3\x90" + b"\x90" * 12
    
    sec2_off = 0x2000
    sec2_va  = 0x402000
    sec2_data = b"\x58\xc3\x90\x90" + b"\x90" * 12
    
    shstrtab_off = 0x2100
    shstrtab = b"\x00.init\x00.text\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab)
    
    shoff = 0x2200
    num_shdrs = 4
    shstrndx = 3
    
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, e_type, e_machine, e_version, sec1_va,
        phoff, shoff, 0, ehdr_size, phdr_size, num_phdrs,
        shdr_size, num_shdrs, shstrndx
    )
    
    # PT_LOAD spanning from 0 to 0x3000
    phdr_load = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, 0x400000, 0x400000, 0x3000, 0x3000, 0x1000
    )
    
    file_bytes = bytearray(ehdr)
    file_bytes += phdr_load
    
    # Pad to sec1_off
    file_bytes += b"\x00" * (sec1_off - len(file_bytes))
    file_bytes += sec1_data
    
    # Pad to sec2_off
    file_bytes += b"\x00" * (sec2_off - len(file_bytes))
    file_bytes += sec2_data
    
    # Pad to shstrtab_off
    file_bytes += b"\x00" * (shstrtab_off - len(file_bytes))
    file_bytes += shstrtab
    
    # Pad to shoff
    file_bytes += b"\x00" * (shoff - len(file_bytes))
    
    sh0 = b"\x00" * shdr_size
    # sh1: .init (sh_name=1)
    sh1 = struct.pack(
        "<IIQQQQIIQQ",
        1, 1, 6, sec1_va, sec1_off, len(sec1_data), 0, 0, 16, 0
    )
    # sh2: .text (sh_name=7)
    sh2 = struct.pack(
        "<IIQQQQIIQQ",
        7, 1, 6, sec2_va, sec2_off, len(sec2_data), 0, 0, 16, 0
    )
    # sh3: .shstrtab (sh_name=13)
    sh3 = struct.pack(
        "<IIQQQQIIQQ",
        13, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0
    )
    
    file_bytes += sh0 + sh1 + sh2 + sh3
    with open(filename, "wb") as f:
        f.write(file_bytes)

if __name__ == "__main__":
    main()
