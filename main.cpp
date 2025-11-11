#include <array>
#include <vector>
#include <fstream>
#include <cstdint>
#include <type_traits>
#include <iostream>

struct Elf64_Ehdr {
    unsigned char e_ident[16]; // ELF identification bytes:
                               // [0..3] 0x7F,'E','L','F'
                               // [4]    EI_CLASS  = 2 (ELF64)
                               // [5]    EI_DATA   = 1 (little-endian)
                               // [6]    EI_VERSION= 1 (EV_CURRENT)
                               // [7]    EI_OSABI  = 0 (System V)
                               // [8]    ABI ver   = 0
                               // [9..15] padding  = 0
    uint16_t e_type;           // ET_EXEC (2)
    uint16_t e_machine;        // EM_X86_64 (62)
    uint32_t e_version;        // EV_CURRENT (1)
    uint64_t e_entry;          // Entry point virtual address
    uint64_t e_phoff;          // Program header table file offset
    uint64_t e_shoff;          // Section header table file offset (0 = none)
    uint32_t e_flags;          // Processor-specific flags (unused on x86-64)
    uint16_t e_ehsize;         // ELF header size in bytes (64)
    uint16_t e_phentsize;      // Program header entry size
    uint16_t e_phnum;          // Program header entry count
    uint16_t e_shentsize;      // Section header entry size (0 = none)
    uint16_t e_shnum;          // Section header entry count (0 = none)
    uint16_t e_shstrndx;       // Section header string table index (0 = none)
};

struct Elf64_Phdr{
    uint32_t p_type;   // PT_LOAD (1)
    uint32_t p_flags;  // PF_R(4) | PF_W(2) | PF_X(1) => 7 (RWX)
    uint64_t p_offset; // Segment file offset
    uint64_t p_vaddr;  // Segment virtual address
    uint64_t p_paddr;  // Segment physical address (ignored on x86-64)
    uint64_t p_filesz; // Segment size in file
    uint64_t p_memsz;  // Segment size in memory
    uint64_t p_align;  // Segment alignment (page, e.g. 0x1000)
};

int main(int argc, char** argv) {
    // Example: To write "Hello\n" to stdout and exit
    // 0:  48 b8 48 65 6c 6c 6f    movabs rax,0xa6f6c6c6548
    // 7:  0a 00 00
    // a:  50                      push   rax
    // b:  48 c7 c0 01 00 00 00    mov    rax,0x1
    // 12: 48 c7 c7 01 00 00 00    mov    rdi,0x1
    // 19: 48 89 e6                mov    rsi,rsp
    // 1c: 48 c7 c2 06 00 00 00    mov    rdx,0x6
    // 23: 0f 05                   syscall
    // 25: 48 83 c4 08             add    rsp,0x8
    // 29: 48 c7 c0 3c 00 00 00    mov    rax,0x3c
    // 30: 48 31 ff                xor    rdi,rdi
    // 33: 0f 05                   syscall
    // echo -en "\x48\xB8\x48\x65\x6C\x6C\x6F\x0A\x00\x00\x50\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\x89\xE6\x48\xC7\xC2\x06\x00\x00\x00\x0F\x05\x48\x83\xC4\x08\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05"  > file.bin

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        std::cerr << "Input file content should be binary.\n";
        std::cerr << "Example: echo -en '\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90' > file.bin\n";
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    // Read input binary file
    std::ifstream input(input_file, std::ios::binary);
    std::cout << "[+] Opening input: " << input_file << " (is_open=" << std::boolalpha << input.is_open() << ")\n";

    std::vector<uint8_t> code(std::istreambuf_iterator<char>(input), {});
    std::cout << "[+] Read code bytes: " << std::dec << code.size() << "\n";

    // --- ELF header ---
    Elf64_Ehdr elf_header{};
    elf_header.e_ident[0] = 0x7f; // 0x7F,'E','L','F' magic
    elf_header.e_ident[1] = 'E';
    elf_header.e_ident[2] = 'L';
    elf_header.e_ident[3] = 'F';
    elf_header.e_ident[4] = 2; // EI_CLASS = 2 (ELF64)
    elf_header.e_ident[5] = 1; // EI_DATA  = 1 (little-endian)
    elf_header.e_ident[6] = 1; // EI_VERSION = EV_CURRENT
    elf_header.e_ident[7] = 0; // EI_OSABI = System V
    elf_header.e_ident[8] = 0; // ABI version
    elf_header.e_ident[9] = 0;  // padding
    elf_header.e_ident[10] = 0; // padding
    elf_header.e_ident[11] = 0; // padding
    elf_header.e_ident[12] = 0; // padding
    elf_header.e_ident[13] = 0; // padding
    elf_header.e_ident[14] = 0; // padding
    elf_header.e_ident[15] = 0; // padding
    elf_header.e_ident[16] = 0; // NOTE: e_ident is 16 bytes (0..15). This index is out-of-bounds.
    elf_header.e_type      = 2;   // ET_EXEC
    elf_header.e_machine   = 62;  // EM_X86_64
    elf_header.e_version   = 1;   // EV_CURRENT
    // Virtual address when loaded; entry points right after EHDR+PHDR (code start)
    elf_header.e_entry     = 0x40000 + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    elf_header.e_phoff     = sizeof(Elf64_Ehdr); // PHDR immediately after EHDR
    elf_header.e_shoff     = 0;                  // no sections
    elf_header.e_flags     = 0;
    elf_header.e_ehsize    = sizeof(Elf64_Ehdr);
    elf_header.e_phentsize = sizeof(Elf64_Phdr);
    elf_header.e_phnum     = 1;  // single PT_LOAD
    elf_header.e_shentsize = 0;
    elf_header.e_shnum     = 0;
    elf_header.e_shstrndx  = 0;

    // --- Program header (single PT_LOAD covering the whole file) ---
    Elf64_Phdr program_header{};
    program_header.p_type   = 1; // PT_LOAD
    program_header.p_flags  = (1 << 1) | (1 << 2) | (1 << 0); // PF_W|PF_R|PF_X = 7 (RWX)
    program_header.p_offset = 0;        // segment starts at file offset 0
    program_header.p_vaddr  = 0x40000;  // mapped base
    program_header.p_paddr  = 0x40000;
    program_header.p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + code.size(); // total file size
    program_header.p_memsz  = program_header.p_filesz; // no .bss
    program_header.p_align  = 0x1000;  // page align
    // Constraint: (p_vaddr % p_align) == (p_offset % p_align) -> 0 == 0 OK

    std::cout << "[+] ELF header size: " << sizeof(Elf64_Ehdr) << "\n";
    std::cout << "[+] Program header size: " << sizeof(Elf64_Phdr) << "\n";
    std::cout << "[+] Code size: " << code.size() << "\n";
    std::cout << std::hex;
    std::cout << "[+] e_entry=0x" << elf_header.e_entry
              << " e_phoff=0x" << elf_header.e_phoff
              << " e_shoff=0x" << elf_header.e_shoff << "\n";
    std::cout << "[+] PHDR: type=" << std::dec << program_header.p_type
              << " flags=" << program_header.p_flags << std::hex
              << " offset=0x" << program_header.p_offset
              << " vaddr=0x"  << program_header.p_vaddr
              << " paddr=0x"  << program_header.p_paddr
              << " filesz=0x" << program_header.p_filesz
              << " memsz=0x"  << program_header.p_memsz
              << " align=0x"  << program_header.p_align << "\n";
    std::cout << std::dec;

    // --- Stitch together: EHDR | PHDR | CODE ---
    std::vector<uint8_t> final_file;
    final_file.reserve(program_header.p_filesz);
    std::cout << "[+] Reserved capacity: " << final_file.capacity() << " bytes\n";

    //TODO: add templates for these
    final_file.insert(final_file.end(),
                      reinterpret_cast<const uint8_t*>(&elf_header),
                      reinterpret_cast<const uint8_t*>(&elf_header) + sizeof(elf_header));
    std::cout << "[+] After EHDR insert, size=" << final_file.size() << "\n";

    final_file.insert(final_file.end(),
                      reinterpret_cast<const uint8_t*>(&program_header),
                      reinterpret_cast<const uint8_t*>(&program_header) + sizeof(program_header));
    std::cout << "[+] After PHDR insert, size=" << final_file.size() << "\n";

    final_file.insert(final_file.end(), code.begin(), code.end());
    std::cout << "[+] After CODE insert, size=" << final_file.size()
              << " (expected " << program_header.p_filesz << ")\n";

    // Writing to a file
    std::ofstream out(output_file, std::ios::binary);
    std::cout << "[+] Opening output: " << output_file << " (is_open=" << std::boolalpha << out.is_open() << ")\n";
    out.write(reinterpret_cast<const char*>(final_file.data()), final_file.size());
    std::cout << "[+] Wrote bytes: " << final_file.size() << " (stream.good=" << std::boolalpha << out.good() << ")\n";
    return 0;
}
