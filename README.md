# Minimal ELF64 wrapper for raw x86-64 syscall code

## Description
Wraps a **raw x86-64 machine-code blob** into a valid **ELF64 ET_EXEC** with a **single PT_LOAD** (no sections). Entry jumps straight to your code placed after `EHDR|PHDR`. Handy for CTF “golfer” binaries and shellcode experiments.

- Target: Linux x86-64, little-endian
- Base VA: `0x40000`
- Entry: `0x40000 + sizeof(EHDR)+sizeof(PHDR)`
- PT_LOAD flags: **RWX (7)** by default (you can change to **RX (5)**)

---

## Build
```bash
g++ -O2 -o main main.cpp
```

## Usage
```bash
./main <input_raw_code.bin> <output_elf>
./<output_elf>
```

## Validate (optional)
```bash
readelf -hW <output_elf>
readelf -lW <output_elf>
objdump -D -M intel <output_elf> | head -n 80
```

---

## Examples

### Example 1 — write "Hello\n" and exit
Create the input blob and wrap it:
```bash
echo -en "\x48\xB8\x48\x65\x6C\x6C\x6F\x0A\x00\x00\x50\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\x89\xE6\x48\xC7\xC2\x06\x00\x00\x00\x0F\x05\x48\x83\xC4\x08\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05" > hello.bin
./main hello.bin hello.elf
./hello.elf
```

### Example 2 — absolute VA trick + manual tail data
Bytes (two ways to embed):
```text
String literal:
"\x48\xC7\xC0\xAD\x00\x04\x00\x50\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\x8B\x34\x24\x48\xC7\xC2\x06\x00\x00\x00\x0F\x05\x48\x83\xC4\x08\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05"

Array literal:
{ 0x48,0xC7,0xC0,0xAD,0x00,0x04,0x00,0x50,0x48,0xC7,0xC0,0x01,0x00,0x00,0x00,0x48,0xC7,0xC7,0x01,0x00,0x00,0x00,0x48,0x8B,0x34,0x24,0x48,0xC7,0xC2,0x06,0x00,0x00,0x00,0x0F,0x05,0x48,0x83,0xC4,0x08,0x48,0xC7,0xC0,0x3C,0x00,0x00,0x00,0x48,0x31,0xFF,0x0F,0x05 }
```
Key idea in the disasm:
```
0: 48 c7 c0 ad 00 04 00   mov rax,0x400ad   ; VA near code end
7: 50                     push rax
...
```
Append text bytes to the end of your blob so the code can reference them without extra program headers.
