#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

struct rich_entry_t {
    uint16_t product_id;
    uint16_t build_id;
    uint32_t count;
};

inline const char *rich_product_name(uint16_t pid) {
    if (pid == 0x0001) return "Linker (import/export)";
    if (pid == 0x0002) return "Resource Compiler";
    if (pid == 0x0004) return "Linker 2.x";
    if (pid == 0x000A) return "MASM / Assembler";
    if (pid >= 0x0060 && pid <= 0x0065) return "VS 97 (5.0)";
    if (pid >= 0x006D && pid <= 0x0072) return "VS 98 (6.0)";
    if (pid >= 0x007A && pid <= 0x0082) return "VS 2002 (7.0)";
    if (pid >= 0x0083 && pid <= 0x008D) return "VS 2003 (7.1)";
    if (pid >= 0x0093 && pid <= 0x00A4) return "VS 2005 (8.0)";
    if (pid >= 0x00A7 && pid <= 0x00B0) return "VS 2008 (9.0)";
    if (pid >= 0x00B4 && pid <= 0x00C1) return "VS 2010 (10.0)";
    if (pid >= 0x00C5 && pid <= 0x00CB) return "VS 2012 (11.0)";
    if (pid >= 0x00CE && pid <= 0x00D8) return "VS 2013 (12.0)";
    if (pid >= 0x00EB && pid <= 0x00F5) return "VS 2015 (14.0)";
    if (pid >= 0x00FD && pid <= 0x010A) return "VS 2017 (14.x)";
    if (pid >= 0x010B && pid <= 0x0115) return "VS 2019 (14.2)";
    if (pid >= 0x0116) return "VS 2022 (14.3+)";
    return "Unknown";
}

// Parse the Rich header from the DOS stub bytes (first dos_e_lfanew bytes of the file).
inline std::vector<rich_entry_t> parse_rich_header(const uint8_t *stub, size_t stub_size) {
    if (!stub || stub_size < 0x40) return {};

    const uint32_t RICH_MAGIC = 0x68636952u; // "Rich" LE
    const uint32_t DANS_MAGIC = 0x536E6144u; // "DanS" LE

    // Search for "Rich" from offset 0x40 onward (4-byte aligned)
    size_t rich_off = 0;
    bool   found    = false;
    for (size_t i = 0x40; i + 8 <= stub_size; i += 4) {
        uint32_t val;
        memcpy(&val, stub + i, 4);
        if (val == RICH_MAGIC) { rich_off = i; found = true; break; }
    }
    if (!found) return {};

    uint32_t key;
    memcpy(&key, stub + rich_off + 4, 4);

    // Locate "DanS" XOR key searching forward from 0x40
    size_t dans_off = 0;
    bool   dans_ok  = false;
    for (size_t i = 0x40; i + 4 <= rich_off; i += 4) {
        uint32_t val;
        memcpy(&val, stub + i, 4);
        if ((val ^ key) == DANS_MAGIC) { dans_off = i; dans_ok = true; break; }
    }
    if (!dans_ok) return {};

    // DanS (4B) + 3 padding DWORDs (12B) = 16 bytes, then 8-byte entries follow
    size_t entry_start = dans_off + 16;
    std::vector<rich_entry_t> entries;
    for (size_t i = entry_start; i + 8 <= rich_off; i += 8) {
        uint32_t a, b;
        memcpy(&a, stub + i,     4);
        memcpy(&b, stub + i + 4, 4);
        a ^= key; b ^= key;
        rich_entry_t e;
        e.product_id = (uint16_t)(a >> 16);
        e.build_id   = (uint16_t)(a & 0xFFFF);
        e.count      = b;
        entries.push_back(e);
    }
    return entries;
}
