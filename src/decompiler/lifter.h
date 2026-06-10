#ifndef LIFTER_H_
#define LIFTER_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include "../binary/disassembler.h"

struct pseudo_line_t {
    std::string text;
    int         indent{};
    uint64_t    rva{};
    bool        is_comment{};
};

class Lifter {
public:
    // Lift a decoded function into pseudo-code lines.
    // imports_map: RVA → function name for resolved call targets (optional).
    static std::vector<pseudo_line_t> lift(
        const std::vector<disasm_t> &insns,
        bool is_64bit,
        const std::unordered_map<uint64_t, std::string> &call_map = {});
};

#endif // LIFTER_H_
