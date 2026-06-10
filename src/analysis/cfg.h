#ifndef CFG_H_
#define CFG_H_

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../binary/disassembler.h"

struct BasicBlock {
    uint64_t              start_rva{0};
    std::vector<disasm_t> insns;
    std::vector<uint64_t> succs;   // successor block start RVAs
    bool                  is_exit{false};
};

struct CFG {
    uint64_t                                    entry_rva{0};
    std::unordered_map<uint64_t, BasicBlock>    blocks;

    static CFG build(const std::vector<disasm_t> &insns);

    // Topological order (entry first) for IR emission
    std::vector<uint64_t> topo_order() const;
};

#endif // CFG_H_
