#include "cfg.h"

#include <algorithm>
#include <queue>

CFG CFG::build(const std::vector<disasm_t> &insns) {
    CFG cfg;
    if (insns.empty()) return cfg;

    cfg.entry_rva = insns.front().address;

    // Pass 1: find all leaders
    std::unordered_set<uint64_t> leaders;
    leaders.insert(insns.front().address);

    for (size_t i = 0; i < insns.size(); ++i) {
        const auto &d = insns[i];
        if (d.is_jump || d.is_call || d.is_ret) {
            // Instruction after a terminator is a leader
            if (i + 1 < insns.size())
                leaders.insert(insns[i + 1].address);
            // Jump target is a leader
            if (d.branch_target && (d.is_jump || d.is_call))
                leaders.insert(d.branch_target);
        }
    }

    // Pass 2: partition instructions into blocks
    uint64_t cur_leader = 0;
    for (const auto &d : insns) {
        if (leaders.count(d.address)) {
            cur_leader = d.address;
            cfg.blocks[cur_leader].start_rva = cur_leader;
        }
        if (cur_leader)
            cfg.blocks[cur_leader].insns.push_back(d);
    }

    // Pass 3: build successor edges
    for (auto &[start, bb] : cfg.blocks) {
        if (bb.insns.empty()) continue;
        const auto &last = bb.insns.back();

        if (last.is_ret) {
            bb.is_exit = true;
            continue;
        }
        if (last.is_jump) {
            // Direct target
            if (last.branch_target && cfg.blocks.count(last.branch_target))
                bb.succs.push_back(last.branch_target);

            if (last.is_cond_jump) {
                // Fall-through for conditional jumps
                // Find the next block start after the jump instruction
                for (size_t i = 0; i + 1 < last.address; /* unused */) {
                    // Walk instruction list to find the instruction after 'last'
                    break;
                }
                // Simpler: find the leader that immediately follows
                uint64_t ft = last.address + last.bytes.size();
                if (cfg.blocks.count(ft))
                    bb.succs.push_back(ft);
            } else {
                // Unconditional JMP — if no known target, mark as exit
                if (bb.succs.empty()) bb.is_exit = true;
            }
        } else {
            // Fall-through (CALL or normal instruction ending a block)
            uint64_t ft = last.address + last.bytes.size();
            if (cfg.blocks.count(ft))
                bb.succs.push_back(ft);
        }
    }

    return cfg;
}

std::vector<uint64_t> CFG::topo_order() const {
    // BFS from entry
    std::vector<uint64_t> order;
    std::unordered_set<uint64_t> visited;
    std::queue<uint64_t> q;

    if (!blocks.count(entry_rva)) return order;
    q.push(entry_rva);
    visited.insert(entry_rva);

    while (!q.empty()) {
        uint64_t cur = q.front(); q.pop();
        order.push_back(cur);
        auto it = blocks.find(cur);
        if (it == blocks.end()) continue;
        for (uint64_t s : it->second.succs) {
            if (!visited.count(s) && blocks.count(s)) {
                visited.insert(s);
                q.push(s);
            }
        }
    }
    return order;
}
