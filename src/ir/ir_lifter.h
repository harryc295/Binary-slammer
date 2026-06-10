#ifndef IR_LIFTER_H_
#define IR_LIFTER_H_

#include <string>
#include <unordered_map>

#include "../analysis/cfg.h"
#include "../binary/disassembler.h"

struct IRResult {
    std::string raw_ir;   // lifted IR before any passes
    std::string opt_ir;   // IR after optimization passes
    std::string error;    // non-empty on failure
    bool        valid{false};
};

class IRLifter {
public:
    static IRResult lift(const CFG &cfg,
                         bool is_64bit,
                         const std::string &func_name,
                         const std::unordered_map<uint64_t, std::string> &call_map);
};

#endif // IR_LIFTER_H_
