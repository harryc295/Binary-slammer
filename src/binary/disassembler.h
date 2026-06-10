#ifndef DISASSEMBLER_H_
#define DISASSEMBLER_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ── Structured operand representation ────────────────────────────────────────

enum class OpKind : uint8_t { None, Reg, Imm, Mem };

struct MemAddr {
    std::string base;       // base register name, "" if none
    std::string index;      // index register name, "" if none
    uint8_t     scale{1};
    int64_t     disp{0};
    uint8_t     size_bytes{8};
};

struct RawOp {
    OpKind      kind{OpKind::None};
    uint8_t     size_bytes{8};
    std::string reg;            // OpKind::Reg
    int64_t     imm{0};        // OpKind::Imm
    bool        imm_unsigned{false};
    MemAddr     mem;            // OpKind::Mem
};

// ── Decoded instruction ───────────────────────────────────────────────────────

struct disasm_t {
  uint64_t address{};
  std::vector<uint8_t> bytes;
  std::string mnemonic;         // uppercase e.g. "MOV"
  std::string operands;         // formatted string for display
  std::string tooltip;
  bool is_call{};
  bool is_jump{};
  bool is_ret{};
  bool is_cond_jump{};
  uint64_t branch_target{};

  // Structured operands for IR lifting
  std::array<RawOp, 4> raw_ops{};
  uint8_t raw_op_count{0};
  uint32_t zydis_mnemonic{0};   // ZydisMnemonic cast to uint32_t
};

class Disassembler {
public:
  // Decode up to max_insns instructions from raw bytes starting at base_rva.
  static std::vector<disasm_t> disassemble(const uint8_t *data, size_t size,
                                           uint64_t base_rva,
                                           size_t max_insns = 512,
                                           bool is_64bit = true);
};

#endif // DISASSEMBLER_H_
