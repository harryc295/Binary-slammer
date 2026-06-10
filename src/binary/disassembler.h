#ifndef DISASSEMBLER_H_
#define DISASSEMBLER_H_

#include <cstdint>
#include <string>
#include <vector>

struct disasm_t {
  uint64_t address{};
  std::vector<uint8_t> bytes;
  std::string mnemonic;
  std::string operands;
  std::string tooltip;
  bool is_call{};
  bool is_jump{};
  bool is_ret{};
  uint64_t branch_target{};
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
