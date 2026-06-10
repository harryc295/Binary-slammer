#include "disassembler.h"

#include <Zydis/Zydis.h>
#include <unordered_map>

// Short human-readable descriptions for common mnemonics shown as tooltips.
static const std::unordered_map<std::string, std::string> k_mnemonic_tips = {
    {"MOV",    "Copy a value from source to destination"},
    {"MOVSX",  "Copy with sign-extension (signed integer widening)"},
    {"MOVZX",  "Copy with zero-extension (unsigned integer widening)"},
    {"MOVSXD", "Move doubleword to quadword with sign-extension (x64)"},
    {"LEA",    "Load Effective Address — compute an address and store it (no memory read)"},
    {"PUSH",   "Push a value onto the stack (RSP/ESP decremented)"},
    {"POP",    "Pop a value off the stack (RSP/ESP incremented)"},
    {"CALL",   "Call a subroutine — pushes return address then jumps"},
    {"RET",    "Return from subroutine — pops return address and jumps to it"},
    {"JMP",    "Unconditional jump"},
    {"JE",     "Jump if Equal (ZF=1)"},
    {"JNE",    "Jump if Not Equal (ZF=0)"},
    {"JZ",     "Jump if Zero (ZF=1)"},
    {"JNZ",    "Jump if Not Zero (ZF=0)"},
    {"JL",     "Jump if Less (SF≠OF) — signed comparison"},
    {"JLE",    "Jump if Less or Equal (ZF=1 or SF≠OF) — signed comparison"},
    {"JG",     "Jump if Greater (ZF=0 and SF=OF) — signed comparison"},
    {"JGE",    "Jump if Greater or Equal (SF=OF) — signed comparison"},
    {"JB",     "Jump if Below (CF=1) — unsigned comparison"},
    {"JBE",    "Jump if Below or Equal (CF=1 or ZF=1) — unsigned comparison"},
    {"JA",     "Jump if Above (CF=0 and ZF=0) — unsigned comparison"},
    {"JAE",    "Jump if Above or Equal (CF=0) — unsigned comparison"},
    {"JS",     "Jump if Sign (SF=1) — result was negative"},
    {"JNS",    "Jump if Not Sign (SF=0)"},
    {"ADD",    "Integer addition — sets CF, OF, ZF, SF, PF"},
    {"SUB",    "Integer subtraction — sets CF, OF, ZF, SF, PF"},
    {"MUL",    "Unsigned multiply — result stored in RDX:RAX or EDX:EAX"},
    {"IMUL",   "Signed multiply"},
    {"DIV",    "Unsigned divide — quotient in RAX, remainder in RDX"},
    {"IDIV",   "Signed divide"},
    {"AND",    "Bitwise AND — clears CF and OF, sets ZF/SF based on result"},
    {"OR",     "Bitwise OR — clears CF and OF"},
    {"XOR",    "Bitwise XOR — XOR of a register with itself zeroes it (common idiom)"},
    {"NOT",    "Bitwise NOT — one's complement"},
    {"NEG",    "Negate (two's complement) — effectively 0 - operand"},
    {"SHL",    "Shift Left logical — equivalent to multiply by 2^n"},
    {"SHR",    "Shift Right logical — equivalent to unsigned divide by 2^n"},
    {"SAR",    "Shift Arithmetic Right — preserves sign bit"},
    {"ROL",    "Rotate Left — bits shifted out re-enter on the right"},
    {"ROR",    "Rotate Right — bits shifted out re-enter on the left"},
    {"CMP",    "Compare — performs subtraction, updates flags, discards result"},
    {"TEST",   "Test — performs AND, updates flags, discards result"},
    {"INC",    "Increment by 1 (does not affect CF)"},
    {"DEC",    "Decrement by 1 (does not affect CF)"},
    {"NOP",    "No Operation — padding or alignment byte (0x90)"},
    {"INT",    "Software interrupt — INT 3 is a debugger breakpoint"},
    {"INT3",   "Debugger breakpoint — triggers EXCEPTION_BREAKPOINT"},
    {"SYSCALL","Invoke kernel via fast system call (x64 Windows/Linux)"},
    {"SYSENTER","Invoke kernel via fast system call (x86)"},
    {"LEAVE",  "Restore stack frame — equivalent to MOV RSP,RBP + POP RBP"},
    {"ENTER",  "Create stack frame — sets up RBP/RSP (rarely emitted by modern compilers)"},
    {"XCHG",   "Atomically swap two operands"},
    {"XADD",   "Exchange and Add — atomic: dst += src, src = old dst"},
    {"CMPXCHG","Compare and Exchange — atomic compare-swap primitive"},
    {"MOVAPS", "Move Aligned Packed Single-precision floats (SSE)"},
    {"MOVDQU", "Move Unaligned Double Quadword (SSE2)"},
    {"PXOR",   "Packed XOR — often used to zero an XMM register"},
    {"CPUID",  "CPU Identification — returns CPU info in EAX/EBX/ECX/EDX (anti-VM probe)"},
    {"RDTSC",  "Read Time-Stamp Counter — high-res timer, used in timing attacks & anti-debug"},
};

static std::string build_tooltip(const std::string &mnemonic,
                                 const ZydisDecodedInstruction &insn,
                                 const ZydisDecodedOperand *ops) {
    std::string tip;

    auto it = k_mnemonic_tips.find(mnemonic);
    if (it != k_mnemonic_tips.end())
        tip = it->second;
    else
        tip = mnemonic + " instruction";

    // Instruction class hint
    if (insn.meta.category == ZYDIS_CATEGORY_COND_BR)
        tip += "\nConditional branch — tests CPU flags to decide whether to jump";
    else if (insn.meta.category == ZYDIS_CATEGORY_CALL)
        tip += "\nFunction call — pushes return address and transfers control";
    else if (insn.meta.category == ZYDIS_CATEGORY_RET)
        tip += "\nReturn — pops the saved return address and jumps to it";

    // Note memory operands
    for (ZyanU8 i = 0; i < insn.operand_count_visible; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            tip += "\nMemory operand: dereferences a computed address";
            break;
        }
    }

    // Note instruction length (useful for shellcode analysis)
    if (insn.length > 8)
        tip += "\nLong instruction (" + std::to_string(insn.length) + " bytes)";

    return tip;
}

std::vector<disasm_t> Disassembler::disassemble(const uint8_t *data,
                                                 size_t size,
                                                 uint64_t base_rva,
                                                 size_t max_insns,
                                                 bool is_64bit) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder,
                     is_64bit ? ZYDIS_MACHINE_MODE_LONG_64
                              : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
                     is_64bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter,
                              ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);

    std::vector<disasm_t> out;
    out.reserve(std::min(max_insns, size / 3 + 1));

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = 0;

    while (offset < size && out.size() < max_insns) {
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, data + offset, size - offset, &insn, ops);

        if (!ZYAN_SUCCESS(status)) {
            // Emit a DB byte and skip
            disasm_t bad;
            bad.address  = base_rva + offset;
            bad.bytes    = {data[offset]};
            bad.mnemonic = "db";
            char buf[8];
            snprintf(buf, sizeof(buf), "0x%02X", data[offset]);
            bad.operands = buf;
            bad.tooltip  = "Unknown / data byte";
            out.push_back(std::move(bad));
            ++offset;
            continue;
        }

        char fmt_buf[256];
        ZydisFormatterFormatInstruction(&formatter, &insn, ops,
                                        insn.operand_count_visible,
                                        fmt_buf, sizeof(fmt_buf),
                                        base_rva + offset, nullptr);

        // Split formatter output into mnemonic + operands
        std::string full(fmt_buf);
        std::string mnemonic, operands;
        auto sp = full.find(' ');
        if (sp != std::string::npos) {
            mnemonic = full.substr(0, sp);
            operands = full.substr(sp + 1);
        } else {
            mnemonic = full;
        }

        // Uppercase mnemonic for tooltip lookup
        std::string mnem_upper = mnemonic;
        for (auto &c : mnem_upper) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

        disasm_t d;
        d.address  = base_rva + offset;
        d.bytes    = std::vector<uint8_t>(data + offset, data + offset + insn.length);
        d.mnemonic = mnemonic;
        d.operands = operands;
        d.tooltip  = build_tooltip(mnem_upper, insn, ops);
        d.is_ret   = (insn.meta.category == ZYDIS_CATEGORY_RET);
        d.is_call  = (insn.meta.category == ZYDIS_CATEGORY_CALL);
        d.is_jump  = (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                      insn.meta.category == ZYDIS_CATEGORY_COND_BR);

        // Resolve direct branch/call target
        if ((d.is_call || d.is_jump) &&
            insn.operand_count_visible > 0 &&
            ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ops[0].imm.is_relative) {
            d.branch_target = base_rva + offset + insn.length +
                              static_cast<int64_t>(ops[0].imm.value.s);
        }

        out.push_back(std::move(d));
        offset += insn.length;

        if (d.is_ret) break; // stop at RET to keep function view clean
    }

    return out;
}
