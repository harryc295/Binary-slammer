#pragma once
#include <string>
#include <cstdio>
#include "../binary/disassembler.h"

inline std::string annotate_insn(const disasm_t &d) {
    const std::string &mn = d.mnemonic;
    const std::string &op = d.operands;

    // MOV family
    if (mn=="MOV"||mn=="MOVZX"||mn=="MOVSX"||mn=="MOVSXD")
        return "Copy → " + op;
    // Stack
    if (mn=="PUSH")  return "Push " + op + " onto the stack";
    if (mn=="POP")   return "Pop top of stack → " + op;
    // Control flow
    if (mn=="CALL") {
        if (d.branch_target) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Call function at 0x%llX",
                     (unsigned long long)d.branch_target);
            return buf;
        }
        return "Call function (indirect / computed address)";
    }
    if (mn=="RET"||mn=="RETN") return "Return to caller";
    if (mn=="JMP")  return "Unconditional jump to " + op;
    // Conditional jumps
    if (mn=="JZ" ||mn=="JE")   return "Jump if equal / zero";
    if (mn=="JNZ"||mn=="JNE")  return "Jump if not equal / not zero";
    if (mn=="JG" ||mn=="JNLE") return "Jump if greater (signed)";
    if (mn=="JL" ||mn=="JNGE") return "Jump if less (signed)";
    if (mn=="JGE"||mn=="JNL")  return "Jump if greater or equal (signed)";
    if (mn=="JLE"||mn=="JNG")  return "Jump if less or equal (signed)";
    if (mn=="JA" ||mn=="JNBE") return "Jump if above (unsigned)";
    if (mn=="JB" ||mn=="JNAE"||mn=="JC") return "Jump if below (unsigned)";
    if (mn=="JAE"||mn=="JNB"||mn=="JNC") return "Jump if above or equal (unsigned)";
    if (mn=="JBE"||mn=="JNA")  return "Jump if below or equal (unsigned)";
    if (mn=="JS")              return "Jump if negative (sign flag set)";
    if (mn=="JNS")             return "Jump if positive (sign flag clear)";
    if (mn=="JO")              return "Jump if overflow";
    if (mn=="JNO")             return "Jump if no overflow";
    if (mn=="JP" ||mn=="JPE")  return "Jump if parity even";
    if (mn=="JNP"||mn=="JPO")  return "Jump if parity odd";
    // Arithmetic
    if (mn=="ADD")  return "Add: " + op;
    if (mn=="SUB")  return "Subtract: " + op;
    if (mn=="MUL"||mn=="IMUL") return "Multiply: " + op;
    if (mn=="DIV"||mn=="IDIV") return "Divide: " + op;
    if (mn=="INC")  return "Increment " + op + " by 1";
    if (mn=="DEC")  return "Decrement " + op + " by 1";
    if (mn=="NEG")  return "Negate (two’s complement): " + op;
    if (mn=="ADC")  return "Add with carry: " + op;
    if (mn=="SBB")  return "Subtract with borrow: " + op;
    // Bitwise
    if (mn=="AND")  return "Bitwise AND: " + op;
    if (mn=="OR")   return "Bitwise OR: " + op;
    if (mn=="NOT")  return "Bitwise NOT (invert all bits): " + op;
    if (mn=="XOR") {
        // XOR reg, reg → zero idiom
        auto c = op.find(',');
        if (c != std::string::npos) {
            std::string lhs = op.substr(0, c);
            std::string rhs = op.substr(c + 1);
            while (!rhs.empty() && rhs[0] == ' ') rhs.erase(rhs.begin());
            if (lhs == rhs) return "Zero out " + lhs + " (XOR with itself)";
        }
        return "Bitwise XOR: " + op;
    }
    // Shifts
    if (mn=="SHL"||mn=="SAL") return "Shift left (x2 per bit): " + op;
    if (mn=="SHR")            return "Shift right unsigned (\xF7""2 per bit): " + op;
    if (mn=="SAR")            return "Arithmetic shift right (preserves sign): " + op;
    if (mn=="ROL")            return "Rotate left: " + op;
    if (mn=="ROR")            return "Rotate right: " + op;
    // Compare / test
    if (mn=="CMP")  return "Compare " + op + " — sets CPU flags, discards result";
    if (mn=="TEST") return "Bitwise test " + op + " — sets CPU flags, discards result";
    // Address / memory
    if (mn=="LEA")  return "Compute address (no memory read): " + op;
    if (mn=="XCHG") return "Swap values: " + op;
    // Stack frame
    if (mn=="LEAVE") return "Tear down stack frame (MOV rsp,rbp then POP rbp)";
    if (mn=="ENTER") return "Set up new stack frame";
    // Flags
    if (mn=="PUSHF"||mn=="PUSHFD"||mn=="PUSHFQ") return "Save all CPU flags onto stack";
    if (mn=="POPF" ||mn=="POPFD" ||mn=="POPFQ")  return "Restore CPU flags from stack";
    if (mn=="STD")  return "Set direction flag — string ops will go backward";
    if (mn=="CLD")  return "Clear direction flag — string ops go forward";
    if (mn=="STI")  return "Enable hardware interrupts";
    if (mn=="CLI")  return "Disable hardware interrupts";
    // System
    if (mn=="NOP")  return "No operation (padding / alignment)";
    if (mn=="INT3") return "Debugger breakpoint";
    if (mn=="INT")  return "Software interrupt: " + op;
    if (mn=="HLT")  return "Halt CPU (privileged — triggers fault in user mode)";
    if (mn=="SYSCALL"||mn=="SYSENTER") return "System call — transfers control to the OS kernel";
    if (mn=="RDTSC") return "Read CPU timestamp counter (used for timing-based anti-debug)";
    if (mn=="CPUID") return "Query CPU capabilities and manufacturer string";
    // String ops
    if (mn.rfind("MOVS",0)==0||mn.rfind("REP MOVS",0)==0) return "Copy memory block: " + op;
    if (mn.rfind("STOS",0)==0||mn.rfind("REP STOS",0)==0) return "Fill memory with value: " + op;
    if (mn.rfind("CMPS",0)==0) return "Compare memory regions: " + op;
    if (mn.rfind("SCAS",0)==0) return "Scan memory for value: " + op;
    if (mn.rfind("REP",0)==0)  return "Repeat string operation: " + op;
    // Set-on-condition
    if (mn.rfind("SET",0)==0)  return "Set byte to 0 or 1 based on flags: " + op;
    // cmov
    if (mn.rfind("CMOV",0)==0) return "Conditional move (if condition): " + op;

    return "";
}
