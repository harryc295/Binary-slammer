#include "lifter.h"
#include "../data/api_descriptions.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

// ── Operand classification ────────────────────────────────────────────────

static bool is_reg(const std::string &s) {
    static const std::unordered_set<std::string> regs = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "ax","bx","cx","dx","si","di","bp","sp",
        "al","bl","cl","dl","sil","dil","bpl","spl",
        "ah","bh","ch","dh",
        "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    };
    std::string lower = s;
    for (auto &c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return regs.count(lower) > 0;
}

static bool is_imm(const std::string &s) {
    if (s.empty()) return false;
    size_t i = 0;
    if (s[i] == '-') ++i;
    if (i + 1 < s.size() && s[i] == '0' && (s[i+1]=='x'||s[i+1]=='X')) return true;
    while (i < s.size() && isdigit(static_cast<unsigned char>(s[i]))) ++i;
    return i == s.size() && i > 0;
}

// Rewrite size prefix "qword ptr [X]" → "*(X)"  "dword ptr [X]" → "*(X)"
static std::string strip_size(const std::string &op) {
    static const char *prefixes[] = {
        "qword ptr ","dword ptr ","word ptr ","byte ptr ",
        "xmmword ptr ","ymmword ptr ","zmmword ptr ", nullptr
    };
    for (int i = 0; prefixes[i]; ++i) {
        size_t n = strlen(prefixes[i]);
        if (op.size() > n && op.substr(0, n) == prefixes[i])
            return op.substr(n);
    }
    return op;
}

static bool is_mem(const std::string &op) {
    std::string s = strip_size(op);
    return !s.empty() && s.front() == '[';
}

// "[rbp - 0x8]" → "*(rbp - 0x8)"
static std::string mem_to_deref(const std::string &op) {
    std::string s = strip_size(op);
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']')
        return "*(" + s.substr(1, s.size()-2) + ")";
    return op;
}

// Split "A, B" into {A, B}  (respects brackets)
static std::vector<std::string> split_ops(const std::string &ops) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : ops) {
        if (c == '[') ++depth;
        else if (c == ']') --depth;
        if (c == ',' && depth == 0) {
            // trim
            while (!cur.empty() && cur.front() == ' ') cur.erase(cur.begin());
            while (!cur.empty() && cur.back()  == ' ') cur.pop_back();
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    while (!cur.empty() && cur.front() == ' ') cur.erase(cur.begin());
    while (!cur.empty() && cur.back()  == ' ') cur.pop_back();
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Normalise a single operand to pseudo-C representation
static std::string lift_op(const std::string &op) {
    if (is_mem(op))  return mem_to_deref(op);
    if (is_reg(op))  return op;
    if (is_imm(op))  return op;
    return op;
}

// ── x64 / x86 calling convention ─────────────────────────────────────────

static const char *k_x64_args[] = {"rcx","rdx","r8","r9"};
static const char *k_x86_args[] = {"ecx","edx"};  // fastcall; stdcall uses stack

// ── Mnemonic → uppercase ──────────────────────────────────────────────────

static std::string upper(const std::string &s) {
    std::string r = s;
    for (auto &c : r) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return r;
}

// ── Condition builder from CMP/TEST ──────────────────────────────────────

struct PendingCmp {
    std::string lhs, rhs;
    bool is_test{};    // TEST sets ZF = (lhs & rhs) == 0
    bool valid{};
};

// Given JCC mnemonic and a pending CMP/TEST, return the condition string.
// If invert=true, return the negated condition (for "else" paths).
static std::string make_cond(const std::string &jcc, const PendingCmp &cmp, bool invert) {
    std::string m = upper(jcc);
    if (!cmp.valid) return "cond";

    if (cmp.is_test) {
        // TEST reg, reg → ZF = (reg == 0)
        // JZ  → jump if zero   → condition: lhs == 0
        // JNZ → jump if not zero → condition: lhs != 0
        bool jump_if_zero = (m == "JZ" || m == "JE");
        bool want_zero = invert ? !jump_if_zero : jump_if_zero;
        return cmp.lhs + (want_zero ? " == 0" : " != 0");
    }

    // CMP a, b sets flags based on a - b
    struct { const char *j; const char *cond; const char *inv; } table[] = {
        {"JE",  "==", "!="}, {"JZ",  "==", "!="},
        {"JNE", "!=", "=="}, {"JNZ", "!=", "=="},
        {"JL",  "<",  ">="}, {"JNL", ">=", "<"},
        {"JLE", "<=", ">"},  {"JNLE",">",  "<="},
        {"JG",  ">",  "<="}, {"JNG", "<=", ">"},
        {"JGE", ">=", "<"},  {"JNGE","<",  ">="},
        {"JB",  "<",  ">="}, {"JNB", ">=", "<"},
        {"JBE", "<=", ">"},  {"JNBE",">",  "<="},
        {"JA",  ">",  "<="}, {"JNA", "<=", ">"},
        {"JAE", ">=", "<"},  {"JNAE","<",  ">="},
        {"JS",  "<0", ">=0"},{"JNS", ">=0","<0"},
        {nullptr, nullptr, nullptr}
    };
    for (int i = 0; table[i].j; ++i) {
        if (m == table[i].j) {
            const char *op = invert ? table[i].inv : table[i].cond;
            if (m == "JS"  && !invert) return cmp.lhs + " < 0";
            if (m == "JNS" && !invert) return cmp.lhs + " >= 0";
            if (m == "JS"  &&  invert) return cmp.lhs + " >= 0";
            if (m == "JNS" &&  invert) return cmp.lhs + " < 0";
            return cmp.lhs + " " + op + " " + cmp.rhs;
        }
    }
    return invert ? "!cond" : "cond";
}

// ── Main lifter ───────────────────────────────────────────────────────────

std::vector<pseudo_line_t> Lifter::lift(
    const std::vector<disasm_t> &insns,
    bool is_64bit,
    const std::unordered_map<uint64_t, std::string> &call_map)
{
    std::vector<pseudo_line_t> out;
    int indent = 1;
    PendingCmp pending{};

    // Track register assignments for arg inference (last N instructions)
    std::unordered_map<std::string, std::string> reg_val;

    // Addresses of all jump targets in this function (for labelling)
    std::unordered_set<uint64_t> jump_targets;
    for (const auto &d : insns)
        if ((d.is_jump || d.is_call) && d.branch_target)
            jump_targets.insert(d.branch_target);

    auto emit = [&](const std::string &text, bool comment = false, int extra_indent = 0) {
        pseudo_line_t pl;
        pl.text = text;
        pl.indent = indent + extra_indent;
        pl.is_comment = comment;
        out.push_back(pl);
    };

    auto emit_rva = [&](uint64_t rva, const std::string &text, bool comment = false) {
        pseudo_line_t pl;
        pl.text = text;
        pl.indent = indent;
        pl.rva = rva;
        pl.is_comment = comment;
        out.push_back(pl);
    };

    // Function signature line
    out.push_back({is_64bit ? "int64_t func(void)" : "int32_t func(void)", 0});
    out.push_back({"{", 0});

    for (size_t idx = 0; idx < insns.size(); ++idx) {
        const auto &d   = insns[idx];
        std::string m   = upper(d.mnemonic);
        auto ops        = split_ops(d.operands);
        std::string dst = ops.size() > 0 ? ops[0] : "";
        std::string src = ops.size() > 1 ? ops[1] : "";

        // Emit a label if this address is a jump target
        if (jump_targets.count(d.address)) {
            std::ostringstream ss;
            ss << "loc_" << std::hex << d.address << ":";
            out.push_back({ss.str(), std::max(0, indent-1)});
        }

        // ── Skip pure setup / noise ───────────────────────────────────────
        if (m == "NOP" || m == "INT3") continue;

        // Stack frame setup — just emit a comment
        if (m == "PUSH" && dst == "rbp") { emit("// --- prologue ---", true); continue; }
        if (m == "MOV"  && dst == "rbp" && src == "rsp") continue;
        if (m == "SUB"  && dst == "rsp") {
            emit("// local frame: " + src + " bytes", true);
            continue;
        }
        if (m == "ADD" && dst == "rsp") continue; // epilogue cleanup

        // ── MOV ───────────────────────────────────────────────────────────
        if (m == "MOV" || m == "MOVZX" || m == "MOVSX" || m == "MOVSXD") {
            std::string lhs = lift_op(dst);
            std::string rhs = lift_op(src);
            // Track register value for call arg inference
            if (is_reg(dst)) reg_val[dst] = rhs;
            // Skip trivial self-moves
            if (lhs == rhs) continue;
            emit_rva(d.address, lhs + " = " + rhs + ";");
            continue;
        }

        // ── LEA ───────────────────────────────────────────────────────────
        if (m == "LEA") {
            std::string rhs = strip_size(src);
            // LEA reg, [base + offset] → reg = base + offset
            if (rhs.size() >= 2 && rhs.front() == '[' && rhs.back() == ']')
                rhs = rhs.substr(1, rhs.size()-2);
            if (is_reg(dst)) reg_val[dst] = rhs;
            emit_rva(d.address, dst + " = " + rhs + ";");
            continue;
        }

        // ── Arithmetic ────────────────────────────────────────────────────
        if (m == "XOR" && dst == src) {
            if (is_reg(dst)) reg_val[dst] = "0";
            emit_rva(d.address, dst + " = 0;");
            continue;
        }
        if (m == "XOR")  { emit_rva(d.address, dst + " ^= " + lift_op(src) + ";"); continue; }
        if (m == "AND")  { emit_rva(d.address, dst + " &= " + lift_op(src) + ";"); continue; }
        if (m == "OR")   { emit_rva(d.address, dst + " |= " + lift_op(src) + ";"); continue; }
        if (m == "ADD")  { emit_rva(d.address, dst + " += " + lift_op(src) + ";"); continue; }
        if (m == "SUB")  { emit_rva(d.address, dst + " -= " + lift_op(src) + ";"); continue; }
        if (m == "IMUL") {
            if (ops.size() == 2)      emit_rva(d.address, dst + " *= " + lift_op(src) + ";");
            else if (ops.size() == 3) emit_rva(d.address, dst + " = " + lift_op(src) + " * " + lift_op(ops[2]) + ";");
            else                      emit_rva(d.address, "// imul (complex)");
            continue;
        }
        if (m == "SHL" || m == "SAL") { emit_rva(d.address, dst + " <<= " + lift_op(src) + ";"); continue; }
        if (m == "SHR")               { emit_rva(d.address, dst + " >>= " + lift_op(src) + ";"); continue; }
        if (m == "SAR")               { emit_rva(d.address, dst + " >>= " + lift_op(src) + ";  // arithmetic"); continue; }
        if (m == "NOT")               { emit_rva(d.address, dst + " = ~" + dst + ";"); continue; }
        if (m == "NEG")               { emit_rva(d.address, dst + " = -" + dst + ";"); continue; }
        if (m == "INC")               { emit_rva(d.address, dst + "++;"); continue; }
        if (m == "DEC")               { emit_rva(d.address, dst + "--;"); continue; }

        // ── PUSH / POP ────────────────────────────────────────────────────
        if (m == "PUSH") { emit_rva(d.address, "// push " + dst, true); continue; }
        if (m == "POP")  { emit_rva(d.address, "// pop  " + dst, true); continue; }

        // ── CALL ──────────────────────────────────────────────────────────
        if (m == "CALL") {
            // Build argument list from calling convention registers
            std::vector<std::string> args;
            const char **arg_regs = is_64bit ? k_x64_args : k_x86_args;
            int   num_arg_regs    = is_64bit ? 4 : 2;

            for (int a = 0; a < num_arg_regs; ++a) {
                std::string reg = arg_regs[a];
                auto it = reg_val.find(reg);
                if (it != reg_val.end() && it->second != reg)
                    args.push_back(it->second);
                else
                    args.push_back(reg);  // unknown, use register name
            }
            // Trim trailing unknown args (just the register names with no known value)
            while (!args.empty() && args.back() == arg_regs[args.size()-1])
                args.pop_back();

            std::string args_str;
            for (size_t i = 0; i < args.size(); ++i) {
                if (i) args_str += ", ";
                args_str += args[i];
            }

            // Resolve callee name
            std::string callee;
            if (d.branch_target) {
                auto it = call_map.find(d.branch_target);
                callee = (it != call_map.end()) ? it->second
                       : ("func_" + [&]{ std::ostringstream s; s << std::hex << d.branch_target; return s.str(); }());
            } else if (!dst.empty() && dst != "0x0") {
                callee = "(*" + lift_op(dst) + ")";
            } else {
                callee = "func_unknown";
            }

            std::string result_reg = is_64bit ? "rax" : "eax";
            reg_val[result_reg] = callee + "_result";

            // Emit API description as a comment if we know the function
            const char *api_tip = get_api_tip(callee);
            if (api_tip) {
                // First line of the tip only
                std::string first_line(api_tip);
                auto nl = first_line.find('\n');
                if (nl != std::string::npos) first_line = first_line.substr(0, nl);
                emit("// " + first_line, true);
            }

            emit_rva(d.address, result_reg + " = " + callee + "(" + args_str + ");");
            // Clear arg regs after call
            for (int a = 0; a < num_arg_regs; ++a) reg_val.erase(arg_regs[a]);
            continue;
        }

        // ── CMP / TEST ────────────────────────────────────────────────────
        if (m == "CMP") {
            pending = { lift_op(dst), lift_op(src), false, true };
            continue;  // don't emit — consumed by next JCC
        }
        if (m == "TEST") {
            // TEST reg, reg → check if reg == 0
            pending = { lift_op(dst), lift_op(src), true, true };
            continue;
        }

        // ── Conditional jumps ─────────────────────────────────────────────
        if (d.is_jump && !d.is_ret && (m.size() >= 2 && m[0] == 'J' && m != "JMP")) {
            bool backward = d.branch_target && d.branch_target < d.address;

            if (backward) {
                // Backward branch → while loop
                std::string cond = make_cond(m, pending, false);
                emit_rva(d.address, "while (" + cond + ") {");
                ++indent;
            } else {
                // Forward branch → if statement
                // The condition is true when we DON'T jump (fall-through)
                std::string cond = make_cond(m, pending, true);
                emit_rva(d.address, "if (" + cond + ") {");
                ++indent;

                // Look ahead: if target is within this function, emit else
                // (simplified: always close block at the jump target)
                // We'll close the block when we hit the target address
            }
            pending = {};
            continue;
        }

        // ── Unconditional jump ────────────────────────────────────────────
        if (m == "JMP") {
            if (d.branch_target) {
                bool backward = d.branch_target < d.address;
                if (backward) {
                    if (indent > 1) --indent;
                    emit_rva(d.address, "}  // end while");
                } else {
                    std::ostringstream ss;
                    ss << "goto loc_" << std::hex << d.branch_target << ";";
                    emit_rva(d.address, ss.str());
                }
            } else {
                emit_rva(d.address, "goto *" + lift_op(dst) + ";");
            }
            pending = {};
            continue;
        }

        // Close if-block when we reach the jump target of a previous JCC
        // (simple heuristic: close one indent level at labelled addresses)
        // This is handled by the label emission above — we'll also close indent
        if (jump_targets.count(d.address) && indent > 1) {
            --indent;
            out.push_back({"}", indent});
        }

        // ── RET ───────────────────────────────────────────────────────────
        if (m == "RET" || m == "RETN" || m == "RETF") {
            std::string ret_reg = is_64bit ? "rax" : "eax";
            auto it = reg_val.find(ret_reg);
            std::string val = (it != reg_val.end()) ? it->second : ret_reg;
            emit_rva(d.address, "return " + val + ";");
            if (indent > 1) { --indent; out.push_back({"}", indent}); }
            continue;
        }

        // ── XCHG ─────────────────────────────────────────────────────────
        if (m == "XCHG") {
            emit_rva(d.address, "swap(" + lift_op(dst) + ", " + lift_op(src) + ");");
            continue;
        }

        // ── Anything else: emit as a comment ─────────────────────────────
        emit_rva(d.address, "// " + d.mnemonic + (d.operands.empty() ? "" : " " + d.operands), true);
    }

    // Close function body
    while (indent > 1) { --indent; out.push_back({"}", indent}); }
    out.push_back({"}", 0});
    return out;
}
