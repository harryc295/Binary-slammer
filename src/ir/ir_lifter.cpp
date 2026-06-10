#include "ir_lifter.h"

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

// Passes (new pass manager)
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>

// ── Register helpers ──────────────────────────────────────────────────────────

// Map a register name to its canonical 64-bit base name
static std::string canonical_reg(const std::string &r) {
    static const std::unordered_map<std::string, std::string> k = {
        {"rax","rax"}, {"eax","rax"}, {"ax","rax"},  {"al","rax"}, {"ah","rax"},
        {"rbx","rbx"}, {"ebx","rbx"}, {"bx","rbx"},  {"bl","rbx"}, {"bh","rbx"},
        {"rcx","rcx"}, {"ecx","rcx"}, {"cx","rcx"},  {"cl","rcx"}, {"ch","rcx"},
        {"rdx","rdx"}, {"edx","rdx"}, {"dx","rdx"},  {"dl","rdx"}, {"dh","rdx"},
        {"rsi","rsi"}, {"esi","rsi"}, {"si","rsi"},  {"sil","rsi"},
        {"rdi","rdi"}, {"edi","rdi"}, {"di","rdi"},  {"dil","rdi"},
        {"rbp","rbp"}, {"ebp","rbp"}, {"bp","rbp"},  {"bpl","rbp"},
        {"rsp","rsp"}, {"esp","rsp"}, {"sp","rsp"},  {"spl","rsp"},
        {"r8","r8"},   {"r8d","r8"},  {"r8w","r8"},  {"r8b","r8"},
        {"r9","r9"},   {"r9d","r9"},  {"r9w","r9"},  {"r9b","r9"},
        {"r10","r10"}, {"r10d","r10"},{"r10w","r10"},{"r10b","r10"},
        {"r11","r11"}, {"r11d","r11"},{"r11w","r11"},{"r11b","r11"},
        {"r12","r12"}, {"r12d","r12"},{"r12w","r12"},{"r12b","r12"},
        {"r13","r13"}, {"r13d","r13"},{"r13w","r13"},{"r13b","r13"},
        {"r14","r14"}, {"r14d","r14"},{"r14w","r14"},{"r14b","r14"},
        {"r15","r15"}, {"r15d","r15"},{"r15w","r15"},{"r15b","r15"},
        {"rip","rip"},
    };
    auto it = k.find(r);
    return it != k.end() ? it->second : r;
}

// Return the bit width of a named register
static unsigned reg_bits(const std::string &r) {
    static const std::unordered_map<std::string, unsigned> k = {
        {"rax",64},{"rbx",64},{"rcx",64},{"rdx",64},
        {"rsi",64},{"rdi",64},{"rbp",64},{"rsp",64},
        {"r8",64},{"r9",64},{"r10",64},{"r11",64},
        {"r12",64},{"r13",64},{"r14",64},{"r15",64},{"rip",64},
        {"eax",32},{"ebx",32},{"ecx",32},{"edx",32},
        {"esi",32},{"edi",32},{"ebp",32},{"esp",32},
        {"r8d",32},{"r9d",32},{"r10d",32},{"r11d",32},
        {"r12d",32},{"r13d",32},{"r14d",32},{"r15d",32},
        {"ax",16},{"bx",16},{"cx",16},{"dx",16},
        {"si",16},{"di",16},{"bp",16},{"sp",16},
        {"r8w",16},{"r9w",16},{"r10w",16},{"r11w",16},
        {"r12w",16},{"r13w",16},{"r14w",16},{"r15w",16},
        {"al",8},{"bl",8},{"cl",8},{"dl",8},
        {"sil",8},{"dil",8},{"bpl",8},{"spl",8},
        {"r8b",8},{"r9b",8},{"r10b",8},{"r11b",8},
        {"r12b",8},{"r13b",8},{"r14b",8},{"r15b",8},
        {"ah",8},{"bh",8},{"ch",8},{"dh",8},
    };
    auto it = k.find(r);
    return it != k.end() ? it->second : 64;
}

// Is this a high-byte register (AH/BH/CH/DH)?
static bool is_hireg(const std::string &r) {
    return r == "ah" || r == "bh" || r == "ch" || r == "dh";
}

// ── Lifter context ────────────────────────────────────────────────────────────

struct Ctx {
    llvm::LLVMContext                              &lctx;
    llvm::IRBuilder<>                              &b;
    llvm::Function                                 *fn;
    llvm::Value                                    *mem_base;  // i8* opaque memory
    std::unordered_map<std::string, llvm::Value *>  reg_ptr;   // alloca per GPR
    std::unordered_map<std::string, llvm::Value *>  flag_ptr;  // alloca per flag (i1)
    std::unordered_map<uint64_t, llvm::BasicBlock*> bb_map;    // rva → LLVM block

    llvm::Type *i1()  { return llvm::Type::getInt1Ty(lctx); }
    llvm::Type *i8()  { return llvm::Type::getInt8Ty(lctx); }
    llvm::Type *i16() { return llvm::Type::getInt16Ty(lctx); }
    llvm::Type *i32() { return llvm::Type::getInt32Ty(lctx); }
    llvm::Type *i64() { return llvm::Type::getInt64Ty(lctx); }
    llvm::Type *ptr() { return llvm::PointerType::getUnqual(lctx); }

    llvm::IntegerType *iN(unsigned bits) {
        return llvm::IntegerType::get(lctx, bits);
    }

    llvm::ConstantInt *imm(int64_t v, unsigned bits = 64) {
        return llvm::ConstantInt::get(iN(bits), static_cast<uint64_t>(v), true);
    }

    // Load the full 64-bit value of a GPR
    llvm::Value *load_reg64(const std::string &base) {
        auto it = reg_ptr.find(base);
        if (it == reg_ptr.end()) return imm(0);
        return b.CreateLoad(i64(), it->second, base + "_v");
    }

    // Read a register (any width), returns iN
    llvm::Value *read_reg(const std::string &r) {
        std::string base = canonical_reg(r);
        llvm::Value *full = load_reg64(base);
        unsigned bits = reg_bits(r);
        if (is_hireg(r)) {
            // bits 8-15
            llvm::Value *shifted = b.CreateLShr(full, imm(8));
            return b.CreateTrunc(shifted, iN(8));
        }
        if (bits == 64) return full;
        return b.CreateTrunc(full, iN(bits));
    }

    // Write a register (any width)
    void write_reg(const std::string &r, llvm::Value *val) {
        std::string base = canonical_reg(r);
        auto it = reg_ptr.find(base);
        if (it == reg_ptr.end()) return;

        unsigned bits = reg_bits(r);
        if (bits == 64) {
            b.CreateStore(val, it->second);
            return;
        }
        if (bits == 32) {
            // x64 rule: writing 32-bit reg zero-extends to 64 bits
            llvm::Value *ext = b.CreateZExt(val, i64());
            b.CreateStore(ext, it->second);
            return;
        }
        // 16-bit or 8-bit: insert into full register
        llvm::Value *old = load_reg64(base);
        uint64_t mask;
        uint64_t shift_amt;
        if (is_hireg(r)) {
            mask = ~0xFF00ULL;
            shift_amt = 8;
        } else if (bits == 16) {
            mask = ~0xFFFFULL;
            shift_amt = 0;
        } else {
            mask = ~0xFFULL;
            shift_amt = 0;
        }
        llvm::Value *cleared = b.CreateAnd(old, imm(static_cast<int64_t>(mask)));
        llvm::Value *ext     = b.CreateZExt(val, i64());
        if (shift_amt) ext = b.CreateShl(ext, imm(static_cast<int64_t>(shift_amt)));
        b.CreateStore(b.CreateOr(cleared, ext), it->second);
    }

    llvm::Value *read_flag(const std::string &f) {
        auto it = flag_ptr.find(f);
        if (it == flag_ptr.end()) return llvm::ConstantInt::getFalse(lctx);
        return b.CreateLoad(i1(), it->second, f + "_v");
    }

    void write_flag(const std::string &f, llvm::Value *v) {
        auto it = flag_ptr.find(f);
        if (it != flag_ptr.end())
            b.CreateStore(v, it->second);
    }

    // Compute ZF, SF from result; CF/OF from with.overflow intrinsics
    void update_flags_add(llvm::Value *res, llvm::Value *a, llvm::Value *b_val) {
        unsigned bits = res->getType()->getIntegerBitWidth();
        write_flag("zf", b.CreateICmpEQ(res, llvm::ConstantInt::get(res->getType(), 0)));
        write_flag("sf", b.CreateICmpSLT(res, llvm::ConstantInt::get(res->getType(), 0)));
        // CF = unsigned overflow
        auto *uadd = llvm::Intrinsic::getOrInsertDeclaration(
            fn->getParent(), llvm::Intrinsic::uadd_with_overflow,
            {llvm::IntegerType::get(lctx, bits)});
        llvm::Value *ures = b.CreateCall(
            llvm::cast<llvm::Function>(uadd), {a, b_val});
        write_flag("cf", b.CreateExtractValue(ures, 1));
        // OF = signed overflow
        auto *sadd = llvm::Intrinsic::getOrInsertDeclaration(
            fn->getParent(), llvm::Intrinsic::sadd_with_overflow,
            {llvm::IntegerType::get(lctx, bits)});
        llvm::Value *sres = b.CreateCall(
            llvm::cast<llvm::Function>(sadd), {a, b_val});
        write_flag("of", b.CreateExtractValue(sres, 1));
    }

    void update_flags_sub(llvm::Value *res, llvm::Value *a, llvm::Value *b_val) {
        unsigned bits = res->getType()->getIntegerBitWidth();
        write_flag("zf", b.CreateICmpEQ(res, llvm::ConstantInt::get(res->getType(), 0)));
        write_flag("sf", b.CreateICmpSLT(res, llvm::ConstantInt::get(res->getType(), 0)));
        // CF = a < b_val (unsigned borrow)
        write_flag("cf", b.CreateICmpULT(a, b_val));
        // OF = signed overflow on subtraction
        auto *ssub = llvm::Intrinsic::getOrInsertDeclaration(
            fn->getParent(), llvm::Intrinsic::ssub_with_overflow,
            {llvm::IntegerType::get(lctx, bits)});
        llvm::Value *sres = b.CreateCall(
            llvm::cast<llvm::Function>(ssub), {a, b_val});
        write_flag("of", b.CreateExtractValue(sres, 1));
    }

    void update_flags_logic(llvm::Value *res) {
        write_flag("zf", b.CreateICmpEQ(res, llvm::ConstantInt::get(res->getType(), 0)));
        write_flag("sf", b.CreateICmpSLT(res, llvm::ConstantInt::get(res->getType(), 0)));
        write_flag("cf", llvm::ConstantInt::getFalse(lctx));
        write_flag("of", llvm::ConstantInt::getFalse(lctx));
    }

    // Compute the address described by a MemAddr operand
    llvm::Value *effective_addr(const MemAddr &m) {
        llvm::Value *addr = imm(m.disp);
        if (!m.base.empty())
            addr = b.CreateAdd(addr, read_reg(m.base));
        if (!m.index.empty()) {
            llvm::Value *idx = read_reg(m.index);
            if (m.scale > 1)
                idx = b.CreateMul(idx, imm(m.scale));
            addr = b.CreateAdd(addr, idx);
        }
        return addr;
    }

    // Read from memory (symbolic — GEP off mem_base)
    llvm::Value *mem_load(llvm::Value *addr, uint8_t size_bytes) {
        llvm::Type *ty = iN(size_bytes * 8);
        llvm::Value *gep = b.CreateGEP(i8(), mem_base, addr, "mptr");
        return b.CreateLoad(ty, gep, "mld");
    }

    void mem_store(llvm::Value *addr, llvm::Value *val) {
        llvm::Value *gep = b.CreateGEP(i8(), mem_base, addr, "mptr");
        b.CreateStore(val, gep);
    }

    // Resolve an operand to an llvm::Value of the natural width
    llvm::Value *read_op(const RawOp &op) {
        switch (op.kind) {
        case OpKind::Reg:
            return read_reg(op.reg);
        case OpKind::Imm:
            return op.imm_unsigned
                   ? llvm::ConstantInt::get(iN(op.size_bytes * 8),
                                            static_cast<uint64_t>(op.imm), false)
                   : llvm::ConstantInt::get(iN(op.size_bytes * 8),
                                            static_cast<uint64_t>(op.imm), true);
        case OpKind::Mem: {
            llvm::Value *addr = effective_addr(op.mem);
            return mem_load(addr, op.mem.size_bytes);
        }
        default:
            return imm(0);
        }
    }

    void write_op(const RawOp &op, llvm::Value *val) {
        if (op.kind == OpKind::Reg) {
            write_reg(op.reg, val);
        } else if (op.kind == OpKind::Mem) {
            llvm::Value *addr = effective_addr(op.mem);
            mem_store(addr, val);
        }
    }

    // Ensure val has exactly 'bits' bits (trunc or zext)
    llvm::Value *coerce(llvm::Value *v, unsigned bits) {
        unsigned vbits = v->getType()->getIntegerBitWidth();
        if (vbits == bits) return v;
        if (vbits > bits) return b.CreateTrunc(v, iN(bits));
        return b.CreateZExt(v, iN(bits));
    }
};

// ── Lift a single instruction ─────────────────────────────────────────────────

static void lift_insn(Ctx &ctx, const disasm_t &d,
                      const std::unordered_map<uint64_t, std::string> &call_map) {
    using Z = uint32_t;
    auto &b = ctx.b;
    const auto &ops = d.raw_ops;
    const uint8_t n = d.raw_op_count;

    // Uppercase mnemonic for matching
    const std::string &mn = d.mnemonic;

    // ── Data movement ──────────────────────────────────────────────────────────
    if (mn == "MOV" || mn == "MOVZX" || mn == "MOVSX" || mn == "MOVSXD") {
        if (n < 2) return;
        llvm::Value *src = ctx.read_op(ops[1]);
        unsigned dst_bits = ops[0].size_bytes * 8;
        if (mn == "MOVZX" || mn == "MOVSXD")
            src = mn == "MOVZX" ? b.CreateZExt(src, ctx.iN(dst_bits))
                                : b.CreateSExt(src, ctx.iN(dst_bits));
        else if (mn == "MOVSX")
            src = b.CreateSExt(src, ctx.iN(dst_bits));
        else
            src = ctx.coerce(src, dst_bits);
        ctx.write_op(ops[0], src);
        return;
    }

    if (mn == "XCHG" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.read_op(ops[1]);
        ctx.write_op(ops[0], bv);
        ctx.write_op(ops[1], a);
        return;
    }

    if (mn == "LEA" && n >= 2 && ops[1].kind == OpKind::Mem) {
        llvm::Value *addr = ctx.effective_addr(ops[1].mem);
        ctx.write_op(ops[0], ctx.coerce(addr, ops[0].size_bytes * 8));
        return;
    }

    if (mn == "PUSH" && n >= 1) {
        llvm::Value *rsp = ctx.load_reg64("rsp");
        llvm::Value *new_rsp = b.CreateSub(rsp, ctx.imm(8));
        ctx.b.CreateStore(new_rsp, ctx.reg_ptr["rsp"]);
        llvm::Value *val = ctx.read_op(ops[0]);
        ctx.mem_store(new_rsp, ctx.coerce(val, 64));
        return;
    }

    if (mn == "POP" && n >= 1) {
        llvm::Value *rsp = ctx.load_reg64("rsp");
        llvm::Value *val = ctx.mem_load(rsp, 8);
        ctx.write_op(ops[0], ctx.coerce(val, ops[0].size_bytes * 8));
        llvm::Value *new_rsp = b.CreateAdd(rsp, ctx.imm(8));
        ctx.b.CreateStore(new_rsp, ctx.reg_ptr["rsp"]);
        return;
    }

    // ── Arithmetic ─────────────────────────────────────────────────────────────
    if ((mn == "ADD" || mn == "ADC") && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateAdd(a, bv);
        ctx.update_flags_add(res, a, bv);
        ctx.write_op(ops[0], res);
        return;
    }

    if ((mn == "SUB" || mn == "SBB") && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateSub(a, bv);
        ctx.update_flags_sub(res, a, bv);
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "INC" && n >= 1) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *res = b.CreateAdd(a, llvm::ConstantInt::get(a->getType(), 1));
        ctx.write_flag("zf", b.CreateICmpEQ(res, llvm::ConstantInt::get(res->getType(), 0)));
        ctx.write_flag("sf", b.CreateICmpSLT(res, llvm::ConstantInt::get(res->getType(), 0)));
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "DEC" && n >= 1) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *res = b.CreateSub(a, llvm::ConstantInt::get(a->getType(), 1));
        ctx.write_flag("zf", b.CreateICmpEQ(res, llvm::ConstantInt::get(res->getType(), 0)));
        ctx.write_flag("sf", b.CreateICmpSLT(res, llvm::ConstantInt::get(res->getType(), 0)));
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "NEG" && n >= 1) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *res = b.CreateNeg(a);
        ctx.update_flags_sub(res, llvm::ConstantInt::get(a->getType(), 0), a);
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "IMUL") {
        if (n == 1) {
            // IMUL r/m: RDX:RAX = RAX * src
            llvm::Value *a = ctx.read_reg("rax");
            llvm::Value *bv = ctx.coerce(ctx.read_op(ops[0]), 64);
            llvm::Value *wide = b.CreateMul(b.CreateSExt(a, ctx.iN(128)),
                                            b.CreateSExt(bv, ctx.iN(128)));
            ctx.write_reg("rax", b.CreateTrunc(wide, ctx.i64()));
            ctx.write_reg("rdx", b.CreateTrunc(
                b.CreateLShr(wide, ctx.imm(64, 128)), ctx.i64()));
        } else if (n == 2) {
            llvm::Value *a = ctx.read_op(ops[0]);
            llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
            ctx.write_op(ops[0], b.CreateMul(a, bv));
        } else if (n == 3) {
            llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), ops[0].size_bytes * 8);
            llvm::Value *cv = ctx.coerce(ctx.read_op(ops[2]), ops[0].size_bytes * 8);
            ctx.write_op(ops[0], b.CreateMul(bv, cv));
        }
        return;
    }

    if (mn == "MUL" && n >= 1) {
        llvm::Value *src = ctx.coerce(ctx.read_op(ops[0]), 64);
        llvm::Value *rax = ctx.read_reg("rax");
        llvm::Value *wide = b.CreateMul(b.CreateZExt(rax, ctx.iN(128)),
                                        b.CreateZExt(src, ctx.iN(128)));
        ctx.write_reg("rax", b.CreateTrunc(wide, ctx.i64()));
        ctx.write_reg("rdx", b.CreateTrunc(
            b.CreateLShr(wide, ctx.imm(64, 128)), ctx.i64()));
        return;
    }

    if ((mn == "DIV" || mn == "IDIV") && n >= 1) {
        bool sign = (mn == "IDIV");
        llvm::Value *src = ctx.coerce(ctx.read_op(ops[0]), 64);
        llvm::Value *rax = ctx.read_reg("rax");
        llvm::Value *q = sign ? b.CreateSDiv(rax, src) : b.CreateUDiv(rax, src);
        llvm::Value *r = sign ? b.CreateSRem(rax, src) : b.CreateURem(rax, src);
        ctx.write_reg("rax", q);
        ctx.write_reg("rdx", r);
        return;
    }

    // ── Bitwise / shift ────────────────────────────────────────────────────────
    if (mn == "AND" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateAnd(a, bv);
        ctx.update_flags_logic(res);
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "OR" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateOr(a, bv);
        ctx.update_flags_logic(res);
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "XOR" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        // XOR reg, reg — common zero idiom; LLVM will fold this
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateXor(a, bv);
        ctx.update_flags_logic(res);
        ctx.write_op(ops[0], res);
        return;
    }

    if (mn == "NOT" && n >= 1) {
        llvm::Value *a = ctx.read_op(ops[0]);
        ctx.write_op(ops[0], b.CreateNot(a));
        return;
    }

    if ((mn == "SHL" || mn == "SAL") && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *cnt = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        ctx.write_op(ops[0], b.CreateShl(a, cnt));
        return;
    }

    if (mn == "SHR" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *cnt = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        ctx.write_op(ops[0], b.CreateLShr(a, cnt));
        return;
    }

    if (mn == "SAR" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *cnt = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        ctx.write_op(ops[0], b.CreateAShr(a, cnt));
        return;
    }

    if ((mn == "ROL" || mn == "ROR") && n >= 2) {
        llvm::Value *a   = ctx.read_op(ops[0]);
        unsigned bits    = a->getType()->getIntegerBitWidth();
        llvm::Value *cnt = ctx.coerce(ctx.read_op(ops[1]), bits);
        llvm::Value *inv = b.CreateSub(llvm::ConstantInt::get(ctx.iN(bits), bits), cnt);
        llvm::Value *res = mn == "ROL"
            ? b.CreateOr(b.CreateShl(a, cnt), b.CreateLShr(a, inv))
            : b.CreateOr(b.CreateLShr(a, cnt), b.CreateShl(a, inv));
        ctx.write_op(ops[0], res);
        return;
    }

    // ── Comparison ─────────────────────────────────────────────────────────────
    if (mn == "CMP" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateSub(a, bv);
        ctx.update_flags_sub(res, a, bv);
        return;
    }

    if (mn == "TEST" && n >= 2) {
        llvm::Value *a = ctx.read_op(ops[0]);
        llvm::Value *bv = ctx.coerce(ctx.read_op(ops[1]), a->getType()->getIntegerBitWidth());
        llvm::Value *res = b.CreateAnd(a, bv);
        ctx.update_flags_logic(res);
        return;
    }

    // ── Control flow ───────────────────────────────────────────────────────────
    if (mn == "JMP") {
        if (n >= 1 && ops[0].kind == OpKind::Imm) {
            uint64_t tgt = static_cast<uint64_t>(ops[0].imm);
            auto it = ctx.bb_map.find(tgt);
            if (it != ctx.bb_map.end()) {
                b.CreateBr(it->second);
                return;
            }
        }
        // Indirect or unknown target — emit unreachable
        b.CreateUnreachable();
        return;
    }

    // Conditional jumps — check mnemonic
    auto emit_condbr = [&](llvm::Value *cond, uint64_t true_rva) {
        auto tit = ctx.bb_map.find(true_rva);
        if (!tit) return;
        // Fall-through block: next instruction after the jump
        uint64_t ft_rva = d.address + d.bytes.size();
        auto fit = ctx.bb_map.find(ft_rva);
        if (fit == ctx.bb_map.end()) {
            b.CreateCondBr(cond, tit->second, tit->second); // degenerate
            return;
        }
        b.CreateCondBr(cond, tit->second, fit->second);
    };

    auto jcc_target = [&]() -> uint64_t {
        return (n >= 1 && ops[0].kind == OpKind::Imm)
               ? static_cast<uint64_t>(ops[0].imm) : 0;
    };

    llvm::Value *zf = ctx.read_flag("zf");
    llvm::Value *sf = ctx.read_flag("sf");
    llvm::Value *of = ctx.read_flag("of");
    llvm::Value *cf = ctx.read_flag("cf");

    if (mn == "JE" || mn == "JZ") { emit_condbr(zf, jcc_target()); return; }
    if (mn == "JNE" || mn == "JNZ") { emit_condbr(b.CreateNot(zf), jcc_target()); return; }
    if (mn == "JS") { emit_condbr(sf, jcc_target()); return; }
    if (mn == "JNS") { emit_condbr(b.CreateNot(sf), jcc_target()); return; }
    if (mn == "JO") { emit_condbr(of, jcc_target()); return; }
    if (mn == "JNO") { emit_condbr(b.CreateNot(of), jcc_target()); return; }
    if (mn == "JB" || mn == "JC" || mn == "JNAE") { emit_condbr(cf, jcc_target()); return; }
    if (mn == "JNB" || mn == "JNC" || mn == "JAE") { emit_condbr(b.CreateNot(cf), jcc_target()); return; }
    if (mn == "JBE" || mn == "JNA") {
        emit_condbr(b.CreateOr(cf, zf), jcc_target()); return;
    }
    if (mn == "JA" || mn == "JNBE") {
        emit_condbr(b.CreateAnd(b.CreateNot(cf), b.CreateNot(zf)), jcc_target()); return;
    }
    if (mn == "JL" || mn == "JNGE") {
        emit_condbr(b.CreateXor(sf, of), jcc_target()); return;
    }
    if (mn == "JGE" || mn == "JNL") {
        emit_condbr(b.CreateNot(b.CreateXor(sf, of)), jcc_target()); return;
    }
    if (mn == "JLE" || mn == "JNG") {
        emit_condbr(b.CreateOr(zf, b.CreateXor(sf, of)), jcc_target()); return;
    }
    if (mn == "JG" || mn == "JNLE") {
        emit_condbr(b.CreateAnd(b.CreateNot(zf),
                                b.CreateNot(b.CreateXor(sf, of))), jcc_target());
        return;
    }

    if (mn == "CALL") {
        // Emit as a call to an external (or known internal) function
        std::string callee_name = "sub_" + std::to_string(d.branch_target);
        if (d.branch_target) {
            auto cit = call_map.find(d.branch_target);
            if (cit != call_map.end()) callee_name = cit->second;
        }
        // Declare as external void() for now
        llvm::FunctionType *fty = llvm::FunctionType::get(ctx.i64(), false);
        llvm::FunctionCallee callee =
            ctx.fn->getParent()->getOrInsertFunction(callee_name, fty);
        llvm::Value *ret = b.CreateCall(callee, {});
        ctx.write_reg("rax", ret); // return value in rax per calling convention
        return;
    }

    if (mn == "RET") {
        b.CreateRet(ctx.read_reg("rax"));
        return;
    }

    if (mn == "NOP" || mn == "ENDBR64" || mn == "ENDBR32") return;

    if (mn == "LEAVE") {
        // MOV RSP, RBP; POP RBP
        llvm::Value *rbp = ctx.read_reg("rbp");
        ctx.write_reg("rsp", rbp);
        llvm::Value *old_rbp = ctx.mem_load(rbp, 8);
        ctx.write_reg("rbp", old_rbp);
        llvm::Value *rsp = b.CreateAdd(ctx.load_reg64("rsp"), ctx.imm(8));
        ctx.b.CreateStore(rsp, ctx.reg_ptr["rsp"]);
        return;
    }

    if (mn == "CDQE" || mn == "CWDE" || mn == "CBW") {
        unsigned from = mn == "CDQE" ? 32 : (mn == "CWDE" ? 16 : 8);
        unsigned to   = mn == "CDQE" ? 64 : (mn == "CWDE" ? 32 : 16);
        std::string src_r = mn == "CDQE" ? "eax" : (mn == "CWDE" ? "ax" : "al");
        ctx.write_reg("rax", b.CreateSExt(ctx.read_reg(src_r), ctx.iN(to)));
        (void)from;
        return;
    }

    if (mn == "XORPS" || mn == "XORPD" || mn == "PXOR") {
        // Treat as integer XOR on the register pair — simplified
        if (n >= 2 && ops[0].kind == OpKind::Reg && ops[1].kind == OpKind::Reg &&
            ops[0].reg == ops[1].reg) {
            // XMM zero idiom — we don't model XMM, just NOP it
        }
        return;
    }

    // Unknown instruction — emit a comment-like poison to mark it
    // (noop from IR perspective; LLVM won't generate dead instructions anyway)
}

// ── Main lift entry point ─────────────────────────────────────────────────────

IRResult IRLifter::lift(const CFG &cfg,
                         bool is_64bit,
                         const std::string &func_name,
                         const std::unordered_map<uint64_t, std::string> &call_map) {
    IRResult result;

    if (cfg.blocks.empty()) {
        result.error = "Empty CFG";
        return result;
    }

    llvm::LLVMContext lctx;
    auto mod = std::make_unique<llvm::Module>(func_name, lctx);

    // Create function: i64 func(i8* mem_base)
    llvm::Type *i64 = llvm::Type::getInt64Ty(lctx);
    llvm::Type *ptr = llvm::PointerType::getUnqual(lctx);
    llvm::FunctionType *fty = llvm::FunctionType::get(i64, {ptr}, false);
    llvm::Function *fn = llvm::Function::Create(
        fty, llvm::Function::ExternalLinkage, func_name, mod.get());

    fn->getArg(0)->setName("mem_base");

    // Create entry block for alloca
    llvm::BasicBlock *entry_alloca =
        llvm::BasicBlock::Create(lctx, "entry_alloca", fn);
    llvm::IRBuilder<> b(entry_alloca);

    Ctx ctx{lctx, b, fn, fn->getArg(0), {}, {}, {}};

    // Alloca all GPRs
    static const char *gprs[] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15","rip"
    };
    for (const char *r : gprs)
        ctx.reg_ptr[r] = b.CreateAlloca(llvm::Type::getInt64Ty(lctx),
                                        nullptr, std::string(r) + "_ptr");
    // Alloca flags
    for (const char *f : {"cf","zf","sf","of","pf"})
        ctx.flag_ptr[f] = b.CreateAlloca(llvm::Type::getInt1Ty(lctx),
                                          nullptr, std::string(f) + "_ptr");

    // Create one LLVM BasicBlock per CFG block
    auto order = cfg.topo_order();
    for (uint64_t rva : order) {
        std::string name = "bb_" + std::to_string(rva);
        ctx.bb_map[rva] = llvm::BasicBlock::Create(lctx, name, fn);
    }

    // entry_alloca falls through to the first real block
    if (!order.empty())
        b.CreateBr(ctx.bb_map[order[0]]);
    else {
        b.CreateRet(llvm::ConstantInt::get(i64, 0));
        result.error = "No blocks in topo order";
        return result;
    }

    // Lift each block
    for (uint64_t rva : order) {
        auto bit = cfg.blocks.find(rva);
        if (bit == cfg.blocks.end()) continue;
        const BasicBlock &bb = bit->second;

        llvm::BasicBlock *llbb = ctx.bb_map[rva];
        b.SetInsertPoint(llbb);

        bool terminated = false;
        for (const auto &insn : bb.insns) {
            if (terminated) break;
            lift_insn(ctx, insn, call_map);
            // Check if we emitted a terminator
            if (llbb->getTerminator()) {
                terminated = true;
            }
        }

        // If no terminator was emitted, add a fall-through or ret
        if (!terminated) {
            if (!bb.succs.empty() && ctx.bb_map.count(bb.succs[0]))
                b.CreateBr(ctx.bb_map[bb.succs[0]]);
            else
                b.CreateRet(ctx.read_reg("rax"));
        }
    }

    // Emit raw IR
    {
        std::string buf;
        llvm::raw_string_ostream os(buf);
        mod->print(os, nullptr);
        result.raw_ir = buf;
    }

    // ── Optimization passes ───────────────────────────────────────────────────
    {
        llvm::LoopAnalysisManager      lam;
        llvm::FunctionAnalysisManager  fam;
        llvm::CGSCCAnalysisManager     cgam;
        llvm::ModuleAnalysisManager    mam;

        llvm::PassBuilder pb;
        pb.registerModuleAnalyses(mam);
        pb.registerCGSCCAnalyses(cgam);
        pb.registerFunctionAnalyses(fam);
        pb.registerLoopAnalyses(lam);
        pb.crossRegisterProxies(lam, fam, cgam, mam);

        llvm::ModulePassManager mpm;
        llvm::FunctionPassManager fpm;

        // Promote allocas (register file) to SSA values
        fpm.addPass(llvm::PromotePass());
        // Fold away constant folding, dead code, combine redundant ops
        fpm.addPass(llvm::InstCombinePass());
        // Global value numbering — eliminates redundant computations
        fpm.addPass(llvm::GVNPass());
        // Eliminate dead instructions
        fpm.addPass(llvm::DCEPass());
        // Simplify control flow
        fpm.addPass(llvm::SimplifyCFGPass());
        // Second round of instcombine after CFG cleanup
        fpm.addPass(llvm::InstCombinePass());
        fpm.addPass(llvm::DCEPass());

        mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
        mpm.run(*mod, mam);

        std::string buf;
        llvm::raw_string_ostream os(buf);
        mod->print(os, nullptr);
        result.opt_ir = buf;
    }

    result.valid = true;
    return result;
}
