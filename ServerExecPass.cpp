#include "ServerExecPass.h"

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/ErrorHandling.h"

#include <array>
#include <cstdint>
#include <fstream>
#include <random>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> ServerExecEnable("obfserverexec", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static constexpr bool SkipLoops = true;
static constexpr unsigned PerFnCap = 32;
// This filename MUST match ServerExecServer.cpp's DefaultManifest. the pass writes it at compile time, the server reads it at startup, and a lockstep rename across both files is the ONLY way to change it without breaking first-run on the default path
static constexpr const char* ManifestPath = "SvxManifest.json";
static constexpr unsigned ManifestVersion = 2;

enum : uint8_t
{
    OpcodeInvalid = 0,
    OpcodeAdd = 1,
    OpcodeSub = 2,
    OpcodeXor = 3,
    OpcodeMul = 4,
    OpcodeAnd = 5,
    OpcodeOr = 6,
    OpcodeShl = 7,
    OpcodeLShr = 8,
    OpcodeAShr = 9,
    OpcodeUDiv = 10,
    OpcodeSDiv = 11,
    OpcodeURem = 12,
    OpcodeSRem = 13,
    OpcodeCount = 14,
};

static bool OpNeedsSextA(uint8_t op)
{
    return op == OpcodeAShr || op == OpcodeSDiv || op == OpcodeSRem;
}

static bool OpNeedsSextB(uint8_t op)
{
    return op == OpcodeSDiv || op == OpcodeSRem;
}

static uint8_t PickOpcode(unsigned op)
{
    switch (op)
    {
        case Instruction::Add: return OpcodeAdd;
        case Instruction::Sub: return OpcodeSub;
        case Instruction::Xor: return OpcodeXor;
        case Instruction::Mul: return OpcodeMul;
        case Instruction::And: return OpcodeAnd;
        case Instruction::Or: return OpcodeOr;
        case Instruction::Shl: return OpcodeShl;
        case Instruction::LShr: return OpcodeLShr;
        case Instruction::AShr: return OpcodeAShr;
        case Instruction::UDiv: return OpcodeUDiv;
        case Instruction::SDiv: return OpcodeSDiv;
        case Instruction::URem: return OpcodeURem;
        case Instruction::SRem: return OpcodeSRem;
        default: return OpcodeInvalid;
    }
}

// The lowercase strings here are wire data. The server's parse_op compares against "add"/"sub"/.../"srem" byte for byte, so any change here must land in ServerExecServer.cpp's ParseOp in the same change
static const char* OpcodeName(uint8_t op)
{
    switch (op)
    {
        case OpcodeAdd: return "add";
        case OpcodeSub: return "sub";
        case OpcodeXor: return "xor";
        case OpcodeMul: return "mul";
        case OpcodeAnd: return "and";
        case OpcodeOr: return "or";
        case OpcodeShl: return "shl";
        case OpcodeLShr: return "lshr";
        case OpcodeAShr: return "ashr";
        case OpcodeUDiv: return "udiv";
        case OpcodeSDiv: return "sdiv";
        case OpcodeURem: return "urem";
        case OpcodeSRem: return "srem";
        default: return "?";
    }
}

static std::array<uint8_t, 16> MakeRandomId()
{
    static std::mt19937_64 rng{std::random_device{}()};
    std::array<uint8_t, 16> out{};
    uint64_t lo = rng();
    uint64_t hi = rng();
    for (int i = 0; i < 8; ++i)
    {
        out[i] = (uint8_t)((lo >> (i * 8)) & 0xff);
        out[i + 8] = (uint8_t)((hi >> (i * 8)) & 0xff);
    }
    return out;
}

static std::string Hex32(const std::array<uint8_t, 16>& id)
{
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.resize(32);
    for (size_t i = 0; i < 16; ++i)
    {
        s[2 * i] = hex[(id[i] >> 4) & 0xf];
        s[2 * i + 1] = hex[id[i] & 0xf];
    }
    return s;
}

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static bool HasServerExecAnnotation(Function& f)
{
    return HasAnnotationTag(f, "serverexec");
}

static bool HasNoServerExecAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noserverexec");
}

static bool HasCommunicatorAnnotation(Function& f)
{
    return HasAnnotationTag(f, "ServerExecCommunicator");
}

static bool WantsServerExec(Function& f)
{
    if (HasNoServerExecAnnotation(f)) return false;
    return HasServerExecAnnotation(f);
}

static bool HasFuncletBody(Function& f)
{
    // Inserting a plain CallInst inside a catchpad or cleanuppad without a funclet operand bundle passes the verifier on MSVC EH personality functions but silently miscompiles at codegen because the backend emits the call in the wrong funclet section; this pass does not attach funclet bundles so any F with funclet body IR is skipped outright
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            if (isa<FuncletPadInst>(&i)) return true;
            if (isa<CatchReturnInst>(&i)) return true;
            if (isa<CleanupReturnInst>(&i)) return true;
        }
    }
    return false;
}

static Function* FindCommunicator(Module& m)
{
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* expected = FunctionType::get(i64, {ptrty, i64, i64}, false);

    Function* found = nullptr;
    unsigned nmatches = 0;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (!HasCommunicatorAnnotation(f)) continue;
        ++nmatches;
        if (!found) found = &f;
    }

    if (nmatches == 0) report_fatal_error("[serverexec] no ServerExecCommunicator function in module — tag the communicator with __attribute__((annotate(\"ServerExecCommunicator\"))) and compile its source into the client bitcode");
    if (nmatches > 1) report_fatal_error("[serverexec] multiple ServerExecCommunicator functions found — expected exactly one");
    if (found->getFunctionType() != expected) report_fatal_error("[serverexec] ServerExecCommunicator has wrong signature — expected i64(ptr, i64, i64)");

    // NoInline keeps the inliner from duplicating the HTTP client body into every call site which would let IPO constant-propagate the site id GV through the body and collapse the "opcode isn't in the client" property; NoUnwind keeps every call site Call eligible for setDoesNotThrow
    found->addFnAttr(Attribute::NoInline);
    found->addFnAttr(Attribute::NoUnwind);
    return found;
}

static GlobalVariable* EmitSiteIdGV(Module& m, const std::array<uint8_t, 16>& id, const std::string& hex)
{
    LLVMContext& c = m.getContext();
    Type* i8 = Type::getInt8Ty(c);
    ArrayType* at = ArrayType::get(i8, 16);

    std::vector<Constant*> bytes;
    bytes.reserve(16);
    for (uint8_t v : id) bytes.push_back(ConstantInt::get(i8, v));
    Constant* init = ConstantArray::get(at, bytes);

    GlobalVariable* gv = new GlobalVariable(m, at, true, GlobalValue::PrivateLinkage, init, "__svx_site_" + hex.substr(0, 16));
    gv->setAlignment(Align(1));
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

struct SiteRecord
{
    std::string hex;
    uint8_t op;
    uint32_t fnindex;
    std::vector<std::string> deps;
};

// Two dominators of B always form a chain (one dominates the other) so pick the "deeper" one. The dominator that is itself dominated by the other; giving B's immediate converted-dominator; the server's fire set check requires every prereq and by induction a legitimately fired immediate dom implies its own prereqs fired, so one dep suffices to chain the whole dominance path
static std::vector<int> ComputeImmediateDominators(const std::vector<BinaryOperator*>& sites, DominatorTree& dt)
{
    std::vector<int> result(sites.size(), -1);
    for (size_t b = 0; b < sites.size(); ++b)
    {
        int imm = -1;
        for (size_t a = 0; a < sites.size(); ++a)
        {
            if (a == b) continue;
            if (!dt.dominates(sites[a], sites[b])) continue;
            if (imm == -1)
            {
                imm = (int)a;
                continue;
            }
            if (dt.dominates(sites[imm], sites[a])) imm = (int)a;
        }
        result[b] = imm;
    }
    return result;
}

static void ProcessFunction(Function& f, Function* communicator, uint32_t fnindex, std::vector<SiteRecord>& out)
{
    if (f.isDeclaration()) return;
    if (&f == communicator) return;
    if (!WantsServerExec(f)) return;
    if (f.hasFnAttribute(Attribute::Naked)) return;
    if (HasFuncletBody(f)) return;

    LLVMContext& c = f.getContext();
    Module& m = *f.getParent();
    Type* i64 = Type::getInt64Ty(c);

    // Build DT+LI locally; The plugin DLL links its own LLVM analysis infra and the host (clang-cl / opt) carries its own, AnalysisKey static IDs do not match across that boundary so MAM.getResult<FunctionAnalysisManagerModuleProxy> hands back either the wrong manager or analyses keyed by the host's IDs and the pass silently corrupts output IR
    DominatorTree dt;
    dt.recalculate(f);
    LoopInfo li;
    li.analyze(dt);

    // Collect candidates up-front. the per site rewrite calls EraseFromParent on the BinaryOperator so iterating the function while rewriting would invalidate the instruction iterator
    std::vector<std::pair<BinaryOperator*, uint8_t>> targets;

    for (BasicBlock& bb : f)
    {
        bool inloop = SkipLoops && (li.getLoopFor(&bb) != nullptr);
        for (Instruction& i : bb)
        {
            auto* bo = dyn_cast<BinaryOperator>(&i);
            if (!bo) continue;

            uint8_t op = PickOpcode(bo->getOpcode());
            if (op == OpcodeInvalid) continue;

            Type* ty = bo->getType();
            if (!ty->isIntegerTy() || ty->getIntegerBitWidth() > 64) continue;
            if (inloop) continue;
            if (targets.size() >= PerFnCap) continue;

            targets.emplace_back(bo, op);
        }
    }

    if (targets.empty()) return;

    // pre generate site ids and compute deps BEFORE any IR mutation. The dominance queries must run against the original BinaryOperator positions, and EraseFromParent inside the rewrite loop would invalidate those pointers before ComputeImmediateDominators ever ran if ordering were flipped
    std::vector<std::array<uint8_t, 16>> ids(targets.size());
    std::vector<std::string> hexes(targets.size());
    for (size_t i = 0; i < targets.size(); ++i)
    {
        ids[i] = MakeRandomId();
        hexes[i] = Hex32(ids[i]);
    }

    std::vector<BinaryOperator*> bos(targets.size());
    for (size_t i = 0; i < targets.size(); ++i) bos[i] = targets[i].first;
    std::vector<int> deps = ComputeImmediateDominators(bos, dt);

    for (size_t i = 0; i < targets.size(); ++i)
    {
        BinaryOperator* bo = targets[i].first;
        uint8_t op = targets[i].second;
        GlobalVariable* gv = EmitSiteIdGV(m, ids[i], hexes[i]);

        IRBuilder<> b(bo);
        Value* aorig = bo->getOperand(0);
        Value* borig = bo->getOperand(1);
        unsigned bw = bo->getType()->getIntegerBitWidth();

        //  AShr's data operand and both SDiv/SRem operands need SExt; ZExt would zero fill the upper half and the server's i64 compute would silently return a wrong signed value after truncation at the site
        bool sexta = OpNeedsSextA(op);
        bool sextb = OpNeedsSextB(op);
        Value* a64 = (bw == 64) ? aorig : (sexta ? b.CreateSExt(aorig, i64) : b.CreateZExt(aorig, i64));
        Value* b64 = (bw == 64) ? borig : (sextb ? b.CreateSExt(borig, i64) : b.CreateZExt(borig, i64));

        CallInst* call = b.CreateCall(communicator, {gv, a64, b64});
        call->setDoesNotThrow();

        Value* result = (bw == 64) ? static_cast<Value*>(call) : b.CreateTrunc(call, bo->getType());

        bo->replaceAllUsesWith(result);
        bo->eraseFromParent();

        SiteRecord rec;
        rec.hex = hexes[i];
        rec.op = op;
        rec.fnindex = fnindex;
        if (deps[i] >= 0) rec.deps.push_back(hexes[deps[i]]);
        out.push_back(std::move(rec));
    }
}

// The manifest MUST stay on the obfuscator controlled server exclusively; publishing it recovers every op the pass ever hid, so the build pipeline must move this file to the server deploy pipeline and never into any client side artifact
static void WriteManifest(Module& m, const std::vector<SiteRecord>& sites)
{
    std::ofstream ofs(ManifestPath, std::ios::trunc);
    if (!ofs) report_fatal_error("[serverexec] could not open manifest for write");

    ofs << "{\n  \"version\": " << ManifestVersion
        << ",\n  \"module\": \"" << m.getName().str()
        << "\",\n  \"sites\": [\n";

    for (size_t i = 0; i < sites.size(); ++i)
    {
        const SiteRecord& s = sites[i];
        if (i) ofs << ",\n";
        ofs << "    { \"id\": \"" << s.hex
            << "\", \"op\": \"" << OpcodeName(s.op)
            << "\", \"fn\": " << s.fnindex
            << ", \"deps\": [";
        for (size_t d = 0; d < s.deps.size(); ++d)
        {
            if (d) ofs << ", ";
            ofs << "\"" << s.deps[d] << "\"";
        }
        ofs << "] }";
    }
    ofs << "\n  ]\n}\n";
}

bool RunServerExec(Module& m)
{
    if (!ServerExecEnable) return false;

    bool anywants = false;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (WantsServerExec(f))
        {
            anywants = true;
            break;
        }
    }
    if (!anywants) return false;

    Function* communicator = FindCommunicator(m);

    std::vector<SiteRecord> sites;
    uint32_t fnindex = 0;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (&f == communicator) continue;
        if (!WantsServerExec(f)) continue;
        ProcessFunction(f, communicator, fnindex++, sites);
    }

    if (!sites.empty()) WriteManifest(m, sites);

    return !sites.empty();
}

PreservedAnalyses ServerExecPass::run(Module& m, ModuleAnalysisManager&)
{
    bool mutated = RunServerExec(m);
    return mutated ? PreservedAnalyses::none() : PreservedAnalyses::all();
}