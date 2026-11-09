#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct ServerExecPass : llvm::PassInfoMixin<ServerExecPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunServerExec(llvm::Module& m);

extern llvm::cl::opt<bool> ServerExecEnable;