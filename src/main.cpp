#include "Analyzer.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include <iostream>
#include <memory>

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <IR file>\n";
    return 1;
  }

  // Create LLVM context
  llvm::LLVMContext context;
  llvm::SMDiagnostic err;

  // Parse the IR file
  std::unique_ptr<llvm::Module> module =
      llvm::parseIRFile(argv[1], err, context);

  if (!module) {
    err.print(argv[0], llvm::errs());
    return 1;
  }

  // Create our analyzer and run it
  Analyzer analyzer(module.get());
  analyzer.analyze();

  return 0;
}