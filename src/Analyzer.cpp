#include "Analyzer.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include <iostream>

Analyzer::Analyzer(llvm::Module *M) : module(M) {}

void Analyzer::analyze() {
  // Count functions and basic blocks
  unsigned numFunctions = 0;
  unsigned numBasicBlocks = 0;

  for (auto &F : *module) {
    numFunctions++;

    for (auto &BB : F) {
      numBasicBlocks++;
    }
  }

  std::cout << "Module Analysis Results:\n"
            << "Number of functions: " << numFunctions << "\n"
            << "Number of basic blocks: " << numBasicBlocks << "\n";
}