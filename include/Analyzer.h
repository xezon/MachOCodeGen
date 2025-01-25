#ifndef ANALYZER_H
#define ANALYZER_H

// Remove forward declaration and include the actual header
#include "llvm/IR/Module.h"

class Analyzer {
public:
  explicit Analyzer(llvm::Module *M); // Added semicolon
  void analyze();                     // Added semicolon

private:
  llvm::Module *module; // Added semicolon
};                      // Added semicolon

#endif // ANALYZER_H