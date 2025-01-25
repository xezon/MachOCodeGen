# MachOCodeGen

A tool for analyzing LLVM IR using the LLVM framework.

## Prerequisites

### Windows
1. Install LLVM:
   ```batch
   winget install LLVM
   ```
   Or download from [LLVM Releases](https://releases.llvm.org/)

2. Either:
   - Install LLVM to the default location (`C:/Program Files/LLVM`), or
   - Set the `LLVM_DIR` environment variable to your LLVM installation path

### macOS
1. Install LLVM using Homebrew:
   ```bash
   brew install llvm
   ```

## Building the Project

### Windows
```batch
mkdir build
cd build
cmake ..
cmake --build .
```

### macOS
```bash
mkdir build
cd build
cmake ..
make
```

## Usage

The analyzer takes an LLVM IR file as input and provides analysis information:

```bash
./analyzer input.ll
```

To generate LLVM IR from C/C++ code:
```bash
clang -S -emit-llvm input.c -o output.ll
```

## Project Structure