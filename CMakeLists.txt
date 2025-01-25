cmake_minimum_required(VERSION 3.13.4)

# Find brew prefix and LLVM installation
execute_process(
    COMMAND brew --prefix llvm
    OUTPUT_VARIABLE LLVM_BREW_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Set the C and CXX compilers before the project declaration
set(CMAKE_C_COMPILER "${LLVM_BREW_PATH}/bin/clang")
set(CMAKE_CXX_COMPILER "${LLVM_BREW_PATH}/bin/clang++")

project(MyLLVMProject)

# Set LLVM_DIR based on brew installation
set(LLVM_DIR "${LLVM_BREW_PATH}/lib/cmake/llvm")

message(STATUS "Using LLVM installed at: ${LLVM_BREW_PATH}")

# Find LLVM package
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# LLVM settings
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Include our own headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable
add_executable(analyzer
    src/main.cpp
    src/Analyzer.cpp
)

# Get the LLVM components we need
llvm_map_components_to_libnames(llvm_libs
    Core
    Support
    IRReader
    Analysis
)

# Link against LLVM libraries
target_link_libraries(analyzer ${llvm_libs}) 