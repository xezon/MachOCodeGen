cmake_minimum_required(VERSION 3.13.4)

# Detect OS and set platform-specific variables
if(WIN32)
    # Windows: Try to find LLVM in standard install locations
    set(LLVM_DIR "C:/Program Files/LLVM/lib/cmake/llvm" CACHE PATH "LLVM installation directory")
    
    # Allow user to override LLVM path through environment variable
    if(DEFINED ENV{LLVM_DIR})
        set(LLVM_DIR "$ENV{LLVM_DIR}/lib/cmake/llvm")
    endif()
else()
    # macOS/Linux: Use brew path or system path
    execute_process(
        COMMAND brew --prefix llvm
        OUTPUT_VARIABLE LLVM_BREW_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE BREW_LLVM_RESULT
    )
    
    if(BREW_LLVM_RESULT EQUAL 0)
        set(LLVM_DIR "${LLVM_BREW_PATH}/lib/cmake/llvm")
        # Set compilers for macOS
        set(CMAKE_C_COMPILER "${LLVM_BREW_PATH}/bin/clang")
        set(CMAKE_CXX_COMPILER "${LLVM_BREW_PATH}/bin/clang++")
    endif()
endif()

project(MyLLVMProject)

message(STATUS "Looking for LLVM in: ${LLVM_DIR}")

# Find LLVM package
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# LLVM settings
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Include our own headers - make this relative to build directory
include_directories("${CMAKE_SOURCE_DIR}/include")  # Quote the path

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

# Set C++ standard for all targets
set_target_properties(analyzer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Windows-specific settings
if(MSVC)
    # Add Windows-specific compiler flags
    target_compile_options(analyzer PRIVATE
        /W4     # Warning level 4
        /EHsc   # Enable C++ exceptions
    )
else()
    # Unix-like compiler flags
    target_compile_options(analyzer PRIVATE
        -Wall
        -Wextra
    )
endif() 