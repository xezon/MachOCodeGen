cmake_minimum_required(VERSION 3.16)

# Use packagename_ROOT for FindPackage.
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

# Disable default MSVC warning level so we can set it ourselves.
if(POLICY CMP0092)
    cmake_policy(SET CMP0092 NEW)
endif()

# Disable default MSVC runtime hardcoding.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

# Platform detection
if(WIN32 OR "${CMAKE_SYSTEM}" MATCHES "Windows")
    set(WINDOWS TRUE)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_CXX_STANDARD 17)

# Platform-specific configurations
if(WINDOWS)
    if(MSVC)
        # Build with multiple processes: speeds up build on multi core processors
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
    endif()
endif()

# Set up a format target to do automated clang format checking.
find_package(ClangFormat)
include(ClangFormat)
include(FetchContent)

# Configure LIEF options before declaring
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_INSTALL OFF CACHE BOOL "" FORCE)
set(LIEF_C_API OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
set(LIEF_ART OFF CACHE BOOL "" FORCE)
set(LIEF_DEX OFF CACHE BOOL "" FORCE)
set(LIEF_VDEX OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    lief
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        0.15.1
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/lief
)
FetchContent_MakeAvailable(lief)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        bc889afb4c5bf1c0d8ee29ef35eaaf4c8bef8a5d
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/nlohmann_json
)
FetchContent_MakeAvailable(json)

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        0c9fce2ffefecfdce794e1859584e25877b7b592
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/fmt
)
FetchContent_MakeAvailable(fmt)

FetchContent_Declare(cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG        3bf268481da8208d171d8908e6491459de3651d7
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/cxxopts
)
FetchContent_MakeAvailable(cxxopts)

# TODO: Can we use FetchContent_MakeAvailable without getting the test suite for it?
FetchContent_Populate(span DOWNLOAD_EXTRACT_TIMESTAMP
    GIT_REPOSITORY https://github.com/xezon/span
    GIT_TAG        master
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/span)

set(GIT_PRE_CONFIGURE_FILE "gitinfo.cpp.in")
set(GIT_POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/gitinfo.cpp")

include(GitWatcher)
include(cmake/xllvmdemangler.cmake)


project(MachOCodeGen LANGUAGES C CXX)
add_executable(MachOCodeGen)

# Common sources for all platforms
target_sources(MachOCodeGen PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/gitinfo.cpp
    gitinfo.h
    src/main.cpp
    src/utility.cpp
    src/utility.h
    src/apple/apple_gnu_defs.h
    src/llvm/demangle.cpp
    src/llvm/demangle.h
)

# Common libraries for all platforms
target_link_libraries(MachOCodeGen PRIVATE
    LIEF::LIEF
    nlohmann_json
    fmt::fmt
    cxxopts::cxxopts
    XLLVMDemangler
)

target_include_directories(MachOCodeGen PRIVATE
    .
    src
    3rdparty/span/include
)

target_compile_definitions(MachOCodeGen PRIVATE
    $<$<CONFIG:MinSizeRel,Release,RelWithDebInfo>:RELEASE=1> # Can we do this nicer?
)
