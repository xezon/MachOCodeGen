#include "MachOReader.h"
#include "utility.h"

#include <LIEF/LIEF.hpp>
#include <LIEF/MachO.hpp>

#include <llvm/Demangle/Demangle.h>

#include <mach-o/nlist.h>
#include <mach-o/stab.h>

bool MachOReader::Load(const std::string &filepath, LIEF::MachO::Header::CPU_TYPE cpuType)
{
    std::unique_ptr<LIEF::MachO::FatBinary> fatBinary = LIEF::MachO::Parser::parse(filepath);
    if (fatBinary == nullptr)
        return false;

    std::unique_ptr<LIEF::MachO::Binary> binary = fatBinary->take(cpuType);
    if (binary == nullptr)
        return false;

    if (!Parse(*binary))
        return false;

    return true;
}

// :f  Local function (non-global function)
// :F  Global function (exported function)
// :S  Local static variable (inside a function or translation unit)
// :V  Global variable (exported variable)
// :G  Local global-like variable (not static, but not exported)

bool MachOReader::Parse(const LIEF::MachO::Binary &binary)
{
    // Using std::malloc, because ItaniumPartialDemangler might use std::realloc on this buffer.
    constexpr size_t BufferSize = 1024;
    char *buffer = (char *)std::malloc(BufferSize);
    size_t bufferSize = BufferSize;
    index_t functionIndex = 0;
    bool inSOBlock = false;

    for (const LIEF::MachO::Symbol &symbol : binary.symbols())
    {
        switch (symbol.raw_type())
        {
            case N_SO: /* source file name: name,,n_sect,0,address */ {
                Parse_SO(symbol, inSOBlock);
                break;
            }
            case N_FUN: /* procedure: name,,n_sect,linenumber,address */ {
                Parse_FUN(symbol, buffer, bufferSize, functionIndex);
                break;
            }
        }
    }

    std::free((void *)buffer);

    return true;
}

void MachOReader::Parse_SO(const LIEF::MachO::Symbol &symbol, bool &inSOBlock)
{
    if (!symbol.name().empty())
    {
        if (!inSOBlock)
        {
            // Step 1/3
            inSOBlock = true;
            m_sourceFiles.emplace_back();
            SourceFile &sourceFile = m_sourceFiles.back();
            sourceFile.m_name = symbol.name();
            sourceFile.m_vaBegin = symbol.value();
        }
        else
        {
            // Step 2/3
            SourceFile &sourceFile = m_sourceFiles.back();
            // symbol.name() is expected to contain the previous symbol name.
            assert(strstr(symbol.name().c_str(), sourceFile.m_name.c_str()) == symbol.name().c_str());
            assert(sourceFile.m_vaBegin == symbol.value());

            sourceFile.m_name = symbol.name().substr(sourceFile.m_name.size());

            index_t index = m_sourceFiles.size() - 1;
            [[maybe_unused]] auto result = m_nameToSourceFileIndex.try_emplace(sourceFile.m_name, index);
            assert(result.second);
        }
    }
    else
    {
        // Step 3/3
        SourceFile &sourceFile = m_sourceFiles.back();
        assert(inSOBlock);
        assert(sourceFile.m_vaBegin != 0);

        sourceFile.m_vaEnd = symbol.value();
        inSOBlock = false;
    }
}

void MachOReader::Parse_FUN(const LIEF::MachO::Symbol &symbol, char *buffer, size_t &bufferSize, index_t &functionIndex)
{
    if (!symbol.name().empty())
    {
        // Step 1/2
        // Skip compiler generated symbols.
        if (starts_with(symbol.name(), "_GLOBAL__"))
            return;
        if (starts_with(symbol.name(), "_Z41")) // _Z41__static_initialization_and_destruction_0ii:f
            return;

        bool isLocal = ends_with(symbol.name(), ":f");
        bool isGlobal = ends_with(symbol.name(), ":F");
        assert(isGlobal || isLocal);

        std::string mangled = {symbol.name().data(), symbol.name().size() - 2};
        std::string demangled = mangled;
        bool isMangled = false;

        llvm::ItaniumPartialDemangler demangler;
        if (!demangler.partialDemangle(mangled.c_str())) // returns true on error, false otherwise.
        {
            isMangled = true;
            size_t size = bufferSize;
            buffer = demangler.finishDemangle(buffer, &size);
            if (buffer != nullptr)
                demangled = {buffer, size - 1};
            bufferSize = std::max(bufferSize, size);
        }

        bool createNewRecord = true;
        for (auto [begin, end] = m_nameToFunctionIndex.equal_range(demangled); begin != end; ++begin)
        {
            if (m_functions[begin->second].m_sourceFileIndex == m_sourceFiles.size() - 1)
            {
                functionIndex = begin->second;
                createNewRecord = false;
                break;
            }
        }

        if (createNewRecord)
        {
            // Add new record.

            m_functions.emplace_back();
            functionIndex = m_functions.size() - 1;
            Function &function = m_functions.back();
            function.m_name = std::move(demangled);
            function.m_sourceLine = symbol.description();
            function.m_isLocalFunction = isLocal;
            function.m_isGlobalFunction = isGlobal;
            function.m_headerFileIndex = InvalidIndex; // ???
            function.m_sourceFileIndex = m_sourceFiles.size() - 1;
            function.m_symbols.push_back(&symbol);
            function.m_mangledNames.push_back(std::move(mangled));

            if (isMangled)
            {
                size_t size = bufferSize;
                buffer = demangler.getFunctionBaseName(buffer, &size);
                if (buffer != nullptr && buffer[0] != '\0')
                {
                    std::string::size_type pos = function.m_name.find(buffer);
                    assert(pos != std::string::npos);
                    function.m_functionBaseName = {function.m_name.data() + pos, size - 1};
                }
                size = bufferSize = std::max(bufferSize, size);

                buffer = demangler.getFunctionDeclContextName(buffer, &size);
                if (buffer != nullptr && buffer[0] != '\0')
                {
                    std::string::size_type pos = function.m_name.find(buffer);
                    assert(pos != std::string::npos);
                    function.m_functionDeclContextName = {function.m_name.data() + pos, size - 1};
                }
                size = bufferSize = std::max(bufferSize, size);

                buffer = demangler.getFunctionName(buffer, &size);
                if (buffer != nullptr && buffer[0] != '\0')
                {
                    std::string::size_type pos = function.m_name.find(buffer);
                    assert(pos != std::string::npos);
                    function.m_functionName = {function.m_name.data() + pos, size - 1};
                }
                size = bufferSize = std::max(bufferSize, size);

                buffer = demangler.getFunctionParameters(buffer, &size);
                if (buffer != nullptr && buffer[0] != '\0')
                {
                    std::string::size_type pos = function.m_name.find(buffer);
                    assert(pos != std::string::npos);
                    function.m_functionParameters = {function.m_name.data() + pos, size - 1};
                }
                size = bufferSize = std::max(bufferSize, size);

                buffer = demangler.getFunctionReturnType(buffer, &size);
                if (buffer != nullptr && buffer[0] != '\0')
                {
                    std::string::size_type pos = function.m_name.find(buffer);
                    assert(pos != std::string::npos);
                    function.m_functionReturnType = {function.m_name.data() + pos, size - 1};
                }
                bufferSize = std::max(bufferSize, size);
            }

            m_sourceFiles.back().m_functionIndices.push_back(functionIndex);

            m_nameToFunctionIndex.emplace(function.m_name, functionIndex);
            m_mangledToFunctionIndex.emplace(function.m_mangledNames.back(), functionIndex);
        }
        else
        {
            // Append to existing record.

            Function &function = m_functions[functionIndex];
            function.m_symbols.push_back(&symbol);
            function.m_mangledNames.push_back(std::move(mangled));

            assert(function.m_sourceLine = symbol.description());
            assert(function.m_sourceFileIndex == m_sourceFiles.size() - 1);
            assert(function.m_isLocalFunction == isLocal);
            assert(function.m_isGlobalFunction == isGlobal);

            m_mangledToFunctionIndex.emplace(function.m_mangledNames.back(), functionIndex);
        }
    }
    else
    {
        // Step 2/2
        Function &function = m_functions[functionIndex];
        function.m_sizes.push_back(symbol.value());
    }
}
