#include "MachOReader.h"
#include "utility.h"

#include <LIEF/LIEF.hpp>
#include <LIEF/MachO.hpp>

#include <llvm/Demangle/Demangle.h>

#include <mach-o/nlist.h>
#include <mach-o/stab.h>

MachOReader::MachOReader()
{
}

MachOReader::~MachOReader()
{
}

bool MachOReader::Load(const std::string &filepath, LIEF::MachO::Header::CPU_TYPE cpuType)
{
    std::unique_ptr<LIEF::MachO::FatBinary> fatBinary = LIEF::MachO::Parser::parse(filepath);
    if (fatBinary == nullptr)
        return false;

    m_binary = fatBinary->take(cpuType);
    if (m_binary == nullptr)
        return false;

    if (!Parse(*m_binary))
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
    index_t functionIndex = InvalidIndex;
    bool SO_InBlock = false;
    std::string SO_Prefix;

    LIEF::MachO::Binary::it_const_symbols symbols = binary.symbols();
    auto SOL_begin = symbols.end();
    auto SOL_end = symbols.end();

    for (auto it = symbols.begin(); it != symbols.end(); ++it)
    {
        const LIEF::MachO::Symbol &symbol = *it;

        switch (symbol.raw_type())
        {
            case N_FUN: /* procedure: name,,n_sect,linenumber,address */ {
                Parse_FUN(symbol, buffer, bufferSize, functionIndex);
                // Parse SOL range after function has been parsed.
                if (symbol.name().empty())
                {
                    if (functionIndex != InvalidIndex)
                    {
                        for (auto SOL_it = SOL_begin; SOL_it != SOL_end; ++SOL_it)
                        {
                            const LIEF::MachO::Symbol &SOL_symbol = *SOL_it;
                            if (SOL_symbol.raw_type() == N_SOL)
                            {
                                Parse_SOL(SOL_symbol, SO_Prefix, functionIndex);
                            }
                        }
                    }
                    SOL_begin = symbols.end();
                    SOL_end = symbols.end();
                }
                break;
            }
            case N_SO: /* source file name: name,,n_sect,0,address */ {
                Parse_SO(symbol, SO_InBlock, SO_Prefix);
                break;
            }
            case N_SOL: /* #included file name: name,,n_sect,0,address */ {
                if (SOL_begin == symbols.end())
                    SOL_begin = it;
                SOL_end = it + 1;
            }
        }
    }

    std::free((void *)buffer);

    return true;
}

void MachOReader::Parse_SO(const LIEF::MachO::Symbol &symbol, bool &SO_InBlock, std::string &SO_Prefix)
{
    if (!symbol.name().empty())
    {
        if (!SO_InBlock)
        {
            // Step 1/3
            SO_InBlock = true;
            SO_Prefix = symbol.name();

            m_sourceFiles.emplace_back();
            SourceFile &sourceFile = m_sourceFiles.back();
            sourceFile.m_vaBegin = symbol.value();
        }
        else
        {
            // Step 2/3
            SourceFile &sourceFile = m_sourceFiles.back();

            assert(strstr(symbol.name().c_str(), SO_Prefix.c_str()) == symbol.name().c_str());
            assert(sourceFile.m_vaBegin == symbol.value());

            sourceFile.m_name = symbol.name().substr(SO_Prefix.size());

            index_t index = m_sourceFiles.size() - 1;
            [[maybe_unused]] auto result = m_nameToSourceFileIndex.try_emplace(sourceFile.m_name, index);
            assert(result.second);
        }
    }
    else
    {
        // Step 3/3
        SourceFile &sourceFile = m_sourceFiles.back();
        assert(SO_InBlock);
        assert(sourceFile.m_vaBegin != 0);

        sourceFile.m_vaEnd = symbol.value();
        SO_InBlock = false;
        SO_Prefix.clear();
    }
}

void MachOReader::Parse_SOL(const LIEF::MachO::Symbol &symbol, const std::string &SO_Prefix, index_t functionIndex)
{
    Function &function = m_functions[functionIndex];
    const uint64_t address = symbol.value();
    const std::string &name = symbol.name();

    const size_t variantIndex = function.m_variants.size() - 1;
    assert(address >= function.GetVirtualAddressBegin(variantIndex));
    assert(address < function.GetVirtualAddressEnd(variantIndex));

    std::string sanitizedName;
    if (starts_with(name, SO_Prefix))
    {
        sanitizedName = {name.data() + SO_Prefix.size(), name.size() - SO_Prefix.size()};
    }
    else
    {
        sanitizedName = name;
    }

    if (sanitizedName == m_sourceFiles.back().m_name)
    {
        // The .cpp file (N_SO)
        FunctionInstruction instruction;
        instruction.m_address = address;
        instruction.sourceFileIndex = m_sourceFiles.size() - 1;
        function.m_variants.back().m_instructions.push_back(instruction);
    }
    else
    {
        // A header file
        index_t headerFileIndex = FindOrCreateHeaderFileIndex(sanitizedName);

        assert(!ends_with(sanitizedName, ".cp"));
        assert(!ends_with(sanitizedName, ".cpp"));
        assert(headerFileIndex != InvalidIndex);

        FunctionInstruction instruction;
        instruction.m_address = address;
        instruction.headerFileIndex = headerFileIndex;
        function.m_variants.back().m_instructions.push_back(instruction);
    }
}

void MachOReader::Parse_FUN(const LIEF::MachO::Symbol &symbol, char *buffer, size_t &bufferSize, index_t &functionIndex)
{
    if (!symbol.name().empty())
    {
        // Step 1/2
        // Skip compiler generated symbols.
        if (starts_with(symbol.name(), "_GLOBAL__"))
        {
            functionIndex = InvalidIndex;
            return;
        }
        if (starts_with(symbol.name(), "_Z41")) // _Z41__static_initialization_and_destruction_0ii:f
        {
            functionIndex = InvalidIndex;
            return;
        }

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
            function.m_isLocalFunction = isLocal;
            function.m_isGlobalFunction = isGlobal;
            function.m_headerFileIndex = InvalidIndex; // ???
            function.m_sourceFileIndex = m_sourceFiles.size() - 1;
            {
                FunctionVariant variant;
                variant.m_mangledName = std::move(mangled);
                variant.m_virtualAddress = symbol.value();
                variant.m_sourceLine = symbol.description();
                function.m_variants.push_back(std::move(variant));
            }

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
            m_mangledToFunctionIndex.emplace(function.m_variants.back().m_mangledName, functionIndex);
        }
        else
        {
            // Append to existing record.

            Function &function = m_functions[functionIndex];

            {
                FunctionVariant variant;
                variant.m_mangledName = std::move(mangled);
                variant.m_virtualAddress = symbol.value();
                variant.m_sourceLine = symbol.description();
                function.m_variants.push_back(std::move(variant));
            }

            assert(function.m_isLocalFunction == isLocal);
            assert(function.m_isGlobalFunction == isGlobal);
            assert(function.m_sourceFileIndex == m_sourceFiles.size() - 1);

            m_mangledToFunctionIndex.emplace(function.m_variants.back().m_mangledName, functionIndex);
        }
    }
    else
    {
        // Step 2/2
        if (functionIndex != InvalidIndex)
        {
            Function &function = m_functions[functionIndex];
            function.m_variants.back().m_size = symbol.value();
        }
    }
}

index_t MachOReader::FindOrCreateHeaderFileIndex(const std::string &name)
{
    StringToIndexMap::iterator it = m_nameToHeaderFileIndex.find(name);
    if (it != m_nameToHeaderFileIndex.end())
        return it->second;

    HeaderFile headerFile;
    headerFile.m_name = name;
    m_headerFiles.push_back(std::move(headerFile));
    const index_t index = m_headerFiles.size() - 1;
    [[maybe_unused]] auto result = m_nameToHeaderFileIndex.try_emplace(name, index);
    assert(result.second);
    return index;
}
