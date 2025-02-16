#include "MachOReader.h"
#include "rtti.h"
#include "utility.h"

#include <LIEF/LIEF.hpp>
#include <LIEF/MachO.hpp>

#include "llvm/demangle.h"
#include <llvm/Demangle/Demangle.h>

#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
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

    Patch(*m_binary);

    if (!Parse(*m_binary))
        return false;

    return true;
}

template<typename T>
const T *TypeInfo(const LIEF::MachO::Binary &binary, uint32_t addr)
{
    auto data = binary.get_content_from_virtual_address(addr, sizeof(T));
    const T *typeinfo = reinterpret_cast<const T *>(data.data());
    return typeinfo;
}

std::string TypeName(const LIEF::MachO::Binary &binary, const __class_type_info *typeinfo)
{
    uint32_t addr = typeinfo->type_name;
    auto data = binary.get_content_from_virtual_address(addr, 1);
    const char *cstr = reinterpret_cast<const char *>(data.data());
    return llvm::itaniumDemangle(cstr, nullptr, nullptr, nullptr);
}

size_t FindClassNameBeginPos(std::string_view name)
{
    int groupCount = 0;
    for (size_t i = name.size() - 1; i != std::string_view::npos; --i)
    {
        const char c = name[i];
        if (c == '>')
        {
            ++groupCount;
            continue;
        }
        if (c == '<')
        {
            --groupCount;
            continue;
        }
        if (groupCount > 0)
            continue;
        if (c == ':')
            return i + 1;
    }
    return std::string_view::npos;
}

std::string_view GetFunctionNameWithoutClassName(std::string_view name)
{
    int groupCount = 0;
    for (size_t i = name.size() - 1; i != std::string_view::npos; --i)
    {
        const char c = name[i];
        if (c == ')' || c == '>')
        {
            ++groupCount;
            continue;
        }
        if (c == '(' || c == '<')
        {
            --groupCount;
            continue;
        }
        if (groupCount > 0)
            continue;
        if (c == ':')
            return name.substr(i + 1);
    }
    return name;
}

std::string MakeFunctionNameWithNewClassName(std::string_view functionName, std::string_view newClassName)
{
    const std::string_view func = GetFunctionNameWithoutClassName(functionName);
    return std::string(newClassName).append("::").append(func);
}

void MachOReader::Patch(LIEF::MachO::Binary &binary)
{
    uint32_t symbolId = 0;

    std::unordered_map<uint32_t, RelocatedSymbol> symbolNumToRelocatedSymbol;
    symbolNumToRelocatedSymbol.reserve(5);

    for (const LIEF::MachO::Symbol &symbol : binary.symbols())
    {
        if (symbol.name() == "__ZTVN10__cxxabiv116__enum_type_infoE")
        {
            symbolNumToRelocatedSymbol[symbolId] = RelocatedSymbol::enum_type_info;
        }
        else if (symbol.name() == "__ZTVN10__cxxabiv117__class_type_infoE")
        {
            symbolNumToRelocatedSymbol[symbolId] = RelocatedSymbol::class_type_info;
        }
        else if (symbol.name() == "__ZTVN10__cxxabiv120__si_class_type_infoE")
        {
            symbolNumToRelocatedSymbol[symbolId] = RelocatedSymbol::si_class_type_info;
        }
        else if (symbol.name() == "__ZTVN10__cxxabiv121__vmi_class_type_infoE")
        {
            symbolNumToRelocatedSymbol[symbolId] = RelocatedSymbol::vmi_class_type_info;
        }
        else if (symbol.name() == "___cxa_pure_virtual")
        {
            symbolNumToRelocatedSymbol[symbolId] = RelocatedSymbol::cxa_pure_virtual;
        }
        ++symbolId;
    }

    const uint32_t externalRelocationOffset = binary.dynamic_symbol_command()->external_relocation_offset();
    const uint32_t nbExternalRelocations = binary.dynamic_symbol_command()->nb_external_relocations();
    const uint64_t vExtRelOff = binary.offset_to_virtual_address(externalRelocationOffset).value();
    const LIEF::span<const uint8_t> span =
        binary.get_content_from_virtual_address(vExtRelOff, nbExternalRelocations * sizeof(relocation_info));
    const LIEF::span<relocation_info> relocationTable((relocation_info *)span.data(), nbExternalRelocations);

    for (const relocation_info &relocation : relocationTable)
    {
        const auto it = symbolNumToRelocatedSymbol.find(relocation.r_symbolnum);
        if (it != symbolNumToRelocatedSymbol.end())
        {
            binary.patch_address(relocation.r_address, static_cast<uint32_t>(it->second), sizeof(uint32_t));
        }
    }
}

bool MachOReader::Parse(const LIEF::MachO::Binary &binary)
{
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
            case N_PEXT | N_SECT: {
                Parse_PEXT_thunks(symbol);
                break;
            }
            case N_GSYM: /* global symbol: name,,NO_SECT,type,0 */ {
                Parse_GSYM(symbol);
                break;
            }
            case N_FUN: /* procedure: name,,n_sect,linenumber,address */ {
                Parse_FUN(symbol, functionIndex);
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
                    functionIndex = InvalidIndex;
                }
                break;
            }
            case N_STSYM: /* static symbol: name,,n_sect,type,address */ {
                Parse_STSYM(symbol);
                break;
            }
            case N_LCSYM: /* .lcomm symbol: name,,n_sect,type,address */ {
                Parse_LCSYM(symbol);
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
                break;
            }
            case N_OPT: /* emitted with gcc2_compiled and in gcc source */
            case N_OSO: /* object file name: name,,0,0,st_mtime */
                break;
        }
    }

    for (auto it = symbols.begin(); it != symbols.end(); ++it)
    {
        const LIEF::MachO::Symbol &symbol = *it;

        switch (symbol.raw_type())
        {
            case N_PEXT | N_SECT: {
                Parse_PEXT_typeinfo(binary, symbol);
                Parse_PEXT_vtable(binary, symbol);
                break;
            }
        }
    }

    // Generate classes from functions because not all classes have RTTI.
    GenerateClassesFromFunctions();

    // Additional base class links need to be build before processing vtables.
    BuildBaseClassLinks();

    ProcessVtables();

    return true;
}

void MachOReader::Parse_PEXT_thunks(const LIEF::MachO::Symbol &symbol)
{
    if (starts_with(symbol.name(), "__ZThn")) // non-virtual thunk to ...
    {
        // Cannot use llvm::ItaniumPartialDemangler to get function details.
        std::string thunkName = llvm::itaniumDemangle(symbol.name().c_str(), nullptr, nullptr, nullptr);
        thunkName.erase(0, 21); // Erase "non-virtual thunk to "

        AddressToIndexMap::iterator it = m_addressToThunkIndex.find(symbol.value());
        assert(it == m_addressToThunkIndex.end());

        NonVirtualThunk thunk;
        thunk.m_name = std::move(thunkName);
        thunk.m_address = symbol.value();
        thunk.m_isDtor = thunk.m_name.find('~') != std::string::npos;

        m_thunks.push_back(std::move(thunk));
        const index_t index = m_thunks.size() - 1;
        m_addressToThunkIndex.emplace(symbol.value(), index);
    }
}

void MachOReader::Parse_PEXT_typeinfo(const LIEF::MachO::Binary &binary, const LIEF::MachO::Symbol &symbol)
{
    if (starts_with(symbol.name(), "__ZTI")) // typeinfo for ...
    {
        std::string className = llvm::itaniumDemangle(symbol.name().c_str(), nullptr, nullptr, nullptr);
        className.erase(0, 13); // Erase "typeinfo for "
        LIEF::span<const uint8_t> mem = binary.get_content_from_virtual_address(symbol.value(), sizeof(__class_type_info));
        auto typeinfo = (const __class_type_info *)mem.data();
        auto relocatedSymbol = *(const RelocatedSymbol *)&typeinfo->__vfptr;
        std::string className2 = TypeName(binary, typeinfo);
        assert(className == className2);

        switch (relocatedSymbol)
        {
            case RelocatedSymbol::enum_type_info: {
                FindOrCreateEnumByName(className);
                break;
            }
            case RelocatedSymbol::class_type_info: {
                FindOrCreateClassByName(className);
                break;
            }
            case RelocatedSymbol::si_class_type_info: {
                auto *si_typeinfo = TypeInfo<__si_class_type_info>(binary, symbol.value());
                auto *base_typeinfo = TypeInfo<__class_type_info>(binary, si_typeinfo->base_type);

                const index_t mainClassIndex = FindOrCreateClassByName(className);
                const std::string baseName = TypeName(binary, base_typeinfo);
                BaseClass baseClass;
                baseClass.m_classIndex = FindOrCreateClassByName(baseName);
                m_classes[mainClassIndex].m_directBaseClasses.push_back(std::move(baseClass));
                break;
            }
            case RelocatedSymbol::vmi_class_type_info: {
                auto *vmi_typeinfo = TypeInfo<__vmi_class_type_info>(binary, symbol.value());
                assert(vmi_typeinfo->flags == 0);
                const index_t mainClassIndex = FindOrCreateClassByName(className);

                for (uint32_t i = 0; i < vmi_typeinfo->base_count; ++i)
                {
                    auto *base_typeinfo = TypeInfo<__class_type_info>(binary, vmi_typeinfo->base_info[i].base_type);
                    const std::string baseName = TypeName(binary, base_typeinfo);
                    const uint32_t offset_flags = vmi_typeinfo->base_info[i].offset_flags;

                    BaseClass baseClass;
                    const uint32_t baseOffset = offset_flags >> __base_class_type_info::__offset_shift;
                    assert(baseOffset < 0xffffu);
                    baseClass.m_baseOffset = static_cast<uint16_t>(baseOffset);
                    baseClass.m_visibility = offset_flags & __base_class_type_info::__public_mask ?
                        BaseClassVisibility::Public :
                        BaseClassVisibility::Private_Or_Protected;
                    baseClass.m_isVirtual = offset_flags & __base_class_type_info::__virtual_mask;

                    uint16_t baseClassSize = 0;
                    if (i + 1 < vmi_typeinfo->base_count)
                    {
                        const uint32_t size =
                            (vmi_typeinfo->base_info[i + 1].offset_flags >> __base_class_type_info::__offset_shift)
                            - (vmi_typeinfo->base_info[i + 0].offset_flags >> __base_class_type_info::__offset_shift);
                        assert(size < 0xffffu);
                        baseClassSize = static_cast<uint16_t>(size);
                    }
                    const index_t baseClassIndex = FindOrCreateClassByName(baseName);
                    baseClass.m_classIndex = baseClassIndex;
                    if (baseClassSize > 0)
                    {
                        assert(m_classes[baseClassIndex].m_size == 0 || m_classes[baseClassIndex].m_size == baseClassSize);
                        m_classes[baseClassIndex].m_size = baseClassSize;
                    }
                    m_classes[mainClassIndex].m_directBaseClasses.push_back(std::move(baseClass));
                }
                break;
            }
        }
    }
}

void MachOReader::Parse_PEXT_vtable(const LIEF::MachO::Binary &binary, const LIEF::MachO::Symbol &symbol)
{
    if (starts_with(symbol.name(), "__ZTV")) // vtable for ...
    {
        // A Vtable has 2 destructors, generated by the compiler:
        // 1. Non-deleting destructor
        // 2. Deleting destructor (calls operator delete)

        std::string className = llvm::itaniumDemangle(symbol.name().c_str(), nullptr, nullptr, nullptr);
        className.erase(0, 11); // Erase "vtable for "
        const uint64_t symbolAddress = symbol.value();
        LIEF::span<const uint8_t> mem = binary.get_content_from_virtual_address(symbolAddress, sizeof(__vtable_info));
        auto vtable_info = (__vtable_info *)mem.data();

        const index_t classIndex = FindOrCreateClassByName(className);
        const LIEF::MachO::Section *vtableSection = binary.section_from_virtual_address(symbolAddress);
        const uint64_t vtableSectionEnd = vtableSection->virtual_address() + vtableSection->size();

        int vtableCount = 1;
        assert(vtable_info->offset_to_this == 0);
        m_classes[classIndex].m_vtables.emplace_back();
        VTable *vtable = &m_classes[classIndex].m_vtables.back();

        for (int i = 0, o = 0;; ++i, ++o)
        {
            VTableEntry vtableEntry;
            uint32_t functionAddress = vtable_info->function_address[i];
            const uint32_t curVtableOffset =
                symbolAddress + sizeof(__vtable_info) * vtableCount + sizeof(uint32_t) * (o - 1);
            if (curVtableOffset >= vtableSectionEnd)
                break; // End of vtable section.
            if (functionAddress == 0)
                break; // End of whole vtable.
            if (vtable_info->function_address[i + 1] == vtable_info->type_info)
            {
                vtable_info = (__vtable_info *)&vtable_info->function_address[i];
                vtableCount += 1;
                i = -1;
                o -= 1;
                m_classes[classIndex].m_vtables.emplace_back();
                vtable = &m_classes[classIndex].m_vtables.back();
                assert(-vtable_info->offset_to_this < 0xffff);
                vtable->m_offset = static_cast<uint16_t>(-vtable_info->offset_to_this);
                continue; // End of primary vtable, begin of secondary vtable.
            }

            if (vtableCount >= 2)
            {
                // Secondary vtable, contains non-virtual chunks among others.
                AddressToIndexMap::iterator it = m_addressToThunkIndex.find(functionAddress);
                if (it != m_addressToThunkIndex.end())
                {
                    vtableEntry.m_functionIndex = InvalidIndex;
                    vtableEntry.m_thunkIndex = it->second;
                    vtableEntry.m_name = m_thunks[it->second].m_name;
                    vtableEntry.m_isDtor = m_thunks[it->second].m_isDtor;
                    vtable->m_entries.push_back(std::move(vtableEntry));
                    continue;
                }
            }

            if (static_cast<RelocatedSymbol>(functionAddress) == RelocatedSymbol::cxa_pure_virtual)
            {
                // Is not a function pointer. Is pure virtual function.
                vtableEntry.m_functionIndex = InvalidIndex;
                vtableEntry.m_thunkIndex = InvalidIndex;
                vtableEntry.m_isPureVirtual = true;
                // Function name needs to be set in post process.
                vtable->m_entries.push_back(std::move(vtableEntry));
                continue;
            }

            const LIEF::MachO::Section *functionSection = binary.section_from_virtual_address(functionAddress);
            if (functionSection == nullptr)
                break; // Unknown entity.
            if (!(functionSection->name() == "__textcoal_nt" || functionSection->name() == "__text"))
                break; // Address does not belong to function.

            AddressToIndexMap::iterator it = m_addressToFunctionIndex.find(functionAddress);
            assert(it != m_addressToFunctionIndex.end());
            vtableEntry.m_functionIndex = it->second;
            vtableEntry.m_thunkIndex = InvalidIndex;
            vtableEntry.m_name = m_functions[it->second].m_name;
            vtableEntry.m_isDtor = m_functions[it->second].m_isCtorOrDtor;
            vtable->m_entries.push_back(std::move(vtableEntry));
        }
    }
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
            sourceFile.m_addressBegin = symbol.value();
        }
        else
        {
            // Step 2/3
            SourceFile &sourceFile = m_sourceFiles.back();

            assert(strstr(symbol.name().c_str(), SO_Prefix.c_str()) == symbol.name().c_str());
            assert(sourceFile.m_addressBegin == symbol.value());

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
        assert(sourceFile.m_addressBegin != 0);

        sourceFile.m_addressEnd = symbol.value();
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
        index_t headerFileIndex = FindOrCreateHeaderFileByName(sanitizedName);

        assert(!ends_with(sanitizedName, ".cp"));
        assert(!ends_with(sanitizedName, ".cpp"));
        assert(headerFileIndex != InvalidIndex);

        FunctionInstruction instruction;
        instruction.m_address = address;
        instruction.headerFileIndex = headerFileIndex;
        function.m_variants.back().m_instructions.push_back(instruction);
    }
}

void MachOReader::Parse_FUN(const LIEF::MachO::Symbol &symbol, index_t &functionIndex)
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
            const char *buffer = demangler.finishDemangle(nullptr, nullptr);
            assert(buffer != nullptr);
            demangled = buffer;
            std::free((void *)buffer);
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
            function.m_isConst = ends_with(function.m_name, "const");
            function.m_headerFileIndex = InvalidIndex; // ???
            function.m_sourceFileIndex = m_sourceFiles.size() - 1;
            {
                FunctionVariant variant;
                variant.m_mangledName = std::move(mangled);
                variant.m_address = symbol.value();
                variant.m_sourceLine = symbol.description();
                variant.m_section = symbol.numberof_sections();
                function.m_variants.push_back(std::move(variant));
            }

            if (isMangled)
            {
                if (const char *buffer = demangler.getFunctionBaseName(nullptr, nullptr))
                {
                    function.m_functionBaseName = buffer;
                    std::free((void *)buffer);
                }

                if (const char *buffer = demangler.getFunctionDeclContextName(nullptr, nullptr))
                {
                    function.m_functionDeclContextName = buffer;
                    std::free((void *)buffer);
                }

                if (const char *buffer = demangler.getFunctionName(nullptr, nullptr))
                {
                    function.m_functionName = buffer;
                    std::free((void *)buffer);
                }

                if (const char *buffer = demangler.getFunctionParameters(nullptr, nullptr))
                {
                    function.m_functionParameters = buffer;
                    std::free((void *)buffer);
                }

                if (const char *buffer = demangler.getFunctionReturnType(nullptr, nullptr))
                {
                    function.m_functionReturnType = buffer;
                    std::free((void *)buffer);
                }

                function.m_isCtorOrDtor = demangler.isCtorOrDtor();
                function.m_functionParameterTypes = Function::GetParameterTypes(function.m_functionParameters);
            }

            m_sourceFiles.back().m_functionIndices.push_back(functionIndex);
            m_nameToFunctionIndex.emplace(function.m_name, functionIndex);
            m_mangledToFunctionIndex.emplace(function.m_variants.back().m_mangledName, functionIndex);
            m_addressToFunctionIndex.emplace(function.m_variants.back().m_address, functionIndex);
        }
        else
        {
            // Append to existing record.

            Function &function = m_functions[functionIndex];

            {
                FunctionVariant variant;
                variant.m_mangledName = std::move(mangled);
                variant.m_address = symbol.value();
                variant.m_sourceLine = symbol.description();
                variant.m_section = symbol.numberof_sections();
                function.m_variants.push_back(std::move(variant));
            }

            assert(function.m_isLocalFunction == isLocal);
            assert(function.m_sourceFileIndex == m_sourceFiles.size() - 1);

            m_mangledToFunctionIndex.emplace(function.m_variants.back().m_mangledName, functionIndex);
            m_addressToFunctionIndex.emplace(function.m_variants.back().m_address, functionIndex);
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

void MachOReader::Parse_GSYM(const LIEF::MachO::Symbol &symbol) // TODO
{
    // assert(ends_with(symbol.name(), ":G"));
    // std::string mangled = std::string{symbol.name().data(), symbol.name().size() - 2};
    // std::string demangled = itanium_demangle(mangled);

    // m_variables.emplace_back();
    // Variable &variable = m_variables.back();
    // variable.m_name = demangled;
    // variable.m_description = symbol.description();
    // variable.m_type = Variable::Type::Global;

    // return;
}

void MachOReader::Parse_STSYM(const LIEF::MachO::Symbol &symbol) // TODO
{
    // assert(ends_with(symbol.name(), ":S") || ends_with(symbol.name(), ":V"));
    // std::string mangled = std::string{symbol.name().data(), symbol.name().size() - 2};
    // std::string demangled = itanium_demangle(mangled);

    // m_variables.emplace_back();
    // Variable &variable = m_variables.back();
    // variable.m_name = demangled;
    // variable.m_address = symbol.value();
    // variable.m_description = symbol.description();
    // variable.m_section = symbol.numberof_sections();
    // variable.m_type = Variable::Type::Static;

    // return;
}

void MachOReader::Parse_LCSYM(const LIEF::MachO::Symbol &symbol) // TODO
{
    // const bool s = ends_with(symbol.name(), ":S");
    // const bool v = ends_with(symbol.name(), ":V");
    // assert(s || v);

    // std::string mangled = std::string{symbol.name().data(), symbol.name().size() - 2};
    // std::string demangled = itanium_demangle(mangled);

    // index_t variableIndex;

    // AddressToIndexMap::iterator it = m_addressToVariableIndex.find(symbol.value());
    // if (it == m_addressToVariableIndex.end())
    //{
    //    // Create new

    //    m_variables.emplace_back();
    //    Variable &variable = m_variables.back();
    //    variable.m_name = demangled;
    //    variable.m_address = symbol.value();
    //    variable.m_description = symbol.description();
    //    variable.m_section = symbol.numberof_sections();
    //    variable.m_type = Variable::Type::Local;

    //    variableIndex = m_variables.size() - 1;
    //    m_addressToVariableIndex.emplace(symbol.value(), variableIndex);

    //    if (s)
    //    {

    //    }
    //    else if (v)
    //    {
    //        m_functions.back().m_variableIndices.push_back(variableIndex);
    //    }
    //}
    // else
    //{
    //    // Verify existing

    //    variableIndex = it->second;
    //    Variable &variable = m_variables[variableIndex];
    //    assert(variable.m_name == demangled);
    //    assert(variable.m_description == symbol.description());
    //    assert(variable.m_section == symbol.numberof_sections());
    //}
}

index_t MachOReader::FindOrCreateHeaderFileByName(const std::string &name)
{
    StringToIndexMap::iterator it = m_nameToHeaderFileIndex.find(name);
    if (it != m_nameToHeaderFileIndex.end())
        return it->second;

    HeaderFile headerFile;
    headerFile.m_name = name;
    m_headerFiles.push_back(std::move(headerFile));
    const index_t index = m_headerFiles.size() - 1;
    m_nameToHeaderFileIndex.emplace(name, index);
    return index;
}

index_t MachOReader::FindOrCreateNamespaceByName(const std::string &name)
{
    StringToIndexMap::iterator it = m_nameToNamespaceIndex.find(name);
    if (it != m_nameToNamespaceIndex.end())
        return it->second;

    Namespace namespaceType;
    namespaceType.m_name = name;
    m_namespaces.push_back(std::move(namespaceType));
    const index_t index = m_namespaces.size() - 1;
    m_nameToNamespaceIndex.emplace(name, index);

    const size_t pos = name.rfind("::");
    if (pos != std::string::npos)
    {
        m_namespaces[index].m_namespaceName = name.substr(pos + 2);
        const std::string parentName = name.substr(0, pos);
        index_t parentNamespaceIndex = FindOrCreateNamespaceByName(parentName);
        m_namespaces[index].m_parentNamespaceIndex = parentNamespaceIndex;
        m_namespaces[parentNamespaceIndex].m_childNamespaceIndices.push_back(index);
    }
    else
    {
        m_namespaces[index].m_namespaceName = name;
    }

    return index;
}

index_t MachOReader::FindOrCreateEnumByName(const std::string &name)
{
    StringToIndexMap::iterator it = m_nameToEnumIndex.find(name);
    if (it != m_nameToEnumIndex.end())
        return it->second;

    Enum enumType;
    enumType.m_name = name;
    m_enums.push_back(std::move(enumType));
    const index_t index = m_enums.size() - 1;
    m_nameToEnumIndex.emplace(name, index);
    return index;
}

index_t MachOReader::FindOrCreateClassByName(const std::string &name)
{
    StringToIndexMap::iterator it = m_nameToClassIndex.find(name);
    if (it != m_nameToClassIndex.end())
        return it->second;

    Class classType;
    classType.m_name = name;
    m_classes.push_back(std::move(classType));
    const index_t index = m_classes.size() - 1;
    m_nameToClassIndex.emplace(name, index);

    const size_t pos = FindClassNameBeginPos(name);
    if (pos != std::string::npos)
    {
        m_classes[index].m_className = name.substr(pos);
        const std::string parentName = name.substr(0, pos - 2);
        StringToIndexMap::iterator itParentClass = m_nameToClassIndex.find(parentName);
        if (itParentClass != m_nameToClassIndex.end())
        {
            m_classes[index].m_parentClassIndex = itParentClass->second;
            m_classes[itParentClass->second].m_childClassIndices.push_back(index);
        }
        else
        {
            if (IsExpectedClass(parentName))
            {
                const index_t parentClassIndex = FindOrCreateClassByName(parentName);
                m_classes[index].m_parentClassIndex = parentClassIndex;
                m_classes[parentClassIndex].m_childClassIndices.push_back(index);
            }
            else
            {
                const index_t namespaceIndex = FindOrCreateNamespaceByName(parentName);
                m_classes[index].m_parentNamespaceIndex = namespaceIndex;
                m_namespaces[namespaceIndex].m_classIndices.push_back(index);
            }
        }
    }
    else
    {
        m_classes[index].m_className = name;
    }

    return index;
}

bool MachOReader::IsKnownNamespace(const std::string &name) const
{
    return m_nameToNamespaceIndex.find(name) != m_nameToNamespaceIndex.end();
}

bool MachOReader::IsKnownClass(const std::string &name) const
{
    return m_nameToClassIndex.find(name) != m_nameToClassIndex.end();
}

bool MachOReader::IsExpectedClass(const std::string &name) const
{
    if (name.find("<") != std::string::npos)
        return true; // Has template syntax.

    if (HasCtorOrDtor(name))
        return true; // Expensive. Has constructor or destructor.

    if (IsFunctionArgument(name))
        return true; // Expensive. Type is used as function argument.

    // TODO: Check if there are static member variables in class.

    if (ends_with(name, "Class") || ends_with(name, "Struct"))
        return true; // Class is indicated in name.

    return false;
}

bool MachOReader::HasCtorOrDtor(const std::string &name) const
{
    for (const Function &function : m_functions)
    {
        if (function.m_functionDeclContextName == name && function.m_isCtorOrDtor)
        {
            return true;
        }
    }
    return false;
}

bool MachOReader::IsFunctionArgument(const std::string &name) const
{
    for (const Function &function : m_functions)
    {
        for (const std::string &type : function.m_functionParameterTypes)
        {
            if (type == name)
                return true;
        }
    }
    return false;
}

void MachOReader::GenerateClassesFromFunctions()
{
    const index_t functionCount = m_functions.size();
    for (index_t functionIndex = 0; functionIndex < functionCount; ++functionIndex)
    {
        Function &function = m_functions[functionIndex];

        if (!function.m_functionDeclContextName.empty())
        {
            const bool isNamespace = IsKnownNamespace(function.m_functionDeclContextName);
            const bool isClass = IsKnownClass(function.m_functionDeclContextName);
            if (!isClass && !isNamespace)
            {
                if (function.m_isCtorOrDtor || IsExpectedClass(function.m_functionDeclContextName))
                {
                    index_t classIndex = FindOrCreateClassByName(function.m_functionDeclContextName);
                    function.m_parentClassIndex = classIndex;
                    m_classes[classIndex].m_functionIndices.push_back(functionIndex);
                }
                else
                {
                    index_t namespaceIndex = FindOrCreateNamespaceByName(function.m_functionDeclContextName);
                    function.m_parentNamespaceIndex = namespaceIndex;
                    m_namespaces[namespaceIndex].m_functionIndices.push_back(functionIndex);
                }
            }
        }
    }
}

void MachOReader::BuildBaseClassLinks()
{
    for (Class &classType : m_classes)
    {
        BuildBaseClassLinksRecursive(classType, classType.m_allBaseClasses);

        assert(VerifyBaseClassLinks(classType));
    }
}

void MachOReader::BuildBaseClassLinksRecursive(
    const Class &classType,
    std::vector<BaseClass> &baseClasses,
    uint16_t baseOffsetAdjustment)
{
    for (const BaseClass &baseClass : classType.m_directBaseClasses)
    {
        Class &baseClassType = m_classes[baseClass.m_classIndex];

        BuildBaseClassLinksRecursive(baseClassType, baseClasses, baseOffsetAdjustment + baseClass.m_baseOffset);

        BaseClass baseClassCopy = baseClass;
        baseClassCopy.m_baseOffset += baseOffsetAdjustment;
        baseClasses.push_back(baseClassCopy);
    }
}

bool MachOReader::VerifyBaseClassLinks(const Class &classType)
{
    const index_t vtableCount = classType.m_vtables.size();
    // Skipping primary vtable because class can have base class without vtable, at offset larger than 0.
    index_t vtableIndex = 1;
    index_t offsetMatchCount = 0;
    if (vtableIndex < vtableCount)
    {
        for (; vtableIndex < vtableCount; ++vtableIndex)
        {
            const VTable &vtable = classType.m_vtables[vtableIndex];
            for (const BaseClass &baseClass : classType.m_allBaseClasses)
            {
                if (baseClass.m_baseOffset == vtable.m_offset)
                {
                    ++offsetMatchCount;
                    break;
                }
            }
        }
    }
    return vtableIndex - 1 == offsetMatchCount;
}

void MachOReader::ProcessVtables()
{
    // Pure virtual names need to be built before all overrides
    // and base class relationships can be populated.
    for (Class &classType : m_classes)
    {
        ProcessVtableOverridesAndPureVirtuals(classType);
    }

    for (Class &classType : m_classes)
    {
        ProcessPrimaryVtableOverrides(classType);
    }

    for (Class &classType : m_classes)
    {
        ProcessPrimaryVtableBaseClassRelationship(classType);
    }
}

void MachOReader::ProcessVtableOverridesAndPureVirtuals(Class &classType)
{
    if (classType.m_directBaseClasses.empty())
        return;
    if (classType.m_vtables.empty())
        return;

    for (VTable &vtable : classType.m_vtables)
    {
        const BaseClass *baseClass = classType.GetBaseClass(vtable.m_offset);
        if (baseClass == nullptr)
            continue;

        Class &baseClassType = m_classes[baseClass->m_classIndex];
        if (baseClassType.m_vtables.empty())
            continue;

        VTable &baseVtable = baseClassType.m_vtables.front();
        const uint16_t vtableCount = vtable.Size();
        const uint16_t baseVtableCount = baseVtable.Size();
        assert(vtable.m_offset != 0 || vtableCount >= baseVtableCount);
        assert(vtable.m_offset == 0 || vtableCount == baseVtableCount);

        for (uint16_t vtableIndex = 0; vtableIndex < baseVtableCount; ++vtableIndex)
        {
            VTableEntry &entry = vtable.m_entries[vtableIndex];
            VTableEntry &baseEntry = baseVtable.m_entries[vtableIndex];
            assert(entry.m_isDtor == baseEntry.m_isDtor);

            ProcessVtableEntryOverride(classType, entry);
            ProcessVtableEntryPureVirtual(baseClassType, baseEntry, entry);
        }

        ProcessVtableOverridesAndPureVirtuals(baseClassType);
    }
}

void MachOReader::ProcessVtableEntryOverride(const Class &classType, VTableEntry &entry)
{
    if (!entry.m_isPureVirtual && starts_with(entry.m_name, classType.m_name))
    {
        assert(!entry.m_isImplicit);
        entry.m_isOverride = true;
    }
    else
    {
        assert(!entry.m_isOverride);
        entry.m_isImplicit = true;
    }
}

void MachOReader::ProcessVtableEntryPureVirtual(const Class &baseClassType, VTableEntry &baseEntry, const VTableEntry &entry)
{
    if (!entry.m_name.empty() && baseEntry.m_isPureVirtual)
    {
        if (baseEntry.m_name.empty())
        {
            baseEntry.m_name = MakeFunctionNameWithNewClassName(entry.m_name, baseClassType.m_name);
        }
        else
        {
            assert(baseEntry.m_name == MakeFunctionNameWithNewClassName(entry.m_name, baseClassType.m_name));
        }
    }
}

void MachOReader::ProcessPrimaryVtableOverrides(Class &classType)
{
    if (classType.m_directBaseClasses.empty())
        return;
    if (classType.m_vtables.empty())
        return;

    VTable &vtable = classType.m_vtables.front();
    assert(vtable.m_offset == 0);
    uint16_t vtableIndex = 0;

    for (BaseClass &baseClass : classType.m_directBaseClasses)
    {
        Class &baseClassType = m_classes[baseClass.m_classIndex];
        if (baseClassType.m_vtables.empty())
            return;

        VTable &baseVtable = baseClassType.m_vtables.front();
        const uint16_t vtableCount = vtable.Size();
        const uint16_t baseVtableCount = baseVtable.Size();

        for (uint16_t baseVtableIndex = 0; vtableIndex < vtableCount && baseVtableIndex < baseVtableCount;)
        {
            // The two child loops walk both vtables one after the other
            // until it finds a vtable entry match or the vtable ends.

            const uint16_t vtableIndexCopy = vtableIndex;
            const uint16_t baseVtableIndexCopy = baseVtableIndex;
            if (ProcessPrimaryVtableEntries1(classType, vtable, baseVtable, vtableIndex, baseVtableIndex))
                continue;

            vtableIndex = vtableIndexCopy;
            baseVtableIndex = baseVtableIndexCopy + 1;
            if (ProcessPrimaryVtableEntries2(classType, vtable, baseVtable, vtableIndex, baseVtableIndex))
                continue;

            vtableIndex = vtableIndexCopy + 1;
            baseVtableIndex = baseVtableIndexCopy + 1;
        }
    }
}

bool MachOReader::ProcessPrimaryVtableEntries1(
    const Class &classType,
    VTable &vtable,
    VTable &baseVtable,
    uint16_t &vtableIndex,
    uint16_t &baseVtableIndex)
{
    const uint16_t vtableCount = vtable.Size();
    while (vtableIndex < vtableCount)
    {
        VTableEntry &entry = vtable.m_entries[vtableIndex];
        VTableEntry &baseEntry = baseVtable.m_entries[baseVtableIndex];
        if (VtableEntryIsOverride(entry, baseEntry))
        {
            ProcessVtableEntryOverride(classType, entry);
            ++vtableIndex;
            ++baseVtableIndex;
            return true;
        }
        else
        {
            ++vtableIndex;
        }
    }
    return false;
}

bool MachOReader::ProcessPrimaryVtableEntries2(
    const Class &classType,
    VTable &vtable,
    VTable &baseVtable,
    uint16_t &vtableIndex,
    uint16_t &baseVtableIndex)
{
    const uint16_t baseVtableCount = baseVtable.Size();
    while (baseVtableIndex < baseVtableCount)
    {
        VTableEntry &entry = vtable.m_entries[vtableIndex];
        VTableEntry &baseEntry = baseVtable.m_entries[baseVtableIndex];
        if (VtableEntryIsOverride(entry, baseEntry))
        {
            ProcessVtableEntryOverride(classType, entry);
            ++vtableIndex;
            ++baseVtableIndex;
            return true;
        }
        else
        {
            ++baseVtableIndex;
        }
    }
    return false;
}

bool MachOReader::VtableEntryIsOverride(const VTableEntry &entry1, const VTableEntry &entry2)
{
    const std::string_view entry1FunctionName = GetFunctionNameWithoutClassName(entry1.m_name);
    const std::string_view entry2FunctionName = GetFunctionNameWithoutClassName(entry2.m_name);

    if ((entry1.m_isDtor && entry2.m_isDtor) || (entry1FunctionName == entry2FunctionName))
    {
        return true;
    }
    return false;
}

// Note: This function is likely more expensive than it needs to be.
void MachOReader::ProcessPrimaryVtableBaseClassRelationship(Class &classType)
{
    if (classType.m_directBaseClasses.empty())
        return;
    if (classType.m_vtables.empty())
        return;

    const index_t baseClassCount = classType.m_allBaseClasses.size();
    for (index_t baseClassIndex = 0; baseClassIndex < baseClassCount; ++baseClassIndex)
    {
        const BaseClass &baseClass = classType.m_allBaseClasses[baseClassIndex];
        const Class &baseClassType = m_classes[baseClass.m_classIndex];
        if (baseClassType.m_vtables.empty())
            continue;

        VTable &vtable = classType.m_vtables.front();
        const VTable &baseVtable = baseClassType.m_vtables.front();

        for (VTableEntry &entry : vtable.m_entries)
        {
            if (entry.m_allBaseClassIndex != InvalidIndex)
                continue;
            if (entry.IsFirstDeclaration())
                continue;

            for (const VTableEntry &baseEntry : baseVtable.m_entries)
            {
                if (!baseEntry.IsFirstDeclaration())
                    continue;
                if (!VtableEntryIsOverride(entry, baseEntry))
                    continue;

                entry.m_allBaseClassIndex = baseClassIndex;
                break;
            }
        }
    }
}
