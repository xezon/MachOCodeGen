#pragma once

#include "CppTypes.h"

#include "LIEF/config.h"

#include <LIEF/MachO/Header.hpp>

#include <memory>
#include <string_view>

namespace LIEF::MachO
{
class Binary;
class Symbol;
} // namespace LIEF::MachO

class MachOReader
{
public:
    MachOReader();
    ~MachOReader();

    bool Load(const std::string &filepath, LIEF::MachO::Header::CPU_TYPE cpuType);

private:
    void Patch(LIEF::MachO::Binary &binary);
    bool Parse(const LIEF::MachO::Binary &binary);
    void Parse_PEXT_thunks(const LIEF::MachO::Symbol &symbol);
    void Parse_PEXT_typeinfo(const LIEF::MachO::Binary &binary, const LIEF::MachO::Symbol &symbol);
    void Parse_PEXT_vtable(const LIEF::MachO::Binary &binary, const LIEF::MachO::Symbol &symbol);
    void Parse_SO(const LIEF::MachO::Symbol &symbol, bool &SO_InBlock, std::string &SO_Prefix);
    void Parse_SOL(const LIEF::MachO::Symbol &symbol, const std::string &SO_Prefix, index_t functionIndex);
    void Parse_FUN(const LIEF::MachO::Symbol &symbol, index_t &functionIndex);
    void Parse_GSYM(const LIEF::MachO::Symbol &symbol);
    void Parse_STSYM(const LIEF::MachO::Symbol &symbol);
    void Parse_LCSYM(const LIEF::MachO::Symbol &symbol);

private:
    index_t FindOrCreateHeaderFileByName(const std::string &name);
    index_t FindOrCreateNamespaceByName(const std::string &name);
    index_t FindOrCreateEnumByName(const std::string &name);
    index_t FindOrCreateClassByName(const std::string &name);

    bool IsKnownNamespace(const std::string &name) const;
    bool IsKnownClass(const std::string &name) const;

    bool IsExpectedClass(const std::string &name) const;
    bool HasCtorOrDtor(const std::string &name) const;
    bool IsFunctionArgument(const std::string &name) const;

    void GenerateClassesFromFunctions();
    void BuildBaseClassLinks();
    void BuildBaseClassLinksRecursive(
        const Class &classType,
        std::vector<BaseClass> &baseClasses,
        uint16_t baseOffsetAdjustment = 0);
    bool VerifyBaseClassLinks(const Class &classType);

    void ProcessVtables();
    // Goes through primary and secondary vtables and fills names for all pure virtual functions that are overridden.
    // Not all vtable entries in primary vtables are visited.
    void ProcessVtableOverridesAndPureVirtuals(Class &classType);
    static void ProcessVtableEntryOverride(const Class &classType, VTableEntry &entry);
    static void ProcessVtableEntryPureVirtual(const Class &baseClassType, VTableEntry &baseEntry, const VTableEntry &entry);
    // Goes through the whole primary vtable and determines overrides.
    void ProcessPrimaryVtableOverrides(Class &classType);
    static bool ProcessPrimaryVtableEntries1(
        const Class &classType,
        VTable &vtable,
        VTable &baseVtable,
        uint16_t &vtableIndex,
        uint16_t &baseVtableIndex);
    static bool ProcessPrimaryVtableEntries2(
        const Class &classType,
        VTable &vtable,
        VTable &baseVtable,
        uint16_t &vtableIndex,
        uint16_t &baseVtableIndex);
    static bool VtableEntryIsOverride(const VTableEntry &entry1, const VTableEntry &entry2);
    // Goes through the whole primary vtable and builds relationships with bottom base classes.
    void ProcessPrimaryVtableBaseClassRelationship(Class &classType);

private:
    std::unique_ptr<LIEF::MachO::Binary> m_binary;

    Namespaces m_namespaces;
    Enums m_enums;
    Variables m_variables;
    Classes m_classes;
    NonVirtualThunks m_thunks;
    Functions m_functions;
    HeaderFiles m_headerFiles;
    SourceFiles m_sourceFiles;

    StringToIndexMap m_nameToNamespaceIndex;
    StringToIndexMap m_nameToEnumIndex;
    // StringToIndexMap m_nameToVariableIndex;
    AddressToIndexMap m_addressToVariableIndex;
    StringToIndexMap m_nameToClassIndex;
    AddressToIndexMap m_addressToThunkIndex;
    StringToIndexMultiMap m_nameToFunctionIndex;
    StringToIndexMultiMap m_mangledToFunctionIndex;
    AddressToIndexMap m_addressToFunctionIndex;
    StringToIndexMap m_nameToHeaderFileIndex;
    StringToIndexMap m_nameToSourceFileIndex;
};
