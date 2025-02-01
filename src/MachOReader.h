#pragma once

#include "CppTypes.h"

#include "LIEF/config.h"

#include <LIEF/MachO/Header.hpp>

#include <string_view>

namespace LIEF::MachO
{
class Binary;
}

class MachOReader
{
public:
    bool Load(const std::string &filepath, LIEF::MachO::Header::CPU_TYPE cpuType);

private:
    bool Parse(const LIEF::MachO::Binary &binary);
    void Parse_SO(const LIEF::MachO::Symbol &symbol, bool &inSOBlock);
    void Parse_FUN(const LIEF::MachO::Symbol &symbol, char *buffer, size_t &bufferSize, index_t &functionIndex);

private:
    Namespaces m_namespaces;
    Enums m_enums;
    Variables m_variables;
    Classes m_classes;
    Functions m_functions;
    HeaderFiles m_headerFiles;
    SourceFiles m_sourceFiles;

    StringToIndexMap m_nameToNamespaceIndex;
    StringToIndexMap m_nameToEnumIndex;
    StringToIndexMap m_nameToVariableIndex;
    StringToIndexMap m_nameToClassIndex;
    StringToIndexMultiMap m_nameToFunctionIndex;
    StringToIndexMultiMap m_mangledToFunctionIndex;
    StringToIndexMap m_nameToHeaderFileIndex;
    StringToIndexMap m_nameToSourceFileIndex;
};
