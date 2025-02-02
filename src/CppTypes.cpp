#include "CppTypes.h"

#include "utility.h"

#include <cassert>

const std::string &Function::GetMangledName(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_mangledName;
}

uint64_t Function::GetVirtualAddressBegin(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_virtualAddress;
}

uint64_t Function::GetVirtualAddressEnd(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_virtualAddress + m_variants[variantIndex].m_size;
}

uint16_t Function::GetSourceLine(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_sourceLine;
}

std::set<std::string> CreateHeaderFileSet(const HeaderFiles &headerFiles, const Function &function)
{
    std::set<std::string> set;

    for (const FunctionVariant &variant : function.m_variants)
    {
        for (const FunctionInstruction &instruction : variant.m_instructions)
        {
            if (instruction.headerFileIndex != InvalidIndex)
            {
                set.insert(headerFiles[instruction.headerFileIndex].m_name);
            }
        }
    }
    return set;
}
