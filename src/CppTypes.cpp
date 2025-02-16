#include "CppTypes.h"

#include "utility.h"

#include <algorithm>
#include <cassert>

uint16_t VTable::Size() const
{
    return static_cast<uint16_t>(m_entries.size());
}

const BaseClass *Class::GetBaseClass(uint16_t baseOffset) const
{
    // Search from back because the top base class at offset 0 is at the back.

    std::vector<BaseClass>::const_reverse_iterator it = m_allBaseClasses.crbegin();
    std::vector<BaseClass>::const_reverse_iterator end = m_allBaseClasses.crend();
    for (; it != end; ++it)
    {
        if (it->m_baseOffset == baseOffset)
            return &(*it);
    }
    return nullptr;
}

const std::string &Function::GetMangledName(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_mangledName;
}

uint64_t Function::GetVirtualAddressBegin(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_address;
}

uint64_t Function::GetVirtualAddressEnd(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_address + m_variants[variantIndex].m_size;
}

uint16_t Function::GetSourceLine(size_t variantIndex) const
{
    assert(variantIndex < m_variants.size());
    return m_variants[variantIndex].m_sourceLine;
}

bool Function::IsClassMemberFunction() const
{
    return m_parentClassIndex != InvalidIndex;
}

std::vector<std::string> Function::GetParameterTypes(const std::string &functionParameters)
{
    std::vector<std::string> types;
    std::string type;
    bool typeOpened = false;
    int templateList = 0;
    const char *c = functionParameters.c_str();

    for (; *c != '\0'; ++c)
    {
        if (*c == '(')
        {
            typeOpened = true;
            continue;
        }
        else if (*c == '<')
        {
            ++templateList;
        }
        else if (*c == '>')
        {
            --templateList;
        }

        if (templateList == 0)
        {
            if (*c == ',')
            {
                if (!type.empty())
                {
                    types.push_back(std::move(type));
                }
                ++c;
                typeOpened = true;
                continue;
            }
            else if (std::isspace(*c))
            {
                if (type == "signed" || type == "unsigned")
                {
                    type += *c;
                    continue;
                }
                if (!type.empty())
                {
                    types.push_back(std::move(type));
                }
                typeOpened = false;
                continue;
            }
            else if (*c == '*' || *c == '&' || *c == ')')
            {
                if (!type.empty())
                {
                    types.push_back(std::move(type));
                }
                typeOpened = false;
                continue;
            }
        }

        if (typeOpened)
        {
            type += *c;
        }
    }
    return types;
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
