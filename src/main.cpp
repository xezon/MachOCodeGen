
#include "MachOReader.h"

int main(int argc, char **argv)
{
    MachOReader machOReader;
    // TODO: Make it configurable.
    if (!machOReader.Load("zh", LIEF::MachO::Header::CPU_TYPE::X86))
        return 1;

    return 0;
}
