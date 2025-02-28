/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Microsoft Corporation
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

enum option {
    FILTER_OMIT_SSE_SETS = 1,
};

std::vector<std::string> get_cpu_flags(option options)
{
    std::vector<std::string> cpu_flags;

    if (!(options & FILTER_OMIT_SSE_SETS)) {
#ifdef __SSE__
        cpu_flags.push_back("SSE");
#endif
#ifdef __SSE2__
        cpu_flags.push_back("SSE2");
#endif
#ifdef __SSE3__
        cpu_flags.push_back("SSE3");
#endif
#ifdef __SSSE3__
        cpu_flags.push_back("SSEE3");
#endif
#ifdef __SSE4_1__
        cpu_flags.push_back("SSE4_1");
#endif
#ifdef __SSE4_2__
        cpu_flags.push_back("SSE4_2");
#endif
    }

#ifdef __AVX__
    cpu_flags.push_back("AVX");
#endif
#ifdef __PCLMUL__
    cpu_flags.push_back("PCLMUL");
#endif
#ifdef __RDRND__
    cpu_flags.push_back("RDRND");
#endif
#ifdef __AVX2__
    cpu_flags.push_back("AVX2");
#endif
#ifdef __RDSEED__
    cpu_flags.push_back("RDSEED");
#endif
#ifdef __AES__
    cpu_flags.push_back("AES");
#endif
#ifdef __VPCLMULQDQ__
    cpu_flags.push_back("VPCLMULQDQ");
#endif
#ifdef __AVX512F__
    cpu_flags.push_back("AVX512F");
#endif
#ifdef __AVX512VL__
    cpu_flags.push_back("AVX512VL");
#endif
#ifdef __AVX512BW__
    cpu_flags.push_back("AVX512BW");
#endif
#ifdef __AVX512DQ__
    cpu_flags.push_back("AVX512DQ");
#endif
#ifdef __AVX512CD__
    cpu_flags.push_back("AVX512CD");
#endif
#ifdef __AVX512IFMA__
    cpu_flags.push_back("AVX512IFMA");
#endif
#ifdef __GFNI__
    cpu_flags.push_back("GFNI");
#endif
    return cpu_flags;
}

void dump_cpu_flags(const std::string &cpu_name, const std::vector<std::string> &cpu_flags)
{
    std::string cpu_name_quoted = std::string("'") + cpu_name + "'";
    std::cout << std::setw(18) << cpu_name_quoted << ": [";
    for (size_t i = 0; i < cpu_flags.size(); ++i) {
        if (i > 0)
            std::cout << ", ";

        std::cout << "'" << cpu_flags[i] << "'";
    }
    std::cout << "],\n";
}

bool does_cpu_meet_dpdk_requirements()
{
#ifdef __SSE4_2__
    return true;
#endif

    return false;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <cpu_name>\n";
        return -1;
    }

    if (does_cpu_meet_dpdk_requirements()) {
        std::vector<std::string> cpu_flags = get_cpu_flags(FILTER_OMIT_SSE_SETS);
        dump_cpu_flags(argv[1], cpu_flags);
    }

    return 0;
}
